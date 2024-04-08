# BSD 2-Clause License
#
# Copyright (c) 2024, Yubico AB
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import base64
import csv
import ctypes
import datetime
import json
import re
import subprocess
import sys
from getpass import getpass
import secrets
import string
from ykman.device import list_all_devices


import requests
import urllib3
from fido2.client import Fido2Client, UserInteraction, WindowsClient
from fido2.ctap2.extensions import CredProtectExtension
from fido2.hid import CtapHidDevice
from fido2.utils import websafe_decode, websafe_encode

# Disabling warnings that get produced when certificate stores aren't updated
# to check certificate validity.
# Not recommended for production code to disable the warnings.
# This is the warning that is produced when the warnings are not disabled.
# InsecureRequestWarning: Unverified HTTPS request is being made
# to host 'login.microsoftonline.com'.
# Adding certificate verification is strongly advised. See:
# https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()


in_csv_file_name = "./registrationUsers.csv"
out_csv_file_name = "./registeredKeys.csv"
config_file_name = "configs.json"
pin = ""

with open(config_file_name, "r", encoding="utf8") as f:
    configs = json.load(f)


try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev


# Handle user interaction
class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your security key now...\n")

    def request_pin(self, permissions, rp_id):
        if not configs["useRandomPIN"]:
            return getpass("Enter PIN: ")
        else:
            return pin

    def request_uv(self, permissions, rp_id):
        print("User Verification required.")
        return True


def base64url_to_bytearray(b64url_string):
    temp = b64url_string.replace("_", "/").replace("-", "+")
    return bytearray(
        base64.urlsafe_b64decode(temp + "=" * (4 - len(temp) % 4))
    )


def create_credentials_on_security_key(
    user_id, challenge, user_display_name, user_name
):
    print("-----")
    print("in create_credentials_on_security_key\n")
    print(
        "\tPrepare for FIDO2 Registration Ceremony and follow the prompts\n"
    )
    print("\tPress Enter when security key is ready\n")
    serial_number = get_serial_number()

    if (
        WindowsClient.is_available()
        and not ctypes.windll.shell32.IsUserAnAdmin()
    ):
        # Use the Windows WebAuthn API if available, and we're not running
        # as admin since the origin is common across all Entra ID tenants
        # we will simply hard-code it here.
        client = WindowsClient("https://login.microsoft.com")

        # Config file setting for useRandomPIN doesn't apply in this scenario
        global pin
        pin = "n/a"
    else:
        generate_and_set_pin()
        # Locate a device
        for dev in enumerate_devices():
            # Since the origin is common across all Entra ID tenants
            # we will simply hard-code it here.
            client = Fido2Client(
                dev,
                "https://login.microsoft.com",
                user_interaction=CliInteraction(),
            )
            if client.info.options.get("rk"):
                break
        else:
            print(
                "No security key with support for discoverable"
                " credentials found"
            )
            sys.exit(1)

    pkcco = build_creation_options(
        challenge, user_id, user_display_name, user_name
    )

    result = client.make_credential(pkcco["publicKey"])

    print("\tNew FIDO credential created on YubiKey")

    attestation_obj = result["attestationObject"]
    attestation = websafe_encode(attestation_obj)
    print(f"Attestation: {attestation}")

    client_data = result["clientData"].b64
    # print(f"\nclientData: {client_data}")

    credential_id = websafe_encode(
        result.attestation_object.auth_data.credential_data.credential_id
    )
    print(f"\ncredentialId: {credential_id}")

    client_extenstion_results = websafe_encode(
        json.dumps(result.attestation_object.auth_data.extensions).encode(
            "utf-8"
        )
    )
    print(f"\nclientExtensions: {websafe_decode(client_extenstion_results)}")

    return (
        attestation,
        client_data,
        credential_id,
        client_extenstion_results,
        serial_number,
    )


def set_http_headers(access_token):
    return {
        "Accept": "application/json",
        "Authorization": access_token,
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
    }


def build_creation_options(challenge, userId, displayName, name):
    # Most of the creation options are static and shouldn't change for each
    # user and for each request so this script staticly defines the creation
    # options that are retrieved from Microsoft Graph. Ideally these would
    # be retrieved directly from Microsoft Graph in case they do change.

    # Note about overriding the value for credentialProtectionPolicy.
    # The fido2 library only supports setting the credProtect extension
    # using the enum not the string value. OPTIONAL is equivalent
    # to "userVerificationOptional" which is also equivalent to "Level 1"

    # Note at the time of writing this, webauthn.dll does not set
    # credprotect extensions. Run in admin mode if credprotect
    # extensions must be set for your scenario and for your
    # fido2 security keys. The default behavior of YubiKeys is to
    # use credprotect level 1 if not explicitly set, the default value
    # aligns with the what Microsoft Graph expects to be used.
    # If credprotect > 1 is used on a security key, you should expect
    # Windows 10 desktop login scenarios to fail.
    public_key_credential_creation_options = {
        "publicKey": {
            "challenge": base64url_to_bytearray(challenge),
            "timeout": 0,
            "attestation": "direct",
            "rp": {"id": "login.microsoft.com", "name": "Microsoft"},
            "user": {
                "id": base64url_to_bytearray(userId),
                "displayName": displayName,
                "name": name,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257},
            ],
            "excludeCredentials": [],
            "authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",
                "requireResidentKey": True,
                "userVerification": "required",
            },
            "extensions": {
                "hmacCreateSecret": True,
                "enforceCredentialProtectionPolicy": True,
                "credentialProtectionPolicy":
                CredProtectExtension.POLICY.OPTIONAL,
            },
        }
    }

    return public_key_credential_creation_options


def get_access_token_for_microsoft_graph():
    # Request a token that is scoped to the main.iam.ad.ext.azure.com
    # private api Use the device code login flow
    print("-----")
    print("in get_access_token_for_microsoft_graph\n")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_endpoint = (
        "https://login.microsoftonline.com/"
        + configs["tenantName"]
        + "/oauth2/v2.0/token"
    )

    body = {
        "grant_type": "client_credentials",
        "client_id": configs["client_id"],
        "client_secret": configs["client_secret"],
        "scope": "https://graph.microsoft.com/.default",
    }

    token_response = requests.post(
        token_endpoint, data=body, headers=headers, verify=False
    )

    access_token = re.search(
        '"access_token":"([^"]+)"', str(token_response.content)
    )

    decoded_response = json.loads(token_response.content)
    if "error" in decoded_response.keys():
        raise Exception(
            decoded_response["error"], decoded_response["error_description"]
        )

    print("\t retrieved access token using app credentials")
    return access_token.group(1)


# Call the Microsoft Graph to create a fido2method


def create_and_activate_fido_method(
    credential_id,
    client_extensions,
    user_name,
    attestation,
    client_data,
    serial_number,
    access_token,
):
    print("-----")
    print("in create_and_activate_fido_method\n")

    headers = set_http_headers(access_token)

    fido_credentials_endpoint = (
        "https://graph.microsoft.com/beta/users/"
        + user_name
        + "/authentication/fido2Methods"
    )

    body = {
        "publicKeyCredential": {
            "id": credential_id,
            "response": {
                "attestationObject": attestation,
                "clientDataJSON": client_data,
            },
            "clientExtensionResults": json.loads(
                base64.b64decode(str(client_extensions)).decode("utf-8")
            ),
        },
        "displayName": "Serial: "
        + str(serial_number)
        + " "
        + str(datetime.date.today()),
    }

    response = requests.post(
        fido_credentials_endpoint, json=body, headers=headers, verify=False
    )

    if response.status_code == 201:
        create_response = response.json()
        print("\tRegistration success.")
        print(f'\tAuth method objectId: {create_response["id"]}')
        return True, create_response["id"]
    else:
        print(response.status_code)
        print(response.content)
        return False, []


def generate_and_set_pin():
    print("-----")
    print("in generate_and_set_pin\n")
    global pin
    if configs["useRandomPIN"]:
        pin = "".join(secrets.choice(string.digits) for i in range(6))
        print(f"\tWe will now set the PIN to: {pin} \n")
        input("\tPress Enter key to continue...")
        cmd = "ykman fido access change-pin -n " + pin
        resp = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, shell=True
        ).communicate()[0]

        print(resp.decode("utf-8"))
        print("\tPIN set\n")
    else:
        pin = "n/a"
        print("\tNot generating PIN. Allowing platform to prompt for PIN\n")


def get_serial_number():
    for device, info in list_all_devices():
        print(f"\tFound YubiKey with serial number: {info.serial}")
        return info.serial


def warn_user_about_pin_behaviors():
    # See BulkRegistration.md for more details
    # Windows configurations to look out for:
    if WindowsClient.is_available():
        # Running on Windows as admin
        if ctypes.windll.shell32.IsUserAnAdmin():
            if not configs["useRandomPIN"]:
                print(
                    "\n\n\tIf PIN is not already set on security key(s), "
                    "then make sure PIN is set on security keys before "
                    "proceeding"
                )
                input("\n\tPress Enter key to continue...")
            if configs["useRandomPIN"]:
                print(
                    "\n\n\tIf PIN is already set on security key(s) then "
                    "script will prompt for existing PIN and change to new "
                    "random PIN."
                )
                input("\n\tPress Enter key to continue...")
        if not ctypes.windll.shell32.IsUserAnAdmin():
            if configs["useRandomPIN"]:
                print(
                    "\n\n\tuseRandomPIN setting is set to true. This "
                    "setting will be ignored. User will be prompted to "
                    "set PIN if it is not already set."
                )
                input("\n\tPress Enter key to continue...")
    # macOS and other platforms configurations to look out for:
    if not WindowsClient.is_available():
        if not configs["useRandomPIN"]:
            print(
                "\n\n\tIf PIN is not already set on security key(s), "
                "then make sure PIN is set on security keys before "
                "proceeding"
            )
            input("\n\tPress Enter key to continue...")
        if configs["useRandomPIN"]:
            print(
                "\n\n\tIf PIN is already set on security key(s) then "
                "script will prompt for existing PIN and change to new "
                "random PIN."
            )
            input("\n\tPress Enter key to continue...")


def main():
    warn_user_about_pin_behaviors()
    access_token = get_access_token_for_microsoft_graph()
    line_count = 0
    with open(in_csv_file_name, newline="") as in_csv_file:
        with open(out_csv_file_name, "w", newline="") as out_csv_file:
            csv_reader = csv.reader(in_csv_file)
            csv_writer = csv.writer(out_csv_file)
            # Write header row for output file registeredKeys.csv
            csv_writer.writerow(
                ["#upn", "entraIDAuthMethodObjectId", "serialNumber", "PIN"]
            )
            for row in csv_reader:
                if line_count == 0:
                    # Assume header exists in the csv and skip this row
                    print("\tSkip csv header row")
                else:
                    user_name = row[0]
                    user_display_name = row[1]
                    user_id = row[2]
                    challenge = row[3]
                    challenge_expiry_time = row[4]
                    print("-------------------------------------------------")
                    print(f"\tprocessing user: {user_name}")
                    print("-------------------------------------------------")
                    print(f"\tuserDisplayName: {user_display_name}")
                    print(f"\tuserId: {user_id}")
                    print(f"\tchallengeExpiryTime: {challenge_expiry_time}")
                    print("\n")
                    (
                        att,
                        clientData,
                        credId,
                        extn,
                        serial,
                    ) = create_credentials_on_security_key(
                        user_id, challenge, user_display_name, user_name
                    )
                    activated, auth_method = create_and_activate_fido_method(
                        credId,
                        extn,
                        user_name,
                        att,
                        clientData,
                        serial,
                        access_token,
                    )

                    print(
                        "\n\tCompleted registration and configuration "
                        + f"for user: {user_name}"
                    )
                    # Write CSV with security key registration details
                    # username,authMethodID,serialNumber,PIN
                    csv_writer.writerow([user_name, auth_method, serial, pin])
                    input("\tPress Enter key to continue...")
                    print("-----")

                line_count += 1
    print(
        "\nAfter verifying results, cleanup any csv files"
        + " that are no longer needed.\n"
    )


main()
