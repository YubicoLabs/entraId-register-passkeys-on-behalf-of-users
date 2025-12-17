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
from getpass import getpass
import secrets
import string

from ykman.device import list_all_devices
from ykman import scripting as s


import requests
import urllib3
from fido2.client import (
    Fido2Client,
    UserInteraction,
    DefaultClientDataCollector,
)
from fido2.client.windows import WindowsClient
from fido2.ctap2.extensions import CredProtectExtension, HmacSecretExtension
from fido2.hid import CtapHidDevice
from fido2.utils import websafe_decode, websafe_encode
from fido2.ctap2 import Ctap2, Config
from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin
try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None
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


in_csv_file_name = "./usersToRegister.csv"
out_csv_file_name = "./keysRegistered.csv"
config_file_name = "configs.json"
pin = ""

with open(config_file_name, "r", encoding="utf8") as f:
    configs = json.load(f)


try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

# Use the Windows WebAuthn API if available, and we're not running as admin
try:
    from fido2.client.windows import WindowsClient

    use_winclient = (
        WindowsClient.is_available()
        and not ctypes.windll.shell32.IsUserAnAdmin()
    )
except ImportError:
    use_winclient = False


def get_client(predicate=None, **kwargs):
    """Locate a CTAP device suitable for use.

    If running on Windows as non-admin, the predicate check will be skipped and
    a webauthn.dll based client will be returned.

    Extra kwargs will be passed to the constructor of Fido2Client.

    The client will be returned, with the CTAP2 Info, if available.
    """
    rp_id = kwargs.pop("rp_id", None)
    client_data_collector = DefaultClientDataCollector("https://" + rp_id)

    if use_winclient:
        return (
            WindowsClient(client_data_collector, allow_hmac_secret=True),
            None,
        )

    user_interaction = (
        kwargs.pop("user_interaction", None) or CliInteraction()
    )

    # Locate a device
    for dev in enumerate_devices():
        # Set up a FIDO 2 client using the origin
        client = Fido2Client(
            dev,
            client_data_collector=client_data_collector,
            user_interaction=user_interaction,
            extensions=[HmacSecretExtension(allow_hmac_secret=True)],
        )
        # Check if it is suitable for use
        if predicate is None or predicate(client.info):
            return client, client.info
    else:
        raise ValueError("No suitable Authenticator found!")


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev


# Handle user interaction via CLI prompts
class CliInteraction(UserInteraction):
    def __init__(self):
        self._pin = None

    def prompt_up(self):
        print(f"\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        if not self._pin:
            self._pin = getpass("Enter PIN: ")
        return self._pin

    def request_uv(self, permissions, rd_id):
        print(f"User Verification required.")
        return True


def base64url_to_bytearray(b64url_string):
    temp = b64url_string.replace("_", "/").replace("-", "+")
    return bytearray(
        base64.urlsafe_b64decode(temp + "=" * (4 - len(temp) % 4))
    )


def create_credentials_on_security_key(
    user_id, challenge, user_display_name, user_name, rp_id
):
    print(f"-----")
    print(f"in create_credentials_on_security_key\n")
    print(
        "\tPrepare for FIDO2 Registration Ceremony and follow the prompts\n"
    )
    print(f"\tPress Enter when security key is ready\n")
    serial_number = get_serial_number()
    #serial_number="123"

    if use_winclient:
        global pin
        pin = "n/a"
    else:
        generate_and_set_pin()

    client, info = get_client(rp_id=rp_id)
    pkcco = build_creation_options(
        challenge, user_id, user_display_name, user_name, rp_id
    )

    result = client.make_credential(pkcco["publicKey"])

    print(f"\tNew FIDO credential created on YubiKey")

    attestation_obj = result.response.attestation_object
    # attestation = websafe_encode(attestation_obj)
    attestation = attestation_obj
    print(f"Attestation: {attestation}")

    client_data = result.response.client_data.b64
    # print(f"\nclientData: {client_data}")

    credential_id = websafe_encode(
        attestation_obj.auth_data.credential_data.credential_id
    )
    print(f"\ncredentialId: {credential_id}")

    if attestation_obj.auth_data.extensions:

        client_extension_results = websafe_encode(
            json.dumps(attestation_obj.auth_data.extensions).encode("utf-8")
        )
    else:
        client_extension_results = ""
    print(f"\nclientExtensions: {websafe_decode(client_extension_results)}")

    return (
        attestation,
        client_data,
        credential_id,
        client_extension_results,
        serial_number,
    )


def set_http_headers(access_token):
    return {
        "Accept": "application/json",
        "Authorization": access_token,
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
    }


def build_creation_options(challenge, userId, displayName, name, rp_id):
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
            "rp": {"id": rp_id, "name": "Microsoft"},
            "user": {
                "id": base64url_to_bytearray(userId),
                "displayName": displayName,
                "name": name,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257},
            ],
            "hints": ["security-key"],
            "excludeCredentials": [],
            "authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",
                "requireResidentKey": True,
                "userVerification": "required",
            },
            "extensions": {
                "hmacCreateSecret": True,
                "enforceCredentialProtectionPolicy": True,
                "credentialProtectionPolicy": CredProtectExtension.POLICY.OPTIONAL,
            },
        }
    }

    return public_key_credential_creation_options


def get_access_token_for_microsoft_graph():
    # Request a token for Graph
    # Use client_credentials grant
    print(f"-----")
    print(f"in get_access_token_for_microsoft_graph\n")
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
    decoded_response = token_response.json()
    if "access_token" in decoded_response:
        access_token = decoded_response["access_token"]
    else:
        # If the response was successful but missing the token, handle it.
        decoded_response = json.loads(token_response.content)
        if "error" in decoded_response.keys():
            raise Exception(
                decoded_response["error"],
                decoded_response["error_description"],
            )

    print(f"\t retrieved access token using app credentials")
    return access_token


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
    print(f"-----")
    print(f"in create_and_activate_fido_method\n")

    headers = set_http_headers(access_token)

    fido_credentials_endpoint = (
        "https://graph.microsoft.com/beta/users/"
        + user_name
        + "/authentication/fido2Methods"
    )

    if client_extensions:
        clientExtensionResults = json.loads(
            websafe_decode(client_extensions).decode("utf-8")
        )
    else:
        clientExtensionResults = None

    body = {
        "publicKeyCredential": {
            "id": credential_id,
            "response": {
                "attestationObject": websafe_encode(attestation),
                "clientDataJSON": client_data,
            },
            "clientExtensionResults": clientExtensionResults,
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
        print(f"\tRegistration success.")
        print(f'\tAuth method objectId: {create_response["id"]}')
        return True, create_response["id"]
    else:
        print(response.status_code)
        print(response.content)
        return False, []


def generate_pin():
    disallowed_pins = [
        "123456",
        "123123",
        "654321",
        "123321",
        "112233",
        "121212",
        "520520",
        "123654",
        "159753",
    ]

    while True:
        digits = "".join(secrets.choice(string.digits) for _ in range(6))
        # Check if PIN is not trivial and not in banned list
        if len(set(digits)) != 1 and digits not in disallowed_pins:
            return digits


def generate_and_set_pin():
    print(f"-----")
    print(f"in generate_and_set_pin\n")
    global pin
    if configs["useRandomPIN"]:
        # devices = list(CtapHidDevice.list_devices())
        device = s.single()
        with device.fido() as connection:
            ctap = Ctap2(connection)
            if ctap.info.options.get("clientPin"):
                print(f"\tPIN already set for the device. Quitting.")
                print(
                    "\tReset YubiKey and rerun the script if you want to use the config 'useRandomPIN'"
                )
                quit()
            pin = generate_pin()
            print(f"\tWe will now set the PIN to: {pin} \n")
            client_pin = ClientPin(ctap)
            client_pin.set_pin(pin)
            print(f"\tPIN set to {pin}")
    else:
        print(f"\tNot generating PIN. Allowing platform to prompt for PIN\n")


def set_ctap21_flags():
    global pin
    # No need to try if using the Windows client (as non-admin)
    if not use_winclient:
        device = s.single()
        if not configs["useRandomPIN"]:
            # Need to prompt for PIN again if using user supplied PIN
            print(
                f"PIN required to set minimum length and force pin change flags"
            )
            pin = getpass("Please enter the PIN:")

        with device.fido() as connection:
            ctap = Ctap2(connection)
            if ctap.info.options.get("setMinPINLength"):
                client_pin = ClientPin(ctap)
                token = client_pin.get_pin_token(
                    pin, ClientPin.PERMISSION.AUTHENTICATOR_CFG
                )
                config = Config(ctap, client_pin.protocol, token)
                print(f"\tGoing to set the minimum pin length to 6.")
                config.set_min_pin_length(min_pin_length=6)
                print(f"\tGoing to force a PIN change on first use.")
                config.set_min_pin_length(force_change_pin=True)
    else:
        print(
            "Using these CTAP21 features are not supported when running in this mode"
        )


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
                    print(f"\tSkip csv header row")
                else:
                    user_name = row[0]
                    user_display_name = row[1]
                    user_id = row[2]
                    challenge = row[3]
                    challenge_expiry_time = row[4]
                    rp_id = row[5]
                    print(
                        f"-------------------------------------------------"
                    )
                    print(f"\tprocessing user: {user_name}")
                    print(
                        f"-------------------------------------------------"
                    )
                    print(f"\tuserDisplayName: {user_display_name}")
                    print(f"\tuserId: {user_id}")
                    print(f"\tchallengeExpiryTime: {challenge_expiry_time}")
                    print(f"\trpID: {rp_id}")
                    print(f"\n")
                    (
                        att,
                        clientData,
                        credId,
                        extn,
                        serial,
                    ) = create_credentials_on_security_key(
                        user_id,
                        challenge,
                        user_display_name,
                        user_name,
                        rp_id,
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

                    # Set min pin length and force pin change flags
                    if configs["useCTAP21Features"]:
                        set_ctap21_flags()
                    print(
                        "\n\tCompleted registration and configuration "
                        + f"for user: {user_name}"
                    )
                    # Write CSV with security key registration details
                    # username,authMethodID,serialNumber,PIN
                    csv_writer.writerow([user_name, auth_method, serial, pin])
                    input("\tPress Enter key to continue...")
                    print(f"-----")

                line_count += 1
    print(
        "\nAfter verifying results, cleanup any csv files"
        + " that are no longer needed.\n"
    )


main()
