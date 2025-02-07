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
import os
import re
import secrets
import string
import sys
from getpass import getpass

import requests
import urllib3
from fido2.client import Fido2Client, UserInteraction, WindowsClient
from fido2.ctap2.extensions import CredProtectExtension
from fido2.hid import CtapHidDevice
from fido2.utils import websafe_decode, websafe_encode
from fido2.ctap2 import Ctap2, Config
from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.colors import black, red
from ykman.device import list_all_devices
from ykman import scripting as s

# Disabling warnings that get produced when certificate stores aren't updated
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

# Configuration and file paths
in_csv_file_name = "./usersToRegister.csv"
out_csv_file_name = "./keysRegistered.csv"
config_file_name = "configs.json"
logo_path = "C:/VS/bulkRegistration/LogoSlogan.png" # Replace with the correct path to your logo
pin = ""

# Load configuration
with open(config_file_name, "r", encoding="utf8") as f:
    configs = json.load(f)

group_name = configs.get("usersInScopeGroup", "DefaultGroup")

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

class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\n🔑 Touch your security key now...\n")

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

def create_credentials_on_security_key(user_id, challenge, user_display_name, user_name, rp_id):
    print("-----")
    print("🔑 Creating credentials on security key\n")
    print("\tPrepare for FIDO2 Registration Ceremony and follow the prompts\n")
    input("\tPress Enter when security key is ready...")
    serial_number = get_serial_number()

    if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
        client = WindowsClient("https://" + rp_id)
        global pin
        pin = "n/a"
    else:
        generate_and_set_pin()
        for dev in enumerate_devices():
            client = Fido2Client(
                dev,
                "https://" + rp_id,
                user_interaction=CliInteraction(),
            )
            if client.info.options.get("rk"):
                break
        else:
            print("No security key with support for discoverable credentials found")
            sys.exit(1)

    pkcco = build_creation_options(challenge, user_id, user_display_name, user_name, rp_id)
    result = client.make_credential(pkcco["publicKey"])

    print("\tNew FIDO credential created on YubiKey")

    attestation_obj = result["attestationObject"]
    attestation = websafe_encode(attestation_obj)
    credential_id = websafe_encode(result.attestation_object.auth_data.credential_data.credential_id)
    client_extenstion_results = websafe_encode(
        json.dumps(result.attestation_object.auth_data.extensions).encode("utf-8")
    )

    return attestation, result["clientData"].b64, credential_id, client_extenstion_results, serial_number

def set_http_headers(access_token):
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
    }

def build_creation_options(challenge, userId, displayName, name, rp_id):
    return {
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

def get_access_token_for_microsoft_graph():
    print("-----")
    print("🔑 Getting access token for Microsoft Graph\n")
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

    token_response = requests.post(token_endpoint, data=body, headers=headers, verify=False)
    access_token = re.search('"access_token":"([^"]+)"', str(token_response.content)).group(1)

    decoded_response = json.loads(token_response.content)
    if "error" in decoded_response:
        raise Exception(decoded_response["error"], decoded_response["error_description"])

    print("\tRetrieved access token using app credentials")
    return access_token

def create_and_activate_fido_method(credential_id, client_extensions, user_name, attestation, client_data, serial_number, access_token):
    print("-----")
    print("🔑 Creating and activating FIDO method\n")

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
            "clientExtensionResults": json.loads(base64.b64decode(str(client_extensions)).decode("utf-8")),
        },
        "displayName": f"Serial: {serial_number} {datetime.date.today()}",
    }

    response = requests.post(fido_credentials_endpoint, json=body, headers=headers, verify=False)

    if response.status_code == 201:
        create_response = response.json()
        print("\tRegistration success.")
        print(f'\tAuth method objectId: {create_response["id"]}')
        return True, create_response["id"]
    else:
        print(response.status_code)
        print(response.content)
        return False, []

def generate_pin():
    disallowed_pins = ["123456", "123123", "654321", "123321", "112233", "121212", "520520", "123654", "159753"]

    while True:
        digits = "".join(secrets.choice(string.digits) for _ in range(6))
        if len(set(digits)) != 1 and digits not in disallowed_pins:
            return digits

def generate_and_set_pin():
    print("-----")
    print("🔑 Generating and setting PIN\n")
    global pin
    if configs["useRandomPIN"]:
        device = s.single()
        with device.fido() as connection:
            ctap = Ctap2(connection)
            if ctap.info.options.get("clientPin"):
                print("\tPIN already set for the device. Quitting.")
                print("\tReset YubiKey and rerun the script if you want to use the config 'useRandomPIN'")
                quit()
            pin = generate_pin()
            print(f"\tWe will now set the PIN to: {pin} \n")
            client_pin = ClientPin(ctap)
            client_pin.set_pin(pin)
            print(f"\tPIN set to {pin}")
    else:
        print("\tNot generating PIN. Allowing platform to prompt for PIN\n")

def set_ctap21_flags():
    global pin
    if not (WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin()):
        device = s.single()
        if not configs['useRandomPIN']:
            print("PIN required to set minimum length and force pin change flags")
            pin = getpass("Please enter the PIN:")

        with device.fido() as connection:
            ctap = Ctap2(connection)
            if ctap.info.options.get("setMinPINLength"):
                client_pin = ClientPin(ctap)
                token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
                config = Config(ctap, client_pin.protocol, token)
                print("\tGoing to set the minimum pin length to 6.")
                config.set_min_pin_length(min_pin_length=6)
                print("\tGoing to force a PIN change on first use.")
                config.set_min_pin_length(force_change_pin=True)
    else:
        print("Using these CTAP21 features are not supported when running in this mode")

def get_serial_number():
    try:
        devices = list(list_all_devices())

        if not devices:
            print("\n❌ No YubiKey detected! Please check:")
            print("- YubiKey is properly connected")
            print("- YubiKey drivers are installed")
            print("- Only one YubiKey is connected at a time")
            return "N/A"

        if len(devices) > 1:
            print("\n⚠️ Multiple YubiKeys detected! Using the first one.")

        device, info = devices[0]
        print(f"\n✅ YubiKey Serial: {info.serial}")
        return info.serial

    except Exception as e:
        print(f"\n❌ Critical error: {str(e)}")
        print("Please check:")
        print("- YubiKey is authentic (not a clone)")
        print("- YubiKey is FIDO2 compatible (YubiKey 5+)")
        return "ERROR"

def warn_user_about_pin_behaviors():
    if WindowsClient.is_available():
        if ctypes.windll.shell32.IsUserAnAdmin():
            if not configs["useRandomPIN"]:
                print("\n\n\tIf PIN is not already set on security key(s), then make sure PIN is set on security keys before proceeding")
                input("\n\tPress Enter key to continue...")
            if configs["useRandomPIN"]:
                print("\n\n\tIf PIN is already set on security key(s) then script will prompt for existing PIN and change to new random PIN.")
                input("\n\tPress Enter key to continue...")
        if not ctypes.windll.shell32.IsUserAnAdmin():
            if configs["useRandomPIN"]:
                print("\n\n\tuseRandomPIN setting is set to true. This setting will be ignored. User will be prompted to set PIN if it is not already set.")
                input("\n\tPress Enter key to continue...")
    if not WindowsClient.is_available():
        if not configs["useRandomPIN"]:
            print("\n\n\tIf PIN is not already set on security key(s), then make sure PIN is set on security keys before proceeding")
            input("\n\tPress Enter key to continue...")
        if configs["useRandomPIN"]:
            print("\n\n\tIf PIN is already set on security key(s) then script will prompt for existing PIN and change to new random PIN.")
            input("\n\tPress Enter key to continue...")

def create_pdf(user_display_name, user_name, pin, serial_number, output_folder):
    pdf_path = os.path.join(output_folder, f"{user_name}_YubiKey_Details.pdf")
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter

    # Styles configuration
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    title_style.alignment = TA_CENTER
    heading_style = styles["Heading2"]
    heading_style.alignment = TA_LEFT
    normal_style = styles["Normal"]
    normal_style.alignment = TA_LEFT
    normal_style.leading = 14 # Adjust line spacing
    bold_style = styles["Normal"]
    bold_style.fontName = 'Helvetica-Bold'
    bold_style.alignment = TA_LEFT
    list_style = ParagraphStyle(
        'ListStyle',
        parent=normal_style,
        alignment=TA_LEFT,
        bulletFontName='Helvetica',
        bulletFontSize=10,
        bulletIndent=15,
        leftIndent=30,
        firstLineIndent=-15,
    )
    security_warning_style = styles["Normal"]
    security_warning_style.alignment = TA_LEFT
    security_warning_style.textColor = red # Set text color to red for warnings

    left_margin = right_margin = 1 * inch
    content_width = width - (left_margin + right_margin)
    current_y = height - 0.8 * inch # Slightly higher starting position
    line_height = 0.25 * inch

    # Logo
    try:
        logo = ImageReader(logo_path)
        logo_width = 1.5 * inch
        logo_height = 0.5 * inch
        c.drawImage(logo, width - right_margin - logo_width, height - 0.8 * inch - logo_height,
                   width=logo_width, height=logo_height, mask='auto')
    except Exception as e:
        print(f"Warning: Logo not found. Error: {e}")

    # Main Title
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(width/2, height - 1.5 * inch, "YubiKey-Zugangsdaten")
    current_y = height - 2.0 * inch # Adjust current_y after title

    # Section 1: Benutzerinformationen
    c.setFont("Helvetica-Bold", 12)
    c.drawString(left_margin, current_y, "Benutzerinformationen")
    current_y -= line_height

    user_data = [
        f"<b>Name und Nachname:</b> {user_display_name}",
        f"<b>E-Mail-Adresse:</b> {user_name}",
        f"<b>Ausstellungsdatum:</b> {datetime.datetime.now().strftime('%d/%m/%Y')}"
    ]

    for data in user_data:
        p = Paragraph(data, normal_style) # Use normal style here for data
        p.wrapOn(c, content_width, line_height)
        p.drawOn(c, left_margin, current_y)
        current_y -= line_height

    current_y -= 0.3 * inch # Reduced space

    # Section 2: YubiKey-Details
    c.setFont("Helvetica-Bold", 12)
    c.drawString(left_margin, current_y, "YubiKey-Details")
    current_y -= line_height

    key_details = [
        f"<b>PIN:</b> {pin if configs['useRandomPIN'] else 'Vom Benutzer festgelegt'}", # More descriptive PIN info
        f"<b>Seriennummer:</b> {serial_number}"
    ]

    for detail in key_details:
        p = Paragraph(detail, normal_style) # Use normal style here for details
        p.wrapOn(c, content_width, line_height)
        p.drawOn(c, left_margin, current_y)
        current_y -= line_height

    current_y -= 0.3 * inch # Reduced space

    # Section 3: Gebrauchsanweisung
    c.setFont("Helvetica-Bold", 12)
    c.drawString(left_margin, current_y, "Gebrauchsanweisung")
    current_y -= line_height

    instructions = [
        ("1. Erster Zugriff", [
            "Stecken Sie den YubiKey in den USB-Anschluss des Geräts.",
            "Öffnen Sie den Browser und gehen Sie zu portal.yokipo.com",
            "Wenn Sie dazu aufgefordert werden, berühren Sie den YubiKey und geben Sie die PIN ein."
        ]),
        ("2. Ersteinrichtung", [
            "Vervollständigen Sie Ihr Benutzerprofil mit Ihren Daten.",
            "Legen Sie eine Sicherheitsfrage für die Wiederherstellung fest.",
            "Richten Sie die Zwei-Faktor-Authentifizierung ein."
        ]),
        ("3. Tägliche Nutzung", [
            "Für den Zugriff stecken Sie immer den YubiKey ein.",
            "Geben Sie die PIN niemals an Dritte weiter.",
            "Ändern Sie die PIN alle 90 Tage in den Einstellungen."
        ])
    ]

    for section_num, (section_title, items) in enumerate(instructions, 1): # Added section numbering
        c.setFont("Helvetica-Bold", 10)
        p_section_title = Paragraph(section_title, normal_style) # Normal style for subsection titles
        p_section_title.wrapOn(c, content_width, line_height)
        p_section_title.drawOn(c, left_margin, current_y)
        current_y -= line_height

        c.setFont("Helvetica", 10)
        for item in items:
            p_item = Paragraph(f"• {item}", list_style)
            p_item.wrapOn(c, content_width - 0.2*inch, line_height * 1.5) # Adjusted line height for bullet points
            p_item.drawOn(c, left_margin + 0.2*inch, current_y)
            current_y -= line_height * 1.1 # Slightly reduced spacing

        current_y -= 0.1 * inch # Reduced space between subsections

    current_y -= 0.2 * inch # Reduced space before Sicherheitshinweise

    # Section 4: Wichtige Sicherheitshinweise
    c.setFont("Helvetica-Bold", 12)
    c.drawString(left_margin, current_y, "Wichtige Sicherheitshinweise")
    current_y -= line_height

    security_items = [
        "Bewahren Sie den YubiKey bei Nichtgebrauch an einem sicheren Ort auf.",
        "Notieren Sie die PIN nicht auf Papier.",
        "Melden Sie Verluste unverzüglich an sicherheit@yokipo.com.",
        "Aktualisieren Sie die YubiKey-Firmware regelmäßig."
    ]

    c.setFont("Helvetica", 10)
    for item in security_items:
        p_item = Paragraph(f"• {item}", list_style)
        p_item.wrapOn(c, content_width - 0.2*inch, line_height * 1.5) # Adjusted line height for bullet points
        p_item.drawOn(c, left_margin + 0.2*inch, current_y)
        current_y -= line_height * 1.1 # Slightly reduced spacing


    # Footer
    footer_text = f"Generiert am {datetime.datetime.now().strftime('%d.%m.%Y %H:%M')} - Vertraulich"
    c.setFont("Helvetica", 8)
    c.drawCentredString(width/2, 0.5*inch, footer_text)

    c.save()
    print(f"\tPDF generato per {user_name}")


def main():
    warn_user_about_pin_behaviors()
    access_token = get_access_token_for_microsoft_graph()
    line_count = 0
    output_folder = os.path.join(".", group_name)
    os.makedirs(output_folder, exist_ok=True)

    with open(in_csv_file_name, newline="") as in_csv_file:
        with open(out_csv_file_name, "w", newline="") as out_csv_file:
            csv_reader = csv.reader(in_csv_file)
            csv_writer = csv.writer(out_csv_file)
            csv_writer.writerow(["#upn", "entraIDAuthMethodObjectId", "serialNumber", "PIN"])
            for row in csv_reader:
                if line_count == 0:
                    print("\tSkip csv header row")
                else:
                    user_name = row[0]
                    user_display_name = row[1]
                    user_id = row[2]
                    challenge = row[3]
                    challenge_expiry_time = row[4]
                    rp_id = row[5]
                    print("-------------------------------------------------")
                    print(f"\tProcessing user: {user_name}")
                    print("-------------------------------------------------")
                    (
                        att,
                        clientData,
                        credId,
                        extn,
                        serial,
                    ) = create_credentials_on_security_key(user_id, challenge, user_display_name, user_name, rp_id)
                    activated, auth_method = create_and_activate_fido_method(
                        credId,
                        extn,
                        user_name,
                        att,
                        clientData,
                        serial,
                        access_token,
                    )

                    if configs["useCTAP21Features"]:
                        set_ctap21_flags()
                    print(f"\n\tCompleted registration for: {user_name}")
                    csv_writer.writerow([user_name, auth_method, serial, pin])
                    create_pdf(user_display_name, user_name, pin, serial, output_folder) # Modified function call
                    input("\tPress Enter to continue...")
                    print("-----")

                line_count += 1
    print("\nProcess completed. Please verify results and clean up temporary files.\n")

if __name__ == "__main__":
    main()
