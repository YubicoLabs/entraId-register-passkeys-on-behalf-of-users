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

import csv
import json
import re

import requests

csv_file_name = "./usersToRegister.csv"
config_file_name = "configs.json"


# Disabling warnings that get produced when certificate stores aren't updated
# to check certificate validity.
# Not recommended for production code to disable the warnings.
# This is the warning that is produced when the warnings are not disabled.
# InsecureRequestWarning: Unverified HTTPS request is being made
# to host 'login.microsoftonline.com'. Adding certificate verification is
# strongly advised. See:
# https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
requests.packages.urllib3.disable_warnings()

with open(config_file_name, "r", encoding="utf8") as f:
    configs = json.load(f)


def set_http_headers(access_token):
    return {
        "Accept": "application/json",
        "Authorization": access_token,
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
    }


def get_access_token_for_microsoft_graph():
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

    print("\t retrieved access_token using app credentials")
    return access_token.group(1)


def get_group_id_for_users_in_scope_for_registration(access_token):
    print("-----")
    print("in get_group_id_for_users_in_scope_for_registration\n")

    headers = set_http_headers(access_token)

    groups_endpoint = "https://graph.microsoft.com/beta/groups/"
    params = {
        "$filter": "displayName eq '" + configs["usersInScopeGroup"] + "'"
    }
    print(f"\tCalling: GET {groups_endpoint}")
    response = requests.get(
        groups_endpoint, headers=headers, params=params, verify=False
    )
    if response.status_code == 200:
        group_id = response.json()["value"][0]["id"]
        return group_id
    else:
        print(response.status_code)
        print(response.content)
        return None


def get_users_in_scope_for_registration(group_id, access_token):
    print("-----")
    print("in get_users_in_scope_for_registration\n")

    headers = set_http_headers(access_token)
    params = {"$select": "id,userPrincipalName"}
    group_members_endpoint = (
        "https://graph.microsoft.com/beta/groups/" + group_id + "/members"
    )
    print(f"\tCalling: GET {group_members_endpoint}")
    response = requests.get(
        group_members_endpoint, headers=headers, params=params, verify=False
    )
    if response.status_code == 200:
        members = response.json()["value"]
        return members
    else:
        print(response.status_code)
        print(response.content)
        return None


# Check if the user has any existing fido2 methods
def does_user_have_fido_credential(userID, access_token):
    print("-----")
    print("in does_user_have_fido_credential\n")
    headers = set_http_headers(access_token)

    fido_credentials_endpoint = (
        "https://graph.microsoft.com/beta/users/"
        + userID
        + "/authentication/fido2Methods"
    )
    print(f"\tCalling: GET {fido_credentials_endpoint}")
    hasFido = False
    fido_credentials = []
    response = requests.get(
        fido_credentials_endpoint, headers=headers, verify=False
    )

    if response.status_code == 200:
        fido_credential_list = response.json()
        hasFido = True
        for credential in fido_credential_list["value"]:
            fido_credentials.append(credential["id"])
        print(f"\tUser has: {len(fido_credentials)} existing "
              "fido2 security keys registered")

    else:
        print(response.status_code)
        print(response.content)
        return False, []

    return hasFido, fido_credentials


# Delete All FIDO Credentials
def delete_all_fido_credentials(userID, fido_credentials, access_token):
    print("-----")
    print("in delete_all_fido_credentials\n")
    headers = set_http_headers(access_token)

    for credential in fido_credentials:
        fido_credentials_endpoint = (
            "https://graph.microsoft.com/beta/users/"
            + userID
            + "/authentication/fido2Methods/"
            + credential
        )
        print(f"\tCalling: DELETE {fido_credentials_endpoint}")
        response = requests.delete(
            fido_credentials_endpoint, headers=headers, verify=False
        )

        if response.status_code == 204:
            print(f"\tDeleted FIDO Credential: {credential}")
        else:
            print(response.status_code)
            print(response.content)
            return

    return


def get_fido2_creation_options(userID, access_token):
    print("-----")
    print("in get_fido2_creation_options\n")

    headers = set_http_headers(access_token)
    challenge_timeout = configs["challengeTimeoutInMinutes"]
    params = {"challengeTimeoutInMinutes": challenge_timeout}
    print("\tGetting fido creation options for user with "
          f"expiry: {challenge_timeout}")

    fido_credentials_endpoint = (
        "https://graph.microsoft.com/beta/users/"
        + userID
        + "/authentication/fido2Methods/creationOptions"
    )

    response = requests.get(
        fido_credentials_endpoint, headers=headers, params=params, verify=False
    )
    if response.status_code == 200:
        creation_options = response.json()
        print("\tRetrieved fido creation options for "
              f'user: {creation_options["publicKey"]["user"]["name"]}')

        return True, creation_options
    else:
        print(response.status_code)
        print(response.content)
        return False, None


def format_csv_header_row():
    header = [
        "#User.Name",
        "User.DisplayName",
        "User.ID",
        "Challenge",
        "ChallengeExpiryTime",
        "RP.ID"
    ]
    return header


def main():
    access_token = get_access_token_for_microsoft_graph()
    group_id = get_group_id_for_users_in_scope_for_registration(access_token)
    users = get_users_in_scope_for_registration(group_id, access_token)

    with open(csv_file_name, "w", newline="") as out:

        csvwriter = csv.writer(out)
        # Header line for output csv file
        header = format_csv_header_row()
        csvwriter.writerow(header)

        # Now get the FIDO2 credential creation options for each user that
        # is in scope for processing and write to csv
        for user in users:
            print(
                "\n\n------------------------------------------------------"
            )
            print(f'processing user: {user["userPrincipalName"]}')
            print(
                "------------------------------------------------------\n\n"
            )

            has_fido, fido_credentials = does_user_have_fido_credential(
                user["id"], access_token
            )
            if has_fido and configs["deleteExistingUserFIDOCredentials"]:
                print("\tDeleting existing credentials")
                delete_all_fido_credentials(
                    user["id"], fido_credentials, access_token
                )

            # Initiate a new FIDO credential creation by getting the FIDO
            # credential creation options
            optionsReturned, webauthnParams = get_fido2_creation_options(
                user["id"], access_token
            )
            if optionsReturned:
                row = [
                    webauthnParams["publicKey"]["user"]["name"],
                    webauthnParams["publicKey"]["user"]["displayName"],
                    webauthnParams["publicKey"]["user"]["id"],
                    webauthnParams["publicKey"]["challenge"],
                    webauthnParams["challengeTimeoutDateTime"],
                    webauthnParams["publicKey"]["rp"]["id"]
                ]
                csvwriter.writerow(row)
    print("\nCompleted retrieval of fido creation requests for users in "
          f'group: {configs["usersInScopeGroup"]}. See csv: {csv_file_name}\n')


main()
