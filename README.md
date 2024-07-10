# entra-Id-register-passkeys-on-behalf-of-users
- This project will use Microsoft Graph APIs to provision FIDO2 credentials on a FIDO2 security key. 
- This project is an unsupported proof of concept.
- This project is a simplistic demonstration of how to use the Microsoft Graph APIs to register a FIDO2 security key with a CTAP client. 

## Overview
Microsoft Graph APIs allow for customers to develop solutions that allow for FIDO2 security keys to be registered using an admin driven on-behalf-of registration flow. Customers may use this type of flow for a variety of reasons including:

1. To reduce user friction and remove the burden of registering security keys from their users.  The admin performs all the registration tasks so that the user doesn’t need to take the time and learn how to do it.

2. As a passwordless bootstrapping method so that the user doesn’t have to be issued a password, or Temporary Access Pass (TAP).

3. As a high-assurance workflow where the organization only allows administrators to register authenticators into their environment, so they can identity proof the user, and provide them with an authenticator that the company has purchased.

4. Thick client apps can support additional capabilities that aren’t supported from WebAuthn or from a browser. Additional capabilities would be available to thick clients like enforcing PIN complexity with the minPinLength or forcePinChange [CTAP2.1](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-feature-descriptions) extensions. The security key must support the extensions see: https://www.yubico.com/blog/now-available-for-purchase-yubikey-5-series-and-security-key-series-with-new-5-7-firmware/. A thick client could also record serial numbers of the registered FIDO2 security keys for tracking purposes.

5. As a recovery mechanism after a user loses all of their security keys and other high-assurance authenticators and is locked out of their account.


## Major components
- Microsoft Graph FIDO2 credential registration API
- A thick client that supports CTAP or leverages system interfaces to interact with security keys.
- A FIDO2 security key like a YubiKey

![Sequence Diagram](images/SolutionOverview-FIDO2-security-key-Admin-on-behalf-of-registration.png)

## Scenarios supported
- Administrator led registration of users' primary and backup FIDO2 security keys.
- Bulk registration of security keys during FIDO2 security key deployment to an organization
- Recovery after a user loses all of their authenticators and is locked out of the account.

## Sample code
- [Bulk registration sample code](bulkRegistration/BulkRegistration.md)