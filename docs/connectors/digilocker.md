# DigiLocker, India: `digilocker`

**What the person does:** signs in to DigiLocker and agrees to share their account details.
DigiLocker sends the birth date with the login answer. V18 decides 18+ and keeps nothing.

**Assurance:** high (national government platform). V18 accepts only accounts whose details come
from Aadhaar (`eaadhaar` = `Y`), so the birth date is backed by Aadhaar.

India also has the zero-knowledge **Anon Aadhaar** method in V18, which is more private.
DigiLocker is the login alternative.

## What you must register for
- A **requester / partner** app through the API Setu / DigiLocker partner portal (NeGD approval,
  signed terms of use, a digital signature). Foreign entities may need an Indian mobile number
  and an Indian-hosted server, according to third-party guides. Check this when you apply.
- Ask for the **user details** (`userdetails`) access only.
- Callback: `https://<server>/v1/connect/digilocker/callback`.

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_DIGILOCKER_CLIENT_ID` | Client ID |
| `V18_CONNECTOR_DIGILOCKER_CLIENT_SECRET` | Client secret |
| `V18_CONNECTOR_DIGILOCKER_ISSUER` | Optional. Default `https://digilocker.meripehchaan.gov.in` |
| `V18_CONNECTOR_DIGILOCKER_PURPOSE` / `_SERVICE_NAME` | Optional. Shown on the consent screen (letters, digits, spaces, underscores). Defaults "Age check" / "V18 age check" |
| `V18_CONNECTOR_DIGILOCKER_REQUIRE_EAADHAAR` | Optional. `0` also accepts accounts not linked to Aadhaar (not recommended) |

## Test environment
No public sandbox. The partner FAQ says there is no separate test environment and access comes
through onboarding.

## How it works and what is read
- OAuth 2.0 code flow with **PKCE S256 (required by DigiLocker)** and the required `purpose` and
  `service_name` parameters. The client secret goes in the POST body.
- Token endpoint `/public/oauth2/1/token`. Its answer includes the user details. V18 reads only
  `digilockerid` (36 characters, stable) as the subject and `dob` (**DDMMYYYY**) for the age.
  `name`, `gender`, `mobile`, `reference_key` and the access token are dropped.
- Not used: the `/2/token` OIDC variant. Its sample ID token has `birthdate` as DD/MM/YYYY and a
  username as `sub`, which can change.

## Sources read
Requester – Meri Pehchaan API Specification v2.4 (API Setu PDF): Get Authorization Code, Get
Access Token, Get User Details. Discovery document at
`https://digilocker.meripehchaan.gov.in/.well-known/openid-configuration`.
