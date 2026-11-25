# BankID, Norway: `bankid_no`

**What the person does:** logs in with BankID (app or code device). V18 gets the birth date,
decides 18+, and keeps nothing.

**Assurance:** high (`urn:bankid:bid`, LOA 4).

## What you must register for
- A BankID OIDC client through one of **BankID's partners** (bankid.no/en/company/bankid-partners).
  They provision test credentials first. Ask for scopes `openid profile` only.
- Callback: `https://<server>/v1/connect/bankid_no/callback`.
- Client authentication: a client secret, or (recommended by BankID) `private_key_jwt`. For the
  latter, send BankID support your public key, or point them at `/v1/connect/bankid_no/jwks`.

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_BANKID_NO_CLIENT_ID` | Client ID |
| `V18_CONNECTOR_BANKID_NO_CLIENT_SECRET` | Client secret, **or** |
| `V18_CONNECTOR_BANKID_NO_SIGNING_KEY` | Private key for `private_key_jwt` (RS256 JWK or PEM) |
| `V18_CONNECTOR_BANKID_NO_ISSUER` | Optional. Test ("current"): `https://auth.current.bankid.no/auth/realms/current/.well-known/openid-configuration` |
| `V18_CONNECTOR_BANKID_NO_ACR` | Optional. Default `urn:bankid:bid`. `urn:bankid:bis` is BankID with biometrics (LOA 3) |
| `V18_CONNECTOR_BANKID_NO_AUTH_METHOD` | Optional. `client_secret_post` instead of the default Basic |

## Test environment
"Current" (`auth.current.bankid.no`) with test users. The credentials come from a BankID
partner, so you need to sign up.

## How it works and what is read
- OIDC code flow with PKCE S256, state and nonce. The ID token is signed (checked against
  BankID's JWKS).
- Read from the ID token: `birthdate` (YYYY-MM-DD) and **`bankid_altsub`** as the subject.
  BankID documents `sub` as unstable, so it is not used. The name claims are dropped. The
  national identity number (`nnin_altsub`) is not requested.

## Sources read
docs.stoe.no/bankid-oidc-provider: Getting started, Scopes and Claims, ID Token, Identity
Providers (acr values), Client authentication, OpenID Configuration.
