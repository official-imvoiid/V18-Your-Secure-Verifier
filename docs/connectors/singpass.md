# Singpass (Myinfo), Singapore: `singpass`

**What the person does:** logs in with the Singpass app. Singpass gives V18 their birth date
from Myinfo (government records). V18 decides 18+ and keeps nothing.

**Assurance:** high (national digital identity, government-verified data).

## What you must register for
- A **Singpass Login + Myinfo (v5)** app on the Singpass Developer Portal. Apps registered after
  10 February 2026 must use the FAPI 2.0 API, which this connector uses.
- Ask for the **`dob`** scope only.
- Singpass needs a **JWKS URL** for your app: give it `https://<server>/v1/connect/singpass/jwks`.
  It must hold one signing key (ES256) and one encryption key (ECDH-ES, P-256).
- Callback (`redirect_uri`, https only): `https://<server>/v1/connect/singpass/callback`.
- Singapore's rules decide who may use Myinfo. A foreign service may need a Singapore entity or
  partner. Check this during onboarding.

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_SINGPASS_CLIENT_ID` | Your app's client ID |
| `V18_CONNECTOR_SINGPASS_SIGNING_KEY` | Private EC P-256 key (JWK with `kid`, or PKCS#8 PEM) |
| `V18_CONNECTOR_SINGPASS_ENCRYPTION_KEY` | Private EC P-256 key for decryption (JWK with `kid` and `"alg":"ECDH-ES+A256KW"`) |
| `V18_CONNECTOR_SINGPASS_ISSUER` | Optional. Staging: `https://stg-id.singpass.gov.sg/fapi/.well-known/openid-configuration` |
| `V18_CONNECTOR_SINGPASS_ACR` | Optional. `urn:singpass:authentication:loa:2` or `loa:3` (needs whitelisting) |

## Test environment
Staging at `stg-id.singpass.gov.sg`, with test accounts ("Myinfo test personas") from the
Developer Portal. It needs a staging app, so it needs sign-up. There is no public sandbox.

## How it works and what is read
- **PAR** (the browser URL carries only `client_id` and `request_uri`), **DPoP** on PAR, token
  and userinfo, **PKCE S256**, `private_key_jwt` (ES256, `aud` = issuer), state and nonce.
- The ID token is always a **JWE** (ECDH-ES+A256KW / A256CBC-HS512) around an ES256 JWS. The
  userinfo is a signed JWT inside a JWE. `openid-client` decrypts and checks both.
- Read: `sub` (a UUID) as the subject, and `person_info.dob.value` (YYYY-MM-DD; YYYY-MM or YYYY
  is handled cautiously). If Myinfo marks `dob` as unavailable, the login fails with
  `MISSING_BIRTHDATE`.
- The DPoP key is made new for each login. It travels in `session`, which the server keeps
  server side and deletes after the callback.

## Sources read
docs.developer.singpass.gov.sg: integration guide 1 (authorization request), 3 (token exchange),
4 (parsing the ID token), 5 (userinfo); client assertion; OIDC discovery; changelog; Myinfo v5
migration guide.
