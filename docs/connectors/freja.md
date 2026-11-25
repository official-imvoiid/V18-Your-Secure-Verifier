# Freja eID, Sweden: `freja`

**What the person does:** confirms in the Freja app. Their account must be **EXTENDED** (an ID
document was checked). V18 gets the birth date, decides 18+, and keeps nothing.

**Assurance:** substantial (Freja eID+ is a private eID; EXTENDED and PLUS accounts are
ID-checked).

## Why OIDC (and not the REST API)
Freja has two interfaces: a REST API with mutual TLS (`initAuthentication` / `getOneResult`,
much like BankID) and its own **OpenID Connect** service. The OIDC service fits V18's redirect
flow directly, and Freja handles its own QR code and app hand-off. So this connector uses OIDC.

## What you must register for
- A relying party contract with Freja eID. Send company details to partnersupport@frejaeid.com
  and get a `client_id` and `client_secret`.
- Ask for the scope `https://frejaeid.com/oidc/scopes/birthdate` only.
- Callback: `https://<server>/v1/connect/freja/callback`.

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_FREJA_CLIENT_ID` | Client ID |
| `V18_CONNECTOR_FREJA_CLIENT_SECRET` | Client secret (sent in the POST body, as in Freja's example) |
| `V18_CONNECTOR_FREJA_ISSUER` | Optional. Customer test: `https://oidc-ct.test.frejaeid.com/oidc/.well-known/openid-configuration` |
| `V18_CONNECTOR_FREJA_AUTH_METHOD` | Optional. `client_secret_basic` if Freja asks for it |

## Test environment
Freja's customer test environment needs test client credentials from partner support. The app's
test mode and test users (the vetting portal) are free, but the client is not.

## How it works and what is read
- OIDC code flow with PKCE S256, state and nonce, plus `min_registration_level=EXTENDED`.
  The ID token signature is checked.
- Read: `birthdate` (YYYY-MM-DD) from the ID token (or userinfo, if it isn't in the token) and
  `sub` as the subject. The personal identity number scope is **not** requested.

## Sources read
frejaeid.atlassian.net (Freja documentation): OpenID Connect – General Guide; REST API
documentation and Authentication Service (for the comparison above).
