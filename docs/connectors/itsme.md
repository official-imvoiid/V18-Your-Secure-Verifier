# itsme, Belgium / Netherlands / Luxembourg: `itsme`

**What the person does:** confirms in the itsme app. V18 asks only for **`age_gte_18`** (yes or
no), so no birth date reaches V18.

**Assurance:** high (itsme is notified under eIDAS at level high).

## What you must register for
- Onboarding with itsme (email onboarding@itsme-id.com). You get a B2B portal account, a
  `client_id` and a **service code** for an "Authentication" service.
- Ask for the `age_gte_18` claim. Its availability depends on the person's ID document.
- itsme uses `private_key_jwt` and encrypts tokens to you. Register the JWKS URL
  `https://<server>/v1/connect/itsme/jwks` (signing key RS256, encryption key RSA-OAEP).
- Callback (https, exact match): `https://<server>/v1/connect/itsme/callback`.

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_ITSME_CLIENT_ID` | Client ID |
| `V18_CONNECTOR_ITSME_SERVICE_CODE` | Your service code (sent as scope `service:<code>`) |
| `V18_CONNECTOR_ITSME_SIGNING_KEY` | Private RSA key for `private_key_jwt` |
| `V18_CONNECTOR_ITSME_ENCRYPTION_KEY` | Private RSA key for decryption (JWK with `kid` and `"alg":"RSA-OAEP"` or `RSA-OAEP-256`, matching what you register) |
| `V18_CONNECTOR_ITSME_ISSUER` | Optional. Sandbox: `https://idp.e2e.itsme.services/v2/.well-known/openid-configuration` |
| `V18_CONNECTOR_ITSME_ACR` | Optional. Default `http://itsme.services/v2/claim/acr_basic` |
| `V18_CONNECTOR_ITSME_ASK_BIRTHDATE` | Optional. `1` also asks for `birthdate`, used only when `age_gte_18` is missing |

## Test environment
"e2e" (`idp.e2e.itsme.services`). It needs onboarding, so it needs sign-up.

## How it works and what is read
- OIDC code flow with PKCE S256, state and nonce. Scope `openid service:<code>`, plus the
  `claims` parameter `{"userinfo":{"age_gte_18":null}}`.
- `private_key_jwt` with `aud` = the token endpoint (as itsme's v2 docs say).
- The ID token and userinfo are nested JWTs (signed, then encrypted). Both are decrypted and
  their signatures checked.
- Read: `sub` as the subject and `age_gte_18` (boolean). With `ASK_BIRTHDATE=1`, `birthdate` is
  the fallback.
- Things to check in e2e: the exact JWE algorithms itsme uses for your client, and whether PKCE
  is enforced for your client. Both are decided per client at onboarding.

## Sources read
belgianmobileid.github.io/doc/authentication (v2). The deprecated v1 page `slate/login` was used
only for comparison.
