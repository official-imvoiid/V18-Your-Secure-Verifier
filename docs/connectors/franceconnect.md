# FranceConnect, France: `franceconnect`

**What the person does:** clicks "S'identifier avec FranceConnect" and logs in with an account
they already have (impots.gouv.fr, ameli.fr, La Poste...). V18 gets the birth date, decides 18+,
and keeps nothing.

**Assurance:** `substantial` in V18. Note that **FranceConnect is eIDAS "low"** (`eidas1`).
For a stronger check, use **FranceConnect+** (`PLUS=1`: `eidas2`, substantial, encrypted
tokens). FranceConnect+ has its own, stricter onboarding.

## What you must register for
- A **DataPass** request for a service provider ("fournisseur de service"), asking for the
  `birthdate` scope only. You then get sandbox credentials in the partner space.
- Callback: `https://<server>/v1/connect/franceconnect/callback`.

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_FRANCECONNECT_CLIENT_ID` | Client ID |
| `V18_CONNECTOR_FRANCECONNECT_CLIENT_SECRET` | Client secret (sent in the POST body) |
| `V18_CONNECTOR_FRANCECONNECT_ISSUER` | Optional. Sandbox: `https://fcp-low.sbx.dev-franceconnect.fr/api/v2/.well-known/openid-configuration` |
| `V18_CONNECTOR_FRANCECONNECT_PLUS` | Optional. `1` = FranceConnect+ (also needs `ENCRYPTION_KEY`) |

## Test environment
Sandbox `fcp-low.sbx.dev-franceconnect.fr` with demo identity providers (`fip1-low` and others)
and test identities. The credentials need DataPass, so you need to sign up.

## How it works and what is read
- OIDC code flow: scope `openid birthdate`, `acr_values=eidas1`, `prompt=login consent`.
  `state` and `nonce` must be at least 32 characters. PKCE is sent too (the docs don't mention
  it).
- The ID token is ES256 and the userinfo is an ES256-signed JWT. Both are checked against
  FranceConnect's JWKS.
- Read: `sub` (64 hex characters + "v1", per service) as the subject and `birthdate`
  (YYYY-MM-DD).
- FranceConnect writes a guessed month or day as `01`. So V18 treats `YYYY-01-01` as "only the
  year is known" and `YYYY-MM-01` as "only the month is known", and decides cautiously.
- Worth checking in the sandbox: the docs disagree in one place about the ID token signature
  (ES256 with JWKS, versus signed with the client secret). The connector expects ES256.

## Sources read
docs.partenaires.franceconnect.gouv.fr/fs/: technical endpoints, FC scopes, eIDAS/acr,
FranceConnect+ OIDC, sandbox environment.
