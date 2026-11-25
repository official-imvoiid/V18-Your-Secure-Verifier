# DigiD, Netherlands: `digid`

> **Probably not available to V18.** Logius (who runs DigiD) connects only organisations that
> carry out a **public task set in law**, are allowed by law to use the citizen service number
> (BSN), and use DigiD for that task. A private age-check service is unlikely to qualify. Also,
> **DigiD gives a BSN, not a birth date.** Dutch users of itsme (`itsme`) are covered by that
> connector.

**Assurance:** substantial (DigiD "Substantieel" or higher, when the broker requests it).

## Why a broker
DigiD connects to approved organisations through SAML. Most of them use a **broker** that offers
OpenID Connect. This connector is a generic OIDC client for such a broker. It reads a birth date
only if the broker adds one (for example from a BRP lookup the organisation is allowed to do).

## What you must register for
- Approval by Logius (see above), plus a yearly ICT security assessment, then a broker contract.
- Ask the broker for: its discovery URL, a client, the acr value for "Substantieel", and the
  name of the **birth date claim** it can add.

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_DIGID_ISSUER` | The broker's issuer or discovery URL (required; there is no default) |
| `V18_CONNECTOR_DIGID_CLIENT_ID` | Client ID |
| `V18_CONNECTOR_DIGID_CLIENT_SECRET` | Client secret (or `SIGNING_KEY` for `private_key_jwt`) |
| `V18_CONNECTOR_DIGID_SCOPE` | Optional. Default `openid` |
| `V18_CONNECTOR_DIGID_ACR` | Optional. The broker's value for DigiD Substantieel/Hoog |
| `V18_CONNECTOR_DIGID_BIRTHDATE_CLAIM` | Optional. Default `birthdate` |
| `V18_CONNECTOR_DIGID_SUBJECT_CLAIM` | Optional. Default `sub` (do not use the BSN) |

## Test environment
Logius has a pre-production environment for approved organisations only. There is no public one.

## How it works and what is read
- OIDC code flow with PKCE S256, state, nonce, and a signed ID token. Userinfo is called only if
  the ID token has no birth date.
- Read: the configured birth date claim (ISO or day-first) and the subject claim. The BSN and
  everything else are dropped. Without a birth date claim every login fails with
  `MISSING_BIRTHDATE`.

## Sources read
logius.nl: DigiD domain page, "Aansluiten" (connection conditions), "Hoe werkt DigiD" (levels),
test connection request. No broker's DigiD page could be read (Signicat's page returned 404), so
the claim names are configurable instead of fixed.
