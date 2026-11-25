# UAE PASS, United Arab Emirates: `uaepass`

> **Not ready for real use:** UAE PASS's public attribute list has **no birth date**. This
> connector stays **off** until UAE PASS gives your service a date-of-birth attribute and you
> set its name in `V18_CONNECTOR_UAEPASS_DOB_ATTRIBUTE`.

**What the person does:** logs in with the UAE PASS app. Only verified accounts (`userType`
SOP2 or SOP3, checked against the Emirates ID) are accepted. V18 decides 18+ and keeps nothing.

**Assurance:** high (national digital identity) for SOP3 accounts.

## What you must register for
- Onboarding with the UAE PASS team (staging credentials first, then production).
- **Ask them for a date-of-birth attribute.** The documented attributes (`uuid`, `idn`,
  `fullnameEN`, nationality, gender, ...) have none. The docs say other attributes and scopes
  are "shared by the UAEPASS team".
- Callback: `https://<server>/v1/connect/uaepass/callback` (must match exactly).

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_UAEPASS_CLIENT_ID` | Client ID |
| `V18_CONNECTOR_UAEPASS_CLIENT_SECRET` | Client secret (sent with HTTP Basic, as UAE PASS requires) |
| `V18_CONNECTOR_UAEPASS_DOB_ATTRIBUTE` | The userinfo field name UAE PASS gives you for the birth date |
| `V18_CONNECTOR_UAEPASS_ISSUER` | Optional. Staging `https://stg-id.uaepass.ae`. Default `https://id.uaepass.ae` |
| `V18_CONNECTOR_UAEPASS_SCOPE` | Optional. Default `urn:uae:digitalid:profile:general` |
| `V18_CONNECTOR_UAEPASS_ACR` | Optional. Default `urn:safelayer:tws:policies:authentication:level:low` |

## Test environment
Staging (`stg-id.uaepass.ae`). The docs publish proof-of-concept credentials (`sandbox_stage`),
but logging in needs a **staging UAE PASS account** created in the staging app. That is a
sign-up, so it was not done.

## How it works and what is read
- OAuth 2.0 code flow: `/idshub/authorize`, `/idshub/token` (HTTP Basic), `/idshub/userinfo`
  (JSON). A PKCE challenge is also sent. UAE PASS doesn't document PKCE, and a server ignores
  parameters it doesn't know.
- Read: `uuid` (the documented unique user ID) as the subject, `userType` (must be SOP2/SOP3),
  and the configured birth-date field (YYYY-MM-DD or DD/MM/YYYY). Everything else is dropped.

## Sources read
docs.uaepass.ae: attributes list; web application authentication steps 1–3 and endpoints;
testing credentials for POC; create a staging account.
