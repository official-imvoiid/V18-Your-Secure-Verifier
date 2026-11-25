# MitID, Denmark: `mitid`

**What the person does:** logs in with MitID. By default V18 asks only **"is this person 18 or
older?"** and gets back yes or no. No birth date reaches V18 at all.

**Assurance:** high (national scheme; MitID flows are NSIS-rated, substantial by default).

## Why a broker
Relying parties can only use MitID through a **certified MitID broker**, which speaks OpenID
Connect. This connector follows the **Signaturgruppen broker** (also called Nets eID Broker),
whose documentation is public. Its `age_verify` scope fits V18 exactly. Other brokers can be
used by setting `ISSUER`, if they offer the same claims.

## What you must register for
- An agreement with Signaturgruppen (they set up your own technical client for production).
  Each MitID login costs money. Ask for the **age verification** flow (`age_verify:18`).
- Callback: `https://<server>/v1/connect/mitid/callback`.

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_MITID_CLIENT_ID` | Client ID |
| `V18_CONNECTOR_MITID_CLIENT_SECRET` | Client secret (or `SIGNING_KEY` for `private_key_jwt`) |
| `V18_CONNECTOR_MITID_ISSUER` | Optional. Pre-production: `https://pp.netseidbroker.dk/op/.well-known/openid-configuration`. Default production `https://netseidbroker.dk/op/...` |
| `V18_CONNECTOR_MITID_MODE` | Optional. `mitid` = full MitID flow, reads `mitid.date_of_birth` from userinfo. Default: age check only |

## Test environment (public, no sign-up)
Signaturgruppen's pre-production (`pp.netseidbroker.dk`) has **open test clients** that allow
any redirect URI, and **public MitID test users** for age checks (born 1985, 2008 and 2011; the
password is on their "Age Verification (MitID)" page). You can try V18 against it yourself:
set `ISSUER` to the pre-production URL and `CLIENT_ID` / `CLIENT_SECRET` to the open code-flow
age-check client from that page. It was **not** run here: that means logging in on a third-party
page with their test users.

## How it works and what is read
- OIDC code flow with PKCE S256, state, nonce, and a signed ID token (checked against the JWKS).
- Default: scope `openid age_verify:18`, `prompt=login`. Read `idbrokerdk_age_verified`
  (`"18:true"` or `"18:false"`) and `sub` (the broker's stable ID for the person, per
  organisation).
- `MODE=mitid`: scope `openid mitid`, `idp_values=mitid`. Read `mitid.date_of_birth` from
  userinfo. `mitid.identity_name`, `mitid.uuid` and the other claims are dropped. The CPR number
  is never requested.

## Sources read
signaturgruppen-a-s.github.io/signaturgruppen-broker-documentation: MitID identity provider,
Environments, Test clients, Age Verification (MitID), Issued claims and tokens.
