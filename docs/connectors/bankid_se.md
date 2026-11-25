# BankID, Sweden: `bankid_se`

**What the person does:** confirms in the BankID app. V18 gets their personal identity number,
reads the birth date from it, decides 18+, and keeps nothing.

**Assurance:** high (Sweden's main eID, issued by banks).

## Why not OIDC
Swedish BankID does not offer OpenID Connect itself. It has its own **relying party (RP) API**
over mutual TLS. This connector uses that documented API directly (v6.0). The alternative is a
broker that wraps BankID in OIDC (Idura/Criipto, Signicat and others). Through a broker the
setup is easier, but a third party sits in the middle. To go that way instead, the broker's OIDC
details can be added like `bankid_no`.

## What you must register for
- An **RP agreement with a Swedish bank** that sells BankID (you get an RP certificate).
  Usually a Swedish organisation number is needed. A broker is the usual route for others.
- Your RP certificate (`.p12`) and BankID's CA certificate (to trust their server).

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_BANKID_SE_CA` | BankID's server CA certificate (PEM text or file path) |
| `V18_CONNECTOR_BANKID_SE_PFX` + `_PASSPHRASE` | Your RP certificate as .p12/.pfx (file path) |
| or `V18_CONNECTOR_BANKID_SE_CERT` + `_KEY` | The same as PEM certificate and PEM key |
| `V18_CONNECTOR_BANKID_SE_API_URL` | Optional. Test: `https://appapi2.test.bankid.com/rp/v6.0`. Default production `https://appapi2.bankid.com/rp/v6.0` |

## Test environment
BankID's test environment is "free and open to all". The public test RP certificate
(`FPTestcert5_20240610.p12`, passphrase `qwerty123`) is on developers.bankid.com. To finish a
login you need a **test BankID**, issued from BankID's test portal. That is a sign-up, so it was
not done, and the live test server was not called.

## How it works and what is read
1. `buildAuthUrl` (needs `endUserIp`): `POST /auth` with `endUserIp` and `returnUrl` = the
   callback with `state`. The answer gives `orderRef`, `autoStartToken`, `qrStartToken` and
   `qrStartSecret`, which are stored in `session`.
2. `authUrl` is `https://app.bankid.com/?autostarttoken=...` (same device). When the person is
   done, the BankID app opens the `returnUrl`.
3. `handleCallback`: `POST /collect` every 2 seconds until `complete` (or `failed`, which gives
   `PROVIDER_ERROR` with the hint code). If it is still pending after 10 tries, you get `PENDING`.
4. Read: `completionData.user.personalNumber` (12 digits, `YYYYMMDDNNNN`; coordination numbers
   with day + 60 are handled) as the subject and for the birth date. The name, device, signature
   and OCSP response are dropped. Note: BankID asks RPs to keep completion data for audit. V18
   deliberately does not, because of its privacy rule.
- **Person on a PC, BankID on the phone:** show the animated QR code. `bankIdQrData(session)`
  gives the text (refresh every second; an order lasts 30 s). The tests check it against the
  example values in BankID's QR guide. The QR page itself is server/app work and is not built.

## Sources read
developers.bankid.com: API references `/auth` and `/collect`, how-to guides "Autostart" and
"QR code", test portal "Test information".
