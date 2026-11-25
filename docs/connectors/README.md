# V18 login connectors

A **connector** lets someone prove "I am 18 or older" by logging in with a government or bank ID
they already have. V18 sees the birth date (or a yes/no age answer) for a moment, decides
"18+", and keeps nothing. The code is the TypeScript package in `connectors/` (`@v18/connectors`).

**Nothing here is switched on until you register with the provider.** A connector only appears
when all of its settings (environment variables) are present. Registering is something **you**
have to do. The build sessions never sign up for anything.

## The 12 connectors

| ID | Name | Countries | Assurance in V18 | How it works | Page |
|----|------|-----------|------------------|--------------|------|
| `singpass` | Singpass (Myinfo) | SG | high | OIDC, FAPI 2.0 (PAR, DPoP, encrypted tokens) | [singpass.md](singpass.md) |
| `digilocker` | DigiLocker | IN | high | OAuth 2.0 + PKCE; birth date in the token response | [digilocker.md](digilocker.md) |
| `uaepass` | UAE PASS | AE | high | OAuth 2.0 + userinfo. **Needs a birth-date attribute from UAE PASS** | [uaepass.md](uaepass.md) |
| `bankid_se` | BankID (Sweden) | SE | high | BankID's own RP API v6 (mutual TLS), not OIDC | [bankid_se.md](bankid_se.md) |
| `bankid_no` | BankID (Norway) | NO | high | OIDC | [bankid_no.md](bankid_no.md) |
| `mitid` | MitID | DK | high | OIDC through a MitID broker (Signaturgruppen) | [mitid.md](mitid.md) |
| `itsme` | itsme | BE, NL, LU | high | OIDC (private_key_jwt, encrypted tokens) | [itsme.md](itsme.md) |
| `franceconnect` | FranceConnect | FR | substantial | OIDC | [franceconnect.md](franceconnect.md) |
| `spid` | SPID | IT | high | SAML 2.0 | [spid.md](spid.md) |
| `cie` | CIE (Entra con CIE) | IT | high | SAML 2.0 | [cie.md](cie.md) |
| `digid` | DigiD | NL | substantial | OIDC through a broker. **Probably not open to V18** | [digid.md](digid.md) |
| `freja` | Freja eID | SE | substantial | OIDC (Freja's own service) | [freja.md](freja.md) |

"Assurance" follows PROTOCOL.md 4d.4: `high` for eIDAS-high or national schemes, otherwise
`substantial`. Two choices differ from a word-for-word reading of that rule, on purpose:
- **FranceConnect** is national, but FranceConnect itself is only eIDAS **low**, so V18 calls it
  `substantial` (the lowest V18 level) and suggests FranceConnect+ (`PLUS=1`, eIDAS substantial).
- **Freja eID** is a private scheme (eIDAS substantial), and **DigiD** at "Substantieel" is
  substantial. Both are `substantial`.

## How to switch one on (after you register)

1. Read the connector's page (links above). Register with the provider or broker it names.
   Most give you a **test** account first.
2. Give the provider V18's callback address:
   `https://<your server>/v1/connect/<id>/callback` (for example
   `https://api.v18.example/v1/connect/singpass/callback`).
3. Put the settings in the server's environment. Every setting is named
   `V18_CONNECTOR_<ID>_<NAME>`, for example `V18_CONNECTOR_BANKID_NO_CLIENT_ID`.
   Keys and certificates can be pasted in directly or given as a file path.
4. Restart the server. The connector now shows in `GET /v1/catalog` for its countries.
5. To use a provider's **test** environment, set `V18_CONNECTOR_<ID>_ISSUER` (or `API_URL` for
   BankID Sweden) to the test address on the connector's page.

Settings for each connector:

| ID | Required | Optional |
|----|----------|----------|
| singpass | `CLIENT_ID`, `SIGNING_KEY`, `ENCRYPTION_KEY` | `ISSUER`, `ACR` |
| digilocker | `CLIENT_ID`, `CLIENT_SECRET` | `ISSUER`, `PURPOSE`, `SERVICE_NAME`, `REQUIRE_EAADHAAR` |
| uaepass | `CLIENT_ID`, `CLIENT_SECRET`, `DOB_ATTRIBUTE` | `ISSUER`, `SCOPE`, `ACR` |
| bankid_se | `CA`, and `PFX` (+`PASSPHRASE`) or `CERT` + `KEY` | `API_URL` |
| bankid_no | `CLIENT_ID`, and `CLIENT_SECRET` or `SIGNING_KEY` | `ISSUER`, `ACR`, `AUTH_METHOD` |
| mitid | `CLIENT_ID`, and `CLIENT_SECRET` or `SIGNING_KEY` | `ISSUER`, `MODE`, `AUTH_METHOD` |
| itsme | `CLIENT_ID`, `SERVICE_CODE`, `SIGNING_KEY`, `ENCRYPTION_KEY` | `ISSUER`, `ACR`, `ASK_BIRTHDATE` |
| franceconnect | `CLIENT_ID`, `CLIENT_SECRET` | `ISSUER`, `PLUS`, `ENCRYPTION_KEY` (with `PLUS=1`) |
| spid | `ENTITY_ID`, `PRIVATE_KEY`, `CERT`, `IDP_METADATA` | `LEVEL`, `ATTRIBUTE_INDEX`, `ORG_NAME`, `ORG_URL` |
| cie | `ENTITY_ID`, `PRIVATE_KEY`, `CERT`, `IDP_METADATA` | `LEVEL`, `ATTRIBUTE_INDEX`, `ORG_NAME`, `ORG_URL` |
| digid | `ISSUER`, `CLIENT_ID`, and `CLIENT_SECRET` or `SIGNING_KEY` | `SCOPE`, `ACR`, `BIRTHDATE_CLAIM`, `SUBJECT_CLAIM`, `AUTH_METHOD` |
| freja | `CLIENT_ID`, and `CLIENT_SECRET` or `SIGNING_KEY` | `ISSUER`, `AUTH_METHOD` |

`SIGNING_KEY` and `ENCRYPTION_KEY` are **private** keys as a JWK (JSON) or a PKCS#8 PEM.
Make them yourself (for example with `jose` or `openssl`), keep them secret, and give the
provider only the **public** half: the server publishes it at `/v1/connect/<id>/jwks`.

## Privacy: what "keeps nothing" means in the code

- A connector returns **only** `{ over18, subject }`. The tests check that the result object has
  exactly these two keys. Names, birth dates, ID numbers, photos and everything else the provider
  sends are read inside the connector and dropped.
- Where a provider can answer "18 or older?" with yes/no, V18 asks only that: itsme
  (`age_gte_18`) and MitID through Signaturgruppen (`age_verify:18`). Then no birth date ever
  reaches V18.
- `subject` is the provider's stable ID for the person. The server uses it only for
  nullifier = HMAC-SHA256(`V18_NULLIFIER_SECRET`, id + "|" + subject), and then forgets it.
- Errors are `ConnectorError` with a fixed English message, a `code` and at most a short provider
  error code (like `access_denied`). They never carry the provider's answer. The tests check this
  with names and birth dates in the mock data.

## For the server: using the package

**Build it first.** The server imports the built files.

```
cd connectors
npm install
npm run build
```

In `server/package.json`: `"@v18/connectors": "file:../connectors"`. Node 22.12 or newer is
needed. The package is CommonJS like the server. It loads `openid-client` and `jose` (ES modules)
through Node's `require()` of ES modules, the same way the server already loads `jose`.

```ts
import { createRegistry, ConnectorError } from '@v18/connectors';

const registry = createRegistry(process.env);  // only configured connectors
registry.summaries();      // [{ id, label, countries, assurance, callbackMethod }] for /v1/catalog
registry.forCountry('SE'); // connectors for one country
const c = registry.get(id); // undefined -> 404 / METHOD_DISABLED

// POST /v1/connect/:id/start
const { authUrl, session } = await c.buildAuthUrl({
  state,          // random, 32+ characters, bound to challenge + device key thumbprint
  nonce,          // random, 32+ characters
  codeVerifier,   // 43-128 characters, [A-Za-z0-9-._~]
  redirectUri,    // https://<server>/v1/connect/<id>/callback
  endUserIp,      // bankid_se only: the person's IP (req.ip, with trust proxy set right)
  idp,            // spid (and cie) only: the chosen identity provider's entityId
});
// Store { nonce, codeVerifier, redirectUri, session } server side under `state`. Never send
// `session` to the app: it can hold a short-lived DPoP private key (Singpass) or a BankID
// order secret.

// GET /v1/connect/:id/callback   (POST form body for spid and cie: c.callbackMethod === 'POST')
// Load and DELETE the stored record for params.state first (one use only), then:
const { over18, subject } = await c.handleCallback({ params, state, nonce, codeVerifier, redirectUri, session });
```

Other exports and methods:

| What | Use |
|------|-----|
| `c.jwks()` | Public keys for `GET /v1/connect/:id/jwks` (Singpass, itsme, and any connector with a `SIGNING_KEY`). Never contains private parts |
| `c.metadata(acsUrl)` | Signed SAML SP metadata for `GET /v1/connect/:id/metadata` (spid, cie) |
| `c.identityProviders()` | SPID/CIE identity providers to show as a list. Pass the chosen `entityId` as `idp` |
| `bankIdQrData(session, nowMs)` | BankID animated QR text for a person on a PC (refresh every second, show for up to 30 s) |
| `CONNECTOR_IDS`, `CONNECTOR_ENV` | All IDs; the settings each one reads |
| `isOver18`, `parseIsoDate`, ... | The same cautious age rule the connectors use |

Suggested mapping of `ConnectorError.code` to answers:

| code | Meaning | Suggested answer |
|------|---------|------------------|
| `NOT_CONFIGURED` | Missing setting | 501 `METHOD_DISABLED` |
| `BAD_REQUEST` | Bad start values (for example no `endUserIp` for BankID) | 400 |
| `STATE_MISMATCH` | The answer is not for this login | 400, redirect `v18://connect?status=error` |
| `PROVIDER_ERROR` | Person cancelled, or provider refused (`providerCode` says which) | redirect `status=cancelled` |
| `MISSING_BIRTHDATE` | Provider gave no usable birth date | 422 |
| `INVALID_RESPONSE` | Bad signature, replayed code, wrong audience, network trouble | 502 |
| `PENDING` | BankID: the person is not finished yet | 202, try again |

`over18: false` means a real person under 18: answer `403 UNDER_AGE` (PROTOCOL.md 4b item 10).

Things the server must do (the package can't do them itself):
- **Never log** callback query strings, form bodies or `session`. They hold codes, tokens and
  SAML assertions.
- **Delete the stored state before** calling `handleCallback`, so a callback works once even
  across several server instances. (OIDC providers also refuse a reused code. SAML replays are
  also blocked inside one process.)
- Serve `/v1/connect/:id/jwks` (Singpass, itsme) and `/v1/connect/:id/metadata` (spid, cie)
  when those connectors are configured.

## Tests

```
cd connectors
npm test
```

Every connector is tested against a **local mock** of its provider that answers in that
provider's real format. No test goes to the internet.
- OIDC providers: a real OpenID provider (`oidc-provider` package) set up like each provider:
  Singpass with PAR, DPoP, private_key_jwt and encrypted tokens; itsme with nested encrypted
  JWTs; FranceConnect with ES256 and JWT userinfo; and so on.
- DigiLocker and UAE PASS: a small OAuth 2.0 server that checks client secrets, PKCE and
  one-time codes.
- BankID Sweden: a mutual-TLS copy of `/auth` and `/collect`.
- SPID and CIE: a SAML identity provider that checks V18's signed request and signs assertions
  with `xml-crypto`.

For each connector the tests cover over 18, under 18, a missing birth date, a bad signature, a
bad state, a replayed code or response, a cancelled login, and the rule that only
`over18` and `subject` come back. The last run had **161 tests, 161 passed**.

Public sandboxes: none were used. Only one needs no sign-up at all (Signaturgruppen's MitID
pre-production, see [mitid.md](mitid.md)), and testing against it means logging in to a
third-party page with their published test users. You can do that yourself.

## Not in v1 / known limits

- **UAE PASS:** its public docs list **no birth-date attribute**. The connector stays off until
  UAE PASS gives you one and you set `V18_CONNECTOR_UAEPASS_DOB_ATTRIBUTE`. Its format has not
  been seen. ISO and day-first dates are both read.
- **DigiD:** Logius only connects government bodies and organisations with a legal public task.
  DigiD itself gives a BSN, not a birth date. The connector works only through a broker that
  adds a birth date, and V18 is probably not allowed to use DigiD at all.
- **SPID/CIE metadata:** `metadata()` makes valid signed SP metadata. AgID's extra contact
  details for private providers (`ContactPerson` with SPID extensions) are not generated. Add
  them before you submit it.
- **BankID Sweden on a PC:** the same-device flow works (BankID app on the same phone, or the
  BankID desktop app). For the phone-scans-PC-screen flow, the server must show a QR page using
  `bankIdQrData`. That page is not built here.
- Tested against mocks only, not against the live providers. Each page lists what to check in
  the provider's test environment once you have access.
