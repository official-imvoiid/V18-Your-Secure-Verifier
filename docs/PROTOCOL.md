# V18 protocol and design specification

This document is the specification for V18: the HTTP protocol between the apps, the server and
websites (section 3), the decisions that refined it (4b), the features of the complete product
(4c), and the ways each country can prove age (4d). Code comments refer to it by section number,
for example "PROTOCOL.md 3.4". `README.md` explains the idea in plain English.

## 2. Design rules

- **Privacy:** never store, log or send a name, date of birth, ID number, ID image, face image, or
  which person visited which site. No request-body logging. The server stores only: ticket
  signing keys, card records (card ID, device public key, method, validity, nullifier hash,
  status), nullifier hashes, issuer trust lists, country rules and anonymous counters.
- **No home-made cryptography.** Use vetted libraries. Where no vetted library exists for a
  platform (RFC 9474 client steps in Dart), implement **exactly** per the RFC, pass **every**
  RFC 9474 Appendix A test vector for `RSABSSA-SHA384-PSS-Randomized`, and cross-test against
  the server's `@cloudflare/blindrsa-ts`.
- **Test data only in the repository.** No real Aadhaar, passport or personal data. Tests use
  Anon Aadhaar test mode and test QR codes, sample passport data, and the dev test issuer.
- **Honesty:** nothing fake is presented as real. Test-only parts are labelled "test" in code,
  UI and docs.
- **Plain, simple English** in UI copy and docs.
- **Names:** the product is **V18**. Deep-link scheme `v18://`. npm scope `@v18/`. Python package
  `v18_verify`. Android application ID `com.v18.app`. Windows app ID `com.v18.desktop`.

## 3. Protocol (version 1)

Dev base URL: `http://localhost:8080/v1`. Demo site: `http://localhost:3000`. All bodies are JSON.
Errors: `{"error": "<text>", "code": "<CODE>"}` with a fitting 4xx or 5xx status. Binary values
are **base64url without padding** unless stated.

### 3.1 Modes

- `V18_DEV_MODE=1` enables the `test_dev` issuer and Anon Aadhaar **test** keys. Without it
  (production), `test_dev` returns 501 `METHOD_DISABLED` and test proofs are rejected.
- The npm dev scripts set `V18_DEV_MODE=1`. Every app shows a visible **TEST MODE** banner
  whenever it talks to a dev-mode server (`GET /v1/health` returns `"devMode": true`).

### 3.2 Ticket signing keys

- Algorithm `RSABSSA-SHA384-PSS-Randomized` (RFC 9474), RSA-2048 in dev, 3072 allowed in production.
- **One key per age threshold and period.** Key ID: `v18-age18-<YYYYMMDD>` (the start date).
- `GET /v1/keys` returns a JWKS. Each key has `kid`, `kty`, `n`, `e`, `use: "sig"`,
  `alg: "RSABSSA-SHA384-PSS-Randomized"`, `v18_min_age` (integer), `nbf` and `exp` (epoch seconds).
- Rotation: a new key every `V18_KEY_ROTATION_DAYS` (default 7). JWKS lists the previous, current
  and next keys. Keys persist across restarts: dev keeps them in `server/data/` (gitignored), and
  production goes through a `KeyStore` interface meant for KMS/HSM.
- `GET /v1/keys/pem?kid=` keeps working for the given or current key.

### 3.3 Challenges

`POST /v1/challenge` returns `{"challenge": "<64 hex chars>", "expiresAt": "<ISO>"}`. It is
single use and valid for 5 minutes. Every card, ticket and link request consumes one.

### 3.4 Device keys and device signatures

Each app makes one device key per age card in secure hardware, unlocked by the user (fingerprint,
face unlock, PIN or Windows Hello). Allowed key types:

| `alg` | Key | Signature over the UTF-8 bytes of the signing string |
|-------|-----|----------------------------------|
| `ES256` | EC P-256, JWK `{kty:"EC",crv:"P-256",x,y}` | ECDSA SHA-256. `sig` is DER **or** 64-byte raw r‖s; the server accepts both |
| `RS256` | RSA-2048, JWK `{kty:"RSA",n,e}` | RSASSA-PKCS1-v1_5 SHA-256. This is the Windows Hello `KeyCredential` default |

A device signature is `{"alg": "ES256" | "RS256", "sig": "<base64url>"}`. The card's
`deviceKeyThumbprint` is the RFC 7638 JWK thumbprint (SHA-256, base64url) of the device public key.

Signing strings (fields joined with `\n`, no trailing newline):

| Action | Signing string |
|--------|----------------|
| Issue card (proof of possession) | `v18-card-issue` `\n` challenge `\n` deviceKeyThumbprint |
| Request ticket | `v18-ticket-request` `\n` cardId `\n` challenge `\n` keyId `\n` blindedMessage |
| Approve device link | `v18-link-approve` `\n` cardId `\n` challenge `\n` linkId |
| Delete card | `v18-card-delete` `\n` cardId `\n` challenge |

### 3.5 Age cards

`POST /v1/card/issue`

```json
{ "method": "test_dev" | "anon_aadhaar" | "passport_zk",
  "challenge": "...",
  "devicePublicKey": { "...JWK...", "alg": "ES256" },
  "deviceSignature": { "alg": "ES256", "sig": "..." },
  "proof": { "...method-specific..." } }
```

- `test_dev` (dev mode only): `proof = {"testSubjectId": "...", "birthDate": "YYYY-MM-DD"}`.
- `anon_aadhaar`: `proof` is the Anon Aadhaar proof object (from `@anon-aadhaar/core`), which must
  reveal **only** "age above 18". Its signal binds the request: signal = `challenge` + `"|"` +
  deviceKeyThumbprint. The nullifier comes from the proof, with nullifier seed = the server's
  `V18_AADHAAR_NULLIFIER_SEED`. The server verifies with `@anon-aadhaar/core`'s verifier and accepts
  the test UIDAI key only in dev mode.
- `passport_zk`: reserved. It returns 501 `METHOD_NOT_READY` until a passport circuit is chosen.
  The planned shape is `{"circuit": "<name>", "proof": ..., "publicSignals": ...}`, with an over-18
  output, a nullifier and challenge binding.

Response 201: `{"cardId": "card_<base64url 16 bytes>", "method", "assuranceLevel", "minAgeCertified": 18, "validUntil": "<ISO>"}`.
Validity: 180 days for `anon_aadhaar` and `passport_zk`, 30 days for `test_dev`, never beyond the ID's own validity.

Nullifier rule: at most `V18_MAX_CARDS_PER_ID` active cards per nullifier (default 3). A further
card returns 409 `NULLIFIER_OVERUSED`.

Other card endpoints:
- `DELETE /v1/card/:cardId` with body `{challenge, deviceSignature}` revokes the card and frees its slot.
- `GET /v1/card/:cardId/status` returns `{status: "active" | "revoked" | "expired", validUntil}`.
  It reveals nothing else.

### 3.6 Tickets

`POST /v1/ticket/blind-sign`

```json
{ "cardId": "...", "challenge": "...", "keyId": "v18-age18-20261109",
  "blindedMessage": "...", "deviceSignature": { "alg": "...", "sig": "..." } }
```

The server checks all of these, or refuses: the challenge is valid (and is consumed); the card is
active and unexpired; the device signature is valid for that card's key; the key's `v18_min_age`
is no more than the card's `minAgeCertified`; the key is current; and the card is under the rate
limit (`V18_TICKETS_PER_HOUR`, default 30). It then returns
`{"blindSignature", "keyId", "algorithm": "RSABSSA-SHA384-PSS-Randomized"}`.
**A request without a valid card and device signature gets 401 `CARD_REQUIRED`.**

Ticket message (built by the app, never seen by the server): UTF-8 JSON

```json
{"v":1,"ticketId":"<base64url 16 random bytes>","origin":"https://example-site.test",
 "challenge":"<the website's challenge>","minAge":18,"iat":1762700000,"expiresAt":1762700300}
```

- `origin` is the website's web origin (`scheme://host[:port]`). The user approves it on screen.
- `expiresAt` is at most `iat` + 300.
- `prepared` = RFC 9474 `prepare` output (32 random bytes followed by the message). The app blinds
  `prepared`, then finalizes.
- **Ticket string:** `<keyId>.<base64url(prepared)>.<base64url(signature)>`

### 3.7 Website verification (verify libraries)

A ticket is valid only if **all** of these hold:
1. The `keyId` is in the JWKS and now ≤ `exp` + 600 seconds.
2. The signature is a valid RSA-PSS (SHA-384, MGF1-SHA-384, salt length 48) signature over `prepared`.
3. `payload.v == 1`.
4. `origin` equals the site's origin.
5. `challenge` equals the challenge this site issued for this visit.
6. The key's `v18_min_age` is at least the site's required age. Authorization uses the key's
   threshold, never the payload's `minAge`.
7. `iat` - 60 ≤ now ≤ `expiresAt` + 60, and `expiresAt` - `iat` ≤ 300.
8. `ticketId` has not been seen before (replay cache).

Websites must verify on their own **server**. The browser widget alone is never trusted.

### 3.8 QR hand-off (website to phone or Windows app)

These are the existing endpoints, hardened:
- `POST /v1/pairing/session` takes `{origin, challenge, minAge, ttlSeconds}` and returns
  `{sessionId, deepLink, qrData, expiresAt, expiresIn, pollUrl}`. The session ID is at least 128
  random bits. If the request has an HTTP `Origin` header, it must equal `origin`.
- `GET /v1/pairing/:id`, `POST /v1/pairing/:id/connect`, `POST /v1/pairing/:id/submit {ticket}`
  (once only), `POST /v1/pairing/:id/cancel`. A delivered ticket is returned by the poll
  **once**, then cleared.
- Deep link:
  `v18://verify?session=<id>&origin=<urlenc>&challenge=<urlenc>&minAge=18&server=<urlenc base URL>`

### 3.9 Device link (getting an age card onto a second device, such as the PC)

1. The PC creates a device key, then calls `POST /v1/card/link/start` with
   `{devicePublicKey, challenge, deviceSignature}`. The signature is the issue-card proof of
   possession. The response is `{linkId, deepLink, expiresIn}`, with
   deepLink `v18://link?id=<linkId>&server=<urlenc>`. The link lasts 120 seconds and works once.
2. The phone (holding an active card) scans the QR, asks for a fingerprint, then calls
   `POST /v1/card/link/:linkId/approve` with `{cardId, challenge, deviceSignature}`.
3. The server issues a new card bound to the PC's key, with the same nullifier (it counts toward
   the cap) and a `validUntil` no later than the phone card's.
4. The PC polls `GET /v1/card/link/:linkId`, which returns
   `{status: "waiting" | "approved" | "expired", card?}`. The card is returned once.

### 3.10 Apps: what is stored on the device

Only: card ID, method, `validUntil`, the device key's alias (the key itself stays in Keystore,
StrongBox or Windows Hello), the server URL and settings. **Shared-device mode** stores no card
at all. Each visit then needs a phone hand-off. Apps accept `server=` values only from a built-in
allowlist (`http://localhost:8080` and `http://10.0.2.2:8080` in debug builds, plus the
production URL placeholder).

## 4. Ports and commands

- Server: port 8080 (`npm run dev --prefix server`, which sets `V18_DEV_MODE=1`).
- Demo site: port 3000.
- The Android emulator reaches the PC's server at `http://10.0.2.2:8080`.
- Tools: Node.js 22, Python 3.9 or newer, Rust and Microsoft C++ Build Tools; for the Android app
  also Flutter 3.47, JDK 17 and the Android SDK (API 36, NDK 28). `SETUP.bat` installs all of them.

## 4b. Protocol decisions (v1.1)

These decisions settle questions found while building, and each overrides anything above it.

| # | Topic | Decision |
|---|-------|----------|
| 1 | Anon Aadhaar signal | `signal = "0x" + hex(SHA-256(UTF-8(challenge + "\|" + deviceKeyThumbprint)))`. The app passes this to `generateArgs`. See `docs/server/API.md` |
| 2 | Nullifier seed | Published as `aadhaarNullifierSeed` in `GET /v1/health` |
| 3 | Importing JWKS keys | Clients import only `{kty, n, e}`. WebCrypto-style importers reject the `alg` value `RSABSSA-SHA384-PSS-Randomized` |
| 4 | `assuranceLevel` | `test` (test_dev), `substantial` (anon_aadhaar), `high` (passport_zk) |
| 5 | CORS | **Widget endpoints are open to any website**, without cookies: `GET /v1/health`, `GET /v1/keys`, `GET /v1/keys/pem`, `POST /v1/pairing/session` (the `Origin` header must still equal `origin`), `GET /v1/pairing/:id` and `POST /v1/pairing/:id/cancel`. Session creation is rate-limited per IP. **App endpoints** (challenge, card, ticket, link, and pairing connect and submit) stay limited to the dev demo origin plus `V18_CORS_ORIGINS` |
| 6 | QR theft | Known limit: anyone who sees a QR can submit first. They cannot use the ticket, but the visitor has to retry. Widgets tell people not to share the QR |
| 7 | Pairing `challenge` | Required on `POST /v1/pairing/session` |
| 8 | `server=` in deep links | The base URL **without** `/v1`, for example `http://localhost:8080` |
| 9 | Debug allowlists | Android: `http://localhost:8080` and `http://10.0.2.2:8080`. Windows: `http://localhost:8080` only |
| 10 | Under 18 | `403 UNDER_AGE` from card issue. Apps show the "Under 18" screen |
| 11 | Card length (6 or 12 months in the designs) | Not in v1. The server decides validity, and apps show `validUntil`. A future `requestedValidityDays` may let the user choose |
| 12 | Key `nbf` | Verifiers refuse a ticket whose key `nbf` is more than 60 seconds in the future |
| 13 | Pairing poll statuses | `waiting`, `connected`, `approved`, `expired`, `cancelled`. A 404 means expired |
| 14 | Windows app and pairing | The Windows app submits its ticket to the same pairing session the phone would use |
| 15 | Website challenge format | An opaque string of 16 to 256 URL-safe characters. The verify libraries make 32 random bytes as hex |
| 16 | Payload `minAge` | Must be a number, but is never used to authorize. The key's `v18_min_age` decides |

## 4c. The complete product (v1.2)

Rules for the complete product:

- **Everything visible works.** Every option shown in an app or the widget does the real thing end
  to end. Nothing is labelled "stub", "coming soon" or "not available yet". If something can't be
  made real and trustworthy now, **remove it from the UI** and list it in the docs under "Not in v1".
- **Methods in v1:**

| Method | Where | Assurance | Card validity |
|--------|-------|-----------|---------------|
| `anon_aadhaar` (real zero-knowledge proof) | Phone and Windows | `substantial` | 180 days |
| `passport_attested` (chip read and checked on a hardware-attested phone) | Phone | `substantial` | 180 days, never past the document's expiry |
| `face_estimate` (on-device estimate plus liveness) | Phone, **only if** a model meets the bar in 4c.6 (none does in v1) | `low` | 30 days |
| `mdoc_wallet` (phone wallet ID through the browser's Digital Credentials API) | Website widget | `substantial` | No card; the server issues the ticket directly |
| Device link | Windows (from the phone) | Same as the phone's card | Up to the phone card's |
| `test_dev` | Dev servers only | `test` | 30 days |

- **Removed from v1** (they come out of the UI): the Windows USB NFC reader (there's no vetted
  JavaScript eMRTD library, so Windows users add passports through the phone link), Windows face
  estimate (there's no hardware attestation path on Windows in v1), and `passport_zk`, which
  `passport_attested` replaces. The server returns 501 `METHOD_NOT_READY` for `passport_zk`.

### 4c.1 Artifacts (Anon Aadhaar circuit files)

- `npm run fetch-artifacts --prefix server` downloads the official Anon Aadhaar circuit files
  (witness `.wasm`, `.zkey`, `vkey.json`) from the project's official release location, checks
  each one against a SHA-256 pinned in `server/assets/artifacts/manifest.json`, and saves them in
  `server/assets/artifacts/` (gitignored except the manifest).
- `GET /v1/artifacts/manifest` returns `[{name, sha256, bytes, url}]`, and `GET /v1/artifacts/:name`
  serves the file, open to any origin. Apps download on first use, **check the SHA-256**, and cache it.
- The server verifies Aadhaar proofs with the pinned `vkey.json`. The real UIDAI public key is
  accepted in production; the test key only in dev mode.

### 4c.2 Nullifier service (for `passport_attested`)

The server must stop one passport making unlimited cards, without ever seeing the document number.
It uses a **deterministic RSA blind signature as an oblivious PRF**:
- A long-lived key `v18-nullifier-1`, using `RSABSSA-SHA384-PSSZERO-Deterministic` (RFC 9474).
  It is published at `GET /v1/keys/nullifier` and is never rotated without a migration plan.
- The app's message is UTF-8 `v18-doc-v1|<ICAO 3-letter issuing state>|<document number, upper case, '<' removed>`.
  The app blinds it, then calls `POST /v1/nullifier/blind-sign` with
  `{challenge, blindedMessage, devicePublicKey, deviceSignature, keyAttestation}`, where the signing
  string is `v18-nullifier` `\n` challenge `\n` deviceKeyThumbprint `\n` blindedMessage. It then
  finalizes. **nullifier = base64url(SHA-256(signature))**.
- Production requires a valid Android key attestation (4c.3). Rate limits: 5 per device key per day
  and 20 per IP per hour.
- The Dart RFC 9474 client adds the `PSSZERO-Deterministic` variant and passes its RFC Appendix A vectors.

### 4c.3 Android key attestation (`passport_attested`, `face_estimate`, nullifier)

- The app creates its Keystore key with `setAttestationChallenge(UTF-8 bytes of the server challenge)`
  and sends `keyAttestation`: an array of base64 DER certificates, leaf first.
- The server checks every one of these: the chain ends at a **Google hardware attestation root**
  (bundle the currently published roots); the leaf's public key equals `devicePublicKey`; the
  attestation challenge equals the challenge; the security level is TrustedEnvironment or StrongBox;
  `attestationApplicationId` has package `com.v18.app` and a signing-certificate SHA-256 listed in
  `V18_ANDROID_CERT_DIGESTS`; production also needs verified boot `Verified` and a locked device;
  and the certificate is not on Google's attestation revocation list (fetched and cached).
- Dev mode may also accept emulator or software attestation, and says so in the response.
- Play Integrity is optional (`V18_PLAY_INTEGRITY`, off by default) because it needs a Play Console project.

### 4c.4 `passport_attested` proof

`proof = {over18: true, docExpiry: "YYYY-MM-DD", issuingState: "IND", passiveAuth: "ok",
chipAuth: "chip_auth" | "active_auth" | "none", nullifier, nullifierKeyId: "v18-nullifier-1"}`,
plus a top-level `keyAttestation`. The phone does all the checks on the chip itself: MRZ, BAC or
PACE, DG1 and SOD, passive authentication against a bundled **CSCA master list**, and chip or
active authentication where the chip has it. It sends **no** name, date of birth or document
number. The server issues the card if the attestation is valid, and the cap applies per nullifier.

### 4c.5 `mdoc_wallet` (browser widget)

- `POST /v1/wallet/request {sessionId}` returns the Digital Credentials API request. It asks
  **only** for `age_over_18` from an mDL or PID, using whichever protocol current Chrome supports
  (OpenID4VP or ISO 18013-7). It is bound to the pairing session and carries a nonce.
- `POST /v1/wallet/verify {sessionId, response}`: the server verifies issuer auth, device auth and
  the nonce against the IACA trust list in `server/assets/iaca/` (a test IACA in dev only), and
  checks `age_over_18 == true`. It then puts a normal ticket (format 3.6, signed with the current
  age-18 key) on the pairing session, and the widget gets it through the normal poll. Use a vetted
  mdoc library such as `@auth0/mdl`.

### 4c.6 Face estimate (not in v1)

The model must run fully on the device, with a licence that allows commercial use and training
data whose licence allows it too. Liveness checking is required. It must have a measured error on
a held-out set, broken down by age band. A "challenge age" (default 25) must be met, so that at
most 5% of 13 to 17 year-olds pass on the test set. If no model meets all of this, `face_estimate`
is removed from v1, and in v1 it is: the best licence-clean model let 5.17% of 13 to 17 year-olds
pass. A future model would ship with a manifest `{"shippable": true, ...}`, and the mobile app
bundles and shows face only then.
`proof = {estimator: "<model id>", challengeAge: 25, passed: true, liveness: "passed"}`, plus
`keyAttestation`. The server accepts only model IDs in `V18_FACE_MODELS`.

### 4c.7 Production readiness

- **Server:** PostgreSQL adapters for **all** state (cards, nullifiers, rate limits, challenges,
  pairing sessions, links) so several instances can run. Tests run against a real PostgreSQL via
  `embedded-postgres` (npm). A production key store: encrypted at rest with a key from `V18_KEK`,
  plus a KMS adapter interface. Also: security headers, body size limits, `/metrics`, a Dockerfile,
  `docker-compose.yml` (server + PostgreSQL) and `docs/server/DEPLOY.md`.
- **Production server URL:** configurable everywhere, with `https://api.v18.example` as the
  placeholder until a real domain is set up.
- **Android:** a release build signed with an upload key kept **outside** the project
  (never inside the repository), R8 on, and the server URL set at build time.
- **Windows:** a release build, an installer that is actually tested (install, `v18://`
  registration, uninstall), and code signing documented. A certificate must be bought.

## 4d. Many IDs in every country (v1.3)

Every country should offer several ways to prove age, not only a passport or one card.
This section adds to 4c, and overrides it where they differ.

### 4d.1 Rule

For each country, V18 offers **every ID that can be checked without the person handing their
identity to V18**, in this order of privacy:
1. **Zero-knowledge proof:** Aadhaar.
2. **Chip or signed data checked on a hardware-attested phone:** passports, chip ID cards,
   residence permits, PhilSys QR, My Number Card.
3. **Wallet IDs that reveal only `age_over_18`:** EU digital identity wallets, mobile driving
   licences, Apple and Google Wallet IDs.
4. **Government and bank logins** (connectors): V18 sees the birth date for a moment, decides
   "18+", and keeps nothing.
5. **Face estimate**, if it ships (4c.6).

The "everything visible works" rule from 4c still applies. A method appears in an app only when
this deployment really supports it.

### 4d.2 Country catalog: the single list of what each country supports

- `catalog/countries.json` follows this schema:

```json
{ "version": 1,
  "countries": [
    { "code": "IN", "name": "India", "region": "asia",
      "methods": [
        { "method": "anon_aadhaar", "label": "Aadhaar QR",
          "documents": ["Aadhaar letter", "e-Aadhaar PDF", "mAadhaar app QR"],
          "needs": ["camera"], "privacy": "zero_knowledge",
          "platforms": ["android", "windows"] },
        { "method": "emrtd_attested", "label": "Passport (chip)",
          "documents": ["Indian e-passport"], "docTypes": ["P"],
          "needs": ["nfc"], "privacy": "on_device", "platforms": ["android"] } ] } ] }
```

- `privacy` is one of `zero_knowledge`, `on_device`, `wallet`, `login` or `estimate`.
  `needs` items come from `camera`, `nfc`, `wallet` and `password`.
- **Coverage:** every EU/EEA country plus the UK and Switzerland, and at least these Asian
  countries: IN, PH, JP, SG, KR, VN, ID, MY, TH, PK, BD, LK, NP, AE, SA, QA, KW, CN, HK, TW, IL and
  TR. Every country with chip passports gets `emrtd_attested` for passports. Every other method
  needs a cited source that it works for that country.
- `GET /v1/catalog` (server, open to any origin) returns the catalog **filtered to what this
  deployment has enabled**: connectors only when their credentials are configured, face only when
  shipped. It accepts `?country=XX` and `?platform=android|windows`.
- **Apps build the country and method screens from `/v1/catalog`.** No hard-coded country lists.

### 4d.3 Methods added or widened

| Method | What | Platforms |
|--------|------|-----------|
| `emrtd_attested` | **Replaces** `passport_attested` (the server keeps that name as an alias). Any ICAO 9303 chip document: passports from every country, **chip ID cards** (every EU/EEA country since 2021, Switzerland, Vietnam CCCD, and others the catalog lists with a source) and **residence permits** (EU, UK BRP). Adds `docType` (the first MRZ letter: `P`, `I`, `A`, `C`) to the proof. ID cards need the CAN (6 digits printed on the card) for PACE. Same checks and nullifier as 4c.2 to 4c.4 | Android |
| `philsys_qr_attested` | Philippines PhilSys (PhilID or ePhilID) signed QR. The phone checks the PSA signature against PSA's published key; nullifier message `v18-philsys-v1\|<PCN>` through the 4c.2 service. **Only if** the QR's signature format and PSA key are publicly documented; otherwise the session reports that and the method is left out | Android |
| `mynumber_attested` | Japan My Number Card. The phone reads the JPKI signature certificate over NFC (the user types the card's signature password; warn that 5 wrong tries lock it), checks the chain to the J-LIS root, and reads the birth date on the phone only. Nullifier message `v18-jpki-v1\|<SHA-256 of the certificate's subject and serial>` | Android |
| `mdoc_app` | The V18 phone app asks **another wallet on the same phone** (Android Credential Manager digital credentials) for only `age_over_18` from an mDL or PID: EU wallets, Google Wallet IDs, national mDL apps. The server verifies with the 4c.5 verifier and issues a card (`substantial`, validity no longer than the credential's) | Android |
| `mdoc_wallet` | Unchanged (4c.5), in the browser widget | Web |
| `connector:<id>` | Government or bank login through OpenID Connect or OAuth with PKCE, see 4d.4 | Android, Windows |

### 4d.4 Login connectors

- **Connectors in v1.3:** `singpass` (SG, MyInfo), `digilocker` (IN), `uaepass` (AE), `bankid_se`,
  `bankid_no`, `mitid` (DK), `itsme` (BE, NL, LU), `franceconnect` (FR), `spid` and `cie` (IT),
  `digid` (NL, usually through a broker), and `freja` (SE). Build each from the provider's public
  docs.
- **Flow:**
  1. The app calls `POST /v1/connect/:id/start` with
     `{challenge, devicePublicKey, deviceSignature, keyAttestation?}` and gets an `authUrl`
     (PKCE, `state` bound to challenge and thumbprint).
  2. The app opens `authUrl` in a Custom Tab (Android) or the system browser (Windows).
  3. The provider redirects to `GET /v1/connect/:id/callback`. The server reads only the birth
     date or age claim, decides over 18, and computes
     nullifier = HMAC-SHA256(`V18_NULLIFIER_SECRET`, id + "|" + provider subject ID).
     It **discards everything else at once**, never logs claims, and issues the card bound to the
     device key.
  4. The server redirects to `v18://connect?status=ok&cardId=...` (the app polls
     `GET /v1/connect/session/:state` as a fallback).
- **Assurance:** `high` for eIDAS-high or national schemes, otherwise `substantial`. Card validity
  is 180 days.
- **Hidden unless configured:** a connector is enabled only when its credentials are set
  (`V18_CONNECTOR_<ID>_CLIENT_ID` and so on). Production use needs registration with each
  provider. Each connector is tested against a
  **local mock provider** built with the `oidc-provider` npm package that returns realistic claims
  in that provider's own format, plus its public sandbox only if that needs no sign-up.
- **Code layout:** the `connectors/` package (TypeScript) exports
  `Connector { id, countries, assurance, buildAuthUrl(), handleCallback() -> {over18, subject} }`
  and a registry. The server wires the endpoints and imports `connectors/` through a `file:` dependency.

### 4d.4b Decisions

- **`mynumber_attested` is not in v1.** The public J-LIS documentation gives no OID for the
  birth-date field. J-LIS gives signature-certificate revocation lists only to certified
  verifiers, so a lost card can't be detected. And Japan's Digital Agency requires a certified
  platform operator. The server turns it off by default, and the catalog removes it from JP.
  Japanese users have passports today, plus My Number in Apple Wallet through `mdoc_wallet` and
  `mdoc_app` where it is available.
- **`face_estimate` is not in v1.** The best licence-clean model let 5.17% of 13 to 17 year-olds
  pass on the test set, over the 5% bar.
- **UAE PASS and DigiD** need the provider's own onboarding. They stay hidden until credentials exist.
