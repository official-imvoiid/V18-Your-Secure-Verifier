# V18 server walkthrough (protocol v1.3)

This explains what the V18 server in `server/` does now, how to run and test it, and what is
still missing. Every endpoint is in [API.md](API.md). Running it for real users is in
[DEPLOY.md](DEPLOY.md).

## 1. The idea in one minute

Think of a cinema membership card (see the root `README.md`):

1. The phone (or PC) proves "18+" once, from an ID, **on the device**. The server never sees the
   ID: it sees a zero-knowledge proof, or an attested phone's "yes", or a wallet's signed
   `age_over_18`, or a login provider's birth date for a moment.
2. The server gives the device an **age card**: a record bound to a key in the device's secure
   chip. The record holds only: card ID, device public key, method, dates, a nullifier hash and
   the status.
3. For each website, the app makes a **ticket**, has the server **blind-sign** it (RFC 9474), and
   gives it to the website. The server never sees the ticket, so it cannot know which sites the
   person visits. The website checks the ticket offline with the public keys.

A **nullifier** is an anonymous code that is the same every time one ID is used. The server keeps
only a hash of it, and allows at most 3 active cards per ID.

## 2. What the complete product added

| Part | What it does now |
|------|------------------|
| **Anon Aadhaar files** (4c.1) | `npm run fetch-artifacts` downloads the official v2 circuit files and checks each SHA-256 against the pins in `assets/artifacts/manifest.json`. The server serves them (`/v1/artifacts/*`, with resume). |
| **Real Aadhaar checking** | Proofs are checked with snarkjs and the **pinned** `vkey.json`. The real UIDAI key is bundled (`assets/uidai/production/`); the TEST key works only in dev mode. The tests use **real proofs** made with the official files. No mock is left. |
| **Nullifier service** (4c.2) | `v18-nullifier-1`, a deterministic blind signature (RSABSSA-SHA384-PSSZERO-Deterministic). The phone blinds its document number; the server signs without seeing it; the phone turns the signature into a stable nullifier. Rate limited per device key (5/day) and per IP (20/hour). |
| **Android key attestation** (4c.3) | A full check of the phone's Keystore certificate chain to Google's roots (both current roots bundled), the revocation list (fetched and cached), the challenge, hardware level, package `com.v18.app` and signing certificate, verified boot and a locked bootloader. |
| **Chip documents** (4c.4, 4d.3) | `emrtd_attested` (passports, chip ID cards, residence permits; `passport_attested` still works), `philsys_qr_attested`. `mynumber_attested` is built but OFF by default (not in v1, PROTOCOL.md 4d.4b; `V18_ENABLE_MYNUMBER=1` turns it on). |
| **Face estimate** (4c.6) | Built, but OFF unless `V18_FACE_MODELS` names a model. No face model meets the bar in v1, so it stays off and out of the catalog. |
| **Phone wallets** (4c.5, 4d.3) | `mdoc_wallet` in the website widget (ticket straight onto the QR session) and `mdoc_app` in the phone app (a card). Checked with `@auth0/mdl` against an IACA trust list. |
| **Country catalog** (4d.2) | `GET /v1/catalog` serves `catalog/countries.json`, checked against the schema and filtered to what this server really supports. |
| **Login connectors** (4d.4) | `/v1/connect/*` with the `@v18/connectors` package, plus the routes providers fetch (`/jwks`, SAML `/metadata`), the SPID/CIE identity provider list and the BankID PC QR code. The server keeps only an HMAC nullifier, never claims. Unconfigured connectors are hidden. |
| **Production** (4c.7) | ALL state in PostgreSQL (or SQLite/memory in dev), keys sealed with `V18_KEK` (or a KMS adapter), security headers, body limits, `/metrics`, `Dockerfile`, `docker-compose.yml`, `DEPLOY.md`. |

## 3. How to run it

From `server/`:

```bash
npm install
```

```bash
npm run fetch-artifacts
```

```bash
npm run build
```

Dev server on port 8080, TEST MODE on:

```bash
npm run dev
```

The shared dev server is started without file watching
(`V18_DEV_MODE=1 npx tsx src/index.ts`), so a half-saved file cannot take it down.

Useful test tools (TEST ONLY):

```bash
npm run dev-client
```

```bash
npm run dev-wallet -- --session <pairing session id>
```

| Script | What it does |
|--------|--------------|
| `npm run dev` | Dev server, TEST MODE, reloads on change |
| `npm start` | Built server, TEST MODE |
| `npm run start:prod` | Built server, production mode (needs `V18_KEK`, see DEPLOY.md) |
| `npm run build` | Clean, compile, type-check `scripts/` |
| `npm test` | All tests on SQLite |
| `npm run test:pg` | All tests on a real PostgreSQL 17 (embedded-postgres) |
| `npm run test:all` | Both |
| `npm run fetch-artifacts` | Download and check the Anon Aadhaar files (`-- --chunks`, `-- --check`) |
| `npm run make-aadhaar-fixtures` | Make the real Aadhaar test proofs (about a minute) |
| `npm run dev-client` | Phase 1 happy path (TEST card and ticket) |
| `npm run dev-wallet` | Plays a phone wallet for a QR session |

## 4. Test results

`npm run build` passes with no errors. Real output counts:

**SQLite** (`npm test`):

```
ℹ tests 201
ℹ suites 43
ℹ pass 200
ℹ fail 0
ℹ skipped 1
```

The one skip is the "two copies issue at the same time" race test: one SQLite file cannot take
two writers in one process, and SQLite deployments run one server copy. It runs on PostgreSQL.

**PostgreSQL 17.11** (`npm run test:pg`, real PostgreSQL through `embedded-postgres`):

```
ℹ tests 201
ℹ suites 43
ℹ pass 201
ℹ fail 0
ℹ skipped 0
```

| File | Tests | What it checks |
|------|-------|----------------|
| `attestation.test.ts` | 23 | **Real** attestation chains from real phones (Pixel 2/3/8/8a/9/10 and Sony Xperia 10 III, from Google's `android/keyattestation` test data): chains to the bundled Google roots (old RSA root and the 2026 EC root), RKP and factory chains, StrongBox and TEE, the expired-2016-root case, revocation of leaf/intermediate/root, wrong challenge/package/signing cert/key, a tampered leaf, a software-attestation Pixel 1. Production refuses the unlocked test phones; the locked retail Sony passes everything. Generated TEST chains for the cases real ones cannot give. Revocation list fetch, cache and fail-closed. |
| `anon-aadhaar.test.ts` | 15 | **Real Groth16 proofs** (official v2 files): UIDAI cert hashes equal the library constants, a tampered `vkey.json` is refused, TEST-key card (`test` level), tampered proof and public signals fail, challenge and device-key binding, a real proof revealing gender is refused, a real under-18 proof gives `UNDER_AGE`, production refuses the TEST key, wrong seed, not configured. |
| `attested.test.ts` | 22 | Nullifier JWKS, same document → same nullifier across devices, key survives restart, attestation required in production, signing string, both rate limits, dev mode; `emrtd_attested` and the alias (document-expiry cap, 3-card cap across both names, ID cards and residence permits), bad proofs including personal fields, unlocked and software phones; PhilSys, My Number (off by default, 4d.4b: health, card issue and catalog; on with `V18_ENABLE_MYNUMBER=1`); face estimate off and on; `passport_zk` 501. |
| `wallet.test.ts` | 16 | Widget flow with TEST mDL and EU PID → a ticket that passes all 8 website checks; under 18, untrusted issuer, wrong nonce, wrong origin, tampered, expired, request used once, not encrypted, Origin header; `mdoc_app` in production and dev, 3-card cap per wallet credential, wrong app origin. |
| `connect.test.ts` | 11 | The **real** `@v18/connectors` FranceConnect connector against the `oidc-provider` mock from `connectors/`: adult gets a card, ticket works, the database holds no birth date, names or subject; 17-year-old refused. Edge cases: 3-card cap per subject, provider error, unknown/reused/expired state, BankID "pending", bad signature, unconfigured 404, production needs `V18_NULLIFIER_SECRET`. The provider-facing routes: connector JWKS (public parts only), SAML metadata with the callback as ACS, the SPID identity provider list, and the BankID PC QR code (matches BankID's HMAC rule, secret never sent to the app). |
| `storage.test.ts` | 10 | Keys sealed with `V18_KEK` (no plain key in the database), restart keeps keys, wrong KEK refused, sealed key bound to its ID, KMS envelope wrapper; two server copies on one database: same keys, shared challenges, QR session, device link, rate limits, and the concurrent nullifier cap. |
| `migrations.test.ts` | 6 | The dev-database bug: a database built up to the OLD 003 with cards in it is opened by the new server; 004 runs, every old card stays, checksums are recorded, and every method (test_dev, real anon_aadhaar, emrtd, passport alias, PhilSys, My Number, face, mdoc_app, a connector) stores a card. The checksum guard refuses an edited applied migration (line endings ignored), and the server refuses to start on such a database. |
| `catalog-artifacts.test.ts` | 8 | The real `catalog/countries.json` passes the schema; filtering by what is enabled, country and platform; connectors appear only when configured; missing and invalid catalogs; artifact manifest, SHA-256 of served files, Range 206 on the 612 MB zkey, path tricks. |
| `http.test.ts` | 15 | Phase 1 HTTP rules plus security headers, the 64 KB / 256 KB body limits and `/metrics` (route patterns only). |
| `unit`, `cards`, `keys`, `tickets`, `pairing`, `links`, `e2e` | 75 | The phase 1 tests, now on the database-backed services. |

I also ran it by hand on the shared dev server (port 8080, dev mode): `/v1/health` shows the
methods, `npm run dev-client` still prints a valid ticket, a `Range` request for the zkey gives 206,
and `npm run dev-wallet` fills a widget session (`approved`, ticket delivered) and gives
`403 UNDER_AGE` with `--under18`.

## 5. Artifact sizes and hashes (pinned)

| File | Bytes | SHA-256 |
|------|-------|---------|
| `vkey.json` | 4,388 | `40f2ea24b56ffe2b6e6e3578053cbda15e773cb560697bac883a404077fcf177` |
| `aadhaar-verifier.wasm` | 10,469,686 | `4894923663fafda95beb70abca4112ea97a62058c9a46419a274f04236f10d4f` |
| `circuit_final.zkey` | 612,082,146 | `0d443ea85279b0370b53202f5e768ca9098cfcb5bb14f8ca8323d2266822c492` |
| `circuit_final_0.gz` to `_9.gz` (optional) | 295,909,375 in total | in `assets/artifacts/manifest.json` |

Proving one Aadhaar proof with these files on this PC took 18 to 19 seconds (Node, snarkjs).

## 6. What is not done, not tested, or external

- **Docker:** `Dockerfile` and `docker-compose.yml` were written but **never built or run**
  (Docker is not installed).
- **Real wallets in the wild:** the wallet code is tested only with TEST mdocs made with
  `@auth0/mdl`. No real Google Wallet, Apple Wallet or EU wallet was tried. Only
  `openid4vp-v1-unsigned` is offered (current Chrome); Safari, which supports only
  `org-iso-mdoc`, will not see the wallet option. No production IACA is bundled yet
  (`assets/iaca/` is empty apart from the dev TEST folder), so in production the wallet methods
  stay off until the operator adds issuers.
- **Real login providers:** connectors are tested against local mocks only. Each provider needs
  the user's own registration (`V18_CONNECTOR_*`), which the sessions must not do.
- **Play Integrity:** not built (it needs a Play Console project). Setting `V18_PLAY_INTEGRITY`
  stops the server with a clear message. Key attestation is always checked.
- **Real Aadhaar QR:** only TEST-key proofs were made (test data only, as the rules say). A real
  UIDAI-signed QR has not been tried; the UIDAI key hash is checked against the library constant.
- **KMS:** the `KmsClient` interface is tested with a TEST stand-in, not a real cloud KMS.
- **Face estimate:** off, because no model is shippable.
- `node:sqlite` prints an "experimental" warning on Node 22. `npm audit` still lists issues in
  packages pulled in by `@anon-aadhaar/core` (react, snarkjs and others); nothing was changed.

## 7. Design notes

Places where PROTOCOL.md was unclear or could not be followed exactly, and what the server does.

**From phase 1 (still true):**

1. **Anon Aadhaar signal:** `signal = "0x" + hex(SHA-256(UTF-8(challenge + "|" + thumbprint)))`,
   then `signalHash = hash(signal)` (now 4b item 1).
2. **Nullifier seed** is in `GET /v1/health` as `aadhaarNullifierSeed` (4b item 2).
3. **JWKS `alg`:** import only `{kty, n, e}` (4b item 3). The same holds for `/v1/keys/nullifier`.
4. **`assuranceLevel`:** a proof made with the Anon Aadhaar TEST key gives `test`, not
   `substantial`, so a test card never looks real. Face estimate gives `low`.
5. Every "no valid card or signature" case on tickets and link approval is `401 CARD_REQUIRED`
   with a `reason`. Each device key may hold one active card (`409 DEVICE_KEY_IN_USE`).
6. Root `package.json` `start:server` runs production mode, which now also needs `V18_KEK`.

**Complete product (4c):**

7. **Artifact pins (4c.1):** the Anon Aadhaar project publishes no SHA-256 values, so the pins
   were made when downloading from the official bucket, after checking each
   file's S3 ETag (MD5) and that `vkey.json` is exactly the key inside `circuit_final.zkey`. Real
   proofs made with the files verify. The manifest answer is the protocol's array
   `[{name, sha256, bytes, url}]` plus `role`, `optional`, `available` and `sourceUrl`. The 10
   official gzip zkey chunks are offered as optional files.
8. **UIDAI key (4c.1):** uidai.gov.in refused connections from the build machine, so the
   certificate comes from the official Anon Aadhaar repository. Its Poseidon hash equals the
   `productionPublicKeyHash` constant in `@anon-aadhaar/core`. The certificate's own dates ended
   in 2024; like Anon Aadhaar, the server checks the key, not the dates. A new UIDAI key can be
   added by dropping its certificate into `assets/uidai/production/`.
9. **Attestation dates (4c.3):** a strict date check would refuse genuine phones, so the server
   follows Google's own verifier: the trusted root's dates and the leaf's dates are not checked,
   and expired factory-provisioned intermediates are allowed (Pixel 2 and Sony chains from 2026
   still use batch certificates that ran out on 2026-05-24). Remotely provisioned chains must be
   in date.
10. **Dev-mode attestation (4c.3):** besides emulator and software chains, dev mode also accepts a
    request with no `keyAttestation` at all, so test clients without a phone work. The response
    always lists what was let through (`devModeExceptions`).
11. **One attested key per request (4c.2, 4c.3):** an attestation challenge is fixed when the key
    is made, and each request uses up its own challenge, so the phone uses one short-lived key for
    the nullifier request and the card key for card issue (as the mobile app does it). This makes
    the "5 per device key per day" limit weak (a phone can make new keys); the per-IP limit
    (20/hour) is the real brake. A stronger limit would need a stable device identity, which
    attestation deliberately does not give.
12. **What the server can check for chip documents (4c.4, 4d.3):** only the attestation (the
    request comes from the genuine V18 app on a locked, verified phone) and the shape and dates of
    the proof. It cannot re-check the chip, PhilSys QR or JPKI chain, because the phone sends
    nothing identifying. To keep it that way, the proof may hold only the listed fields.
13. **`passport_attested` alias (4d.3):** stored as `emrtd_attested` (so both names share one
    nullifier cap), echoed back as sent; with the alias, a missing `docType` means `P`.
14. **Face estimate nullifier (4c.6):** there is no ID behind a face estimate, so the device key
    is the nullifier (one card per key).
15. **Wallet protocol (4c.5):** the server offers OpenID4VP 1.0 over the DC API, unsigned, with an
    encrypted answer (`dc_api.jwt`). It does not also offer ISO 18013-7 Annex C (`org-iso-mdoc`),
    so Safari users do not get the wallet option yet.
16. **Wallet test IACA (4c.5):** a dev server makes a TEST IACA and document signer in
    `assets/iaca/test/` (gitignored, never in the Docker image) and also trusts PEM files listed in
    `V18_DEV_IACA_PEMS`. A production server never reads either.

**4d:**

17. **`mdoc_app` (4d.3):** the protocol gives no request endpoint, so the server adds
    `POST /v1/wallet/app-request {challenge}`; its nonce IS the server challenge, which the card
    issue then uses up. A wallet shares no ID number, so the hash of the credential's own holder
    key (from the signed MSO) is the nullifier: one wallet ID gives at most 3 cards. The expected
    origin is `android:apk-key-hash:<signing cert digest>` from `V18_ANDROID_CERT_DIGESTS`.
18. **Connector start signature (4d.4):** the protocol names none, so `start` uses the card-issue
    proof of possession (`v18-card-issue\n<challenge>\n<thumbprint>`), like device link start. The
    Windows session already signs this.
19. **Connector callback (4d.4):** it always redirects to `v18://connect?...`, also on errors
    (`status=error&code=...`, `status=under_age`, `status=pending` for BankID). The session poll
    returns the card once. SAML providers (SPID, CIE) post the callback, so `POST` works too.
20. **Catalog filtering (4d.2):** methods this server does not know or has not enabled are left
    out, and a country left with no method is left out. `platform=web` is accepted too, because
    the catalog marks `mdoc_wallet` as a web method.
21. **Several copies (4c.7):** PostgreSQL only. SQLite is for one copy. The per-IP limits use a
    salt kept in the database, so all copies count the same IP the same way.
22. **Body limit:** 64 KB as before, but 256 KB on `/v1/card/issue`, `/v1/nullifier/*`,
    `/v1/wallet/*` and `/v1/connect/*` (attestation chains and wallet answers are bigger).
23. **Card method names are checked by the server, not by the database (migration 004).**
    A bug, found during end-to-end testing on 2026-11-24: on 2026-11-19 the dev server had applied an
    early version of migration 003, whose `cards` table allowed only five methods. 003 was edited
    later, but a database never runs an applied migration again, so on the dev database
    `emrtd_attested`, `mdoc_app` and connector cards failed with `500 INTERNAL`. The tests always
    start from an empty database, so they did not see it. The fix:
    - 003 is back to exactly the text that was applied, and the NEW migration
      `004_cards_any_method` (SQLite and PostgreSQL) drops the method list, keeping every row.
      `src/cards/store.ts` refuses any method name the server does not know.
    - **Guard:** every applied migration's SHA-256 is now stored in `schema_migrations`. The
      server refuses to start if an applied file has changed (Windows line endings are ignored),
      with a message saying to add a new migration instead. Databases from before the guard get
      their checksums filled in on first start.
    - `migrations.test.ts` builds a database the old way (up to the old 003, with cards), opens
      it with the new server, and issues every method, on SQLite and PostgreSQL.
    - The dev database was upgraded in place; 0 cards were lost. A copy from just before is in
      `server/data/backups/`.
24. **My Number Card is off (4d.4b).** `mynumber_attested` answers `501 METHOD_DISABLED`, shows as
    `disabled` in health and is never in the catalog, unless `V18_ENABLE_MYNUMBER=1`. The code and
    its tests stay. `philsys_qr_attested` is still on in the server; the mobile app does not build
    it (PSA gives its key only to relying parties), and the catalog does not list it.

## 8. Files

```
server/
  package.json        scripts in section 3; deps: express, helmet, pg, prom-client, @cloudflare/blindrsa-ts,
                      @anon-aadhaar/core, snarkjs, @auth0/mdl, @peculiar/x509 + asn1-android, jose, @v18/connectors (file:)
  Dockerfile, docker-compose.yml, .dockerignore   (NOT built or run)
  migrations/         001-003, SQLite (*_sqlite.sql) and PostgreSQL
  assets/
    artifacts/        manifest.json (pins); the circuit files are downloaded here (gitignored)
    uidai/            UIDAI production key, Anon Aadhaar TEST key (dev only), README
    android/          Google attestation roots, revocation list snapshot
    iaca/             wallet issuer trust list (README); test/ is made by dev servers
  test-fixtures/      real attestation chains (Google, Apache-2.0), real Aadhaar TEST proofs, UIDAI sample QR
  scripts/            fetch-artifacts, make-aadhaar-fixtures, test-pg, dev-client, dev-wallet
  src/
    app.ts            builds everything (createV18)
    config.ts         environment variables
    db/               sql.ts (SQLite + PostgreSQL), state.ts (challenges, rate limits, documents)
    keys/             keystore.ts (memory, file, encrypted db), wrap.ts (KEK, KMS), ticket-keys.ts
    nullifier/        store.ts (hashes), service.ts (v18-nullifier-1 OPRF)
    attestation/      android.ts (verifier, revocation list), gate.ts (dev/prod policy), test-chain.ts (TEST)
    issuers/          test-dev, anon-aadhaar (pinned vkey, UIDAI keys), attested (emrtd, PhilSys, My Number, face)
    wallet/           mdoc.ts (OpenID4VP + @auth0/mdl), service.ts, test-wallet.ts (TEST)
    connect/          service.ts (4d.4 endpoints)
    catalog/          service.ts (4d.2)
    artifacts/        manifest.ts, service.ts (4c.1)
    cards/, tickets/, pairing/, links/, device/, http/ (CORS, errors, metrics), routes/
    tests/            201 tests
```
