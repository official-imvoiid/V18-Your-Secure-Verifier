# V18 server API (protocol v1, protocol v1.3)

This is every endpoint of the V18 server in `server/`, with its request, its answer and every
error it can give. It follows `PROTOCOL.md` section 3 and the decisions in 4b, 4c (complete product) and 4d (many IDs per country). Where this file adds something the protocol
does not say, it is marked **(V18 server choice)**.

- Base URL in dev: `http://localhost:8080/v1`. Everything lives under `/v1`.
- Bodies are JSON (`Content-Type: application/json`), at most 64 KB, except `/v1/card/issue`,
  `/v1/nullifier/*`, `/v1/wallet/*` and `/v1/connect/*` (256 KB, for proofs, attestation chains and
  wallet answers). Connector callbacks may also be form posts (SAML, up to 512 KB).
- Binary values are **base64url without padding** (`A-Z a-z 0-9 - _`, no `=`).
- Times: `expiresAt`/`validUntil` are ISO 8601 UTC strings. JWKS `nbf`/`exp` and ticket
  `iat`/`expiresAt` are epoch seconds.
- Errors always look like `{"error": "<plain text>", "code": "<CODE>"}`. Some add a field such
  as `reason`, `status` or `retryAfterSeconds`.
- Answers carry `Cache-Control: no-store`, except the public data: `GET /v1/keys`, `/v1/keys/nullifier`,
  `/v1/artifacts/*` and `/v1/catalog`.
- Security headers on every answer (helmet): `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: cross-origin`,
  and HSTS in production.

## Contents

1. [Errors that any endpoint can give](#1-errors-that-any-endpoint-can-give)
2. [Health and keys](#2-health-and-keys): `GET /health`, `GET /keys`, `GET /keys/pem`
3. [Challenges](#3-challenges): `POST /challenge`
4. [Device keys and signatures](#4-device-keys-and-signatures)
5. [Age cards](#5-age-cards): `POST /card/issue`, `GET /card/:cardId/status`, `DELETE /card/:cardId`
6. [Tickets](#6-tickets): `POST /ticket/blind-sign`
7. [QR hand-off (pairing)](#7-qr-hand-off-pairing): `POST /pairing/session`, `GET /pairing/:id`, `connect`, `submit`, `cancel`
8. [Device link](#8-device-link): `POST /card/link/start`, `POST /card/link/:linkId/approve`, `GET /card/link/:linkId`
9. [CORS](#9-cors)
10. [Settings (environment variables)](#10-settings-environment-variables)
11. [Anon Aadhaar artifacts](#11-anon-aadhaar-artifacts-4c1): `GET /artifacts/manifest`, `GET /artifacts/:name`
12. [Nullifier service](#12-nullifier-service-4c2): `GET /keys/nullifier`, `POST /nullifier/blind-sign`
13. [Android key attestation](#13-android-key-attestation-4c3)
14. [Phone wallets](#14-phone-wallets-4c5-4d3): `POST /wallet/request`, `POST /wallet/verify`, `POST /wallet/app-request`
15. [Country catalog](#15-country-catalog-4d2): `GET /catalog`
16. [Login connectors](#16-login-connectors-4d4): `POST /connect/:id/start`, `GET|POST /connect/:id/callback`, `GET /connect/session/:state`
17. [Metrics](#17-metrics): `GET /metrics`
18. [Test tools](#18-test-tools-test-only)

---

## 1. Errors that any endpoint can give

| Status | `code` | When |
|--------|--------|------|
| 400 | `BAD_JSON` | The body is not valid JSON. The server never repeats the body back. |
| 400 | `BAD_REQUEST` | A field is missing or has the wrong shape. `error` names the field. |
| 404 | `NOT_FOUND` | No such path (remember the `/v1` prefix). |
| 413 | `BODY_TOO_LARGE` | The body is over 64 KB (256 KB on the proof, wallet and connector endpoints). |
| 429 | `RATE_LIMITED` | A rate limit. `Retry-After` and `retryAfterSeconds` say how long to wait. |
| 415 | `BAD_ENCODING` | The body is not UTF-8. |
| 500 | `INTERNAL` | A server bug. The log shows the route and stack, never the body. |
| 503 | `BUSY` | Too many open challenges. Try again soon. |

---

## 2. Health and keys

### `GET /v1/health`

```json
{
  "status": "ok",
  "service": "v18-server",
  "version": "0.3.0",
  "protocolVersion": 1,
  "contractVersion": "1.3",
  "devMode": true,
  "time": "2026-11-23T12:00:00.000Z",
  "methods": {
    "test_dev": "ready", "anon_aadhaar": "ready",
    "emrtd_attested": "ready", "passport_attested": "ready",
    "philsys_qr_attested": "ready", "mynumber_attested": "disabled",
    "face_estimate": "disabled", "mdoc_wallet": "ready", "mdoc_app": "ready",
    "passport_zk": "not_ready",
    "connector:singpass": "ready"
  },
  "connectors": ["singpass"],
  "ageThresholds": [18],
  "aadhaarNullifierSeed": "180018001800180018",
  "nullifierKeyId": "v18-nullifier-1",
  "artifacts": "ready",
  "catalog": "ready",
  "storage": "sqlite"
}
```

- `devMode: true` means the server accepts TEST identities. **Every app must show a TEST MODE
  banner** when it sees this (protocol 3.1).
- `methods.*` is `ready`, `disabled` (test_dev in production, face_estimate without `V18_FACE_MODELS`,
  mynumber_attested unless `V18_ENABLE_MYNUMBER=1`),
  `not_configured` (anon_aadhaar without the pinned `vkey.json` or seed; attested methods in production
  without `V18_ANDROID_CERT_DIGESTS`; wallets without a trusted IACA) or `not_ready` (passport_zk).
  A `connector:<id>` key appears only for login connectors whose credentials are set.
  **Apps and the widget show a method only when it is `ready`.**
- `artifacts`: `ready` when the three required Anon Aadhaar files are on the server and match their pins.
- `catalog`: `ready`, `missing` or `invalid` (section 15). `storage`: `sqlite` or `postgres`.
- `aadhaarNullifierSeed` **(V18 server choice)**: the phone needs this number as an input to the
  Anon Aadhaar proof, and the protocol has no other place to get it. It is not secret. `null` if
  not set.

### `GET /v1/keys`

The ticket signing keys as a JWKS (protocol 3.2). Websites cache this for 5 minutes
(`Cache-Control: public, max-age=300`).

```json
{ "keys": [
  { "kty": "RSA", "kid": "v18-age18-20261109", "use": "sig",
    "alg": "RSABSSA-SHA384-PSS-Randomized",
    "n": "<base64url modulus>", "e": "AQAB",
    "v18_min_age": 18, "nbf": 1794182400, "exp": 1794787200 },
  { "kty": "RSA", "kid": "v18-age18-20261116", "...": "the NEXT key" }
] }
```

- One key per age threshold (`V18_AGE_THRESHOLDS`, default `18`) and period
  (`V18_KEY_ROTATION_DAYS`, default 7). RSA-2048 by default.
- The list holds the **previous** key (once there is one), the **current** key and the **next**
  key, for each threshold.
- `kid` is `v18-age<threshold>-<YYYYMMDD>`, where the date is the key's start (`nbf`) in UTC.
  The first key starts at midnight UTC on the day the server first runs. Each later key starts
  exactly when the one before it ends.
- Only the current key signs (`nbf <= now < exp`). Websites accept a ticket while
  `now <= exp + 600`.
- Keys survive restarts (dev: `server/data/keys/`).

> **Important for app and website code (protocol issue):** WebCrypto (`crypto.subtle.importKey`)
> **throws `DataError`** on these JWKs, because their `alg` is not a WebCrypto name. Import only
> `{kty, n, e}`:
> ```js
> crypto.subtle.importKey('jwk', { kty: 'RSA', n: k.n, e: k.e },
>   { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify'])
> ```

### `GET /v1/keys/pem` and `GET /v1/keys/pem?kid=<kid>`

The current key for age 18 (or the key named by `kid`) as an SPKI PEM text file
(`Content-Type: text/plain`).

| Status | `code` | When |
|--------|--------|------|
| 404 | `KEY_NOT_FOUND` | That `kid` is not in the JWKS. |

---

## 3. Challenges

### `POST /v1/challenge`

No body. Answer:

```json
{ "challenge": "<64 lowercase hex characters>", "expiresAt": "2026-11-09T12:05:00.000Z" }
```

A challenge works **once** and lasts **5 minutes**. Card issue, card delete, ticket, link start
and link approve each use up one. A request that fails after the challenge check still uses it
up, so get a new one for every try.

Errors that use a challenge give `401 CHALLENGE_INVALID` when it is missing, unknown, used or
expired.

---

## 4. Device keys and signatures

Each age card is bound to one **device key** that lives in the device's secure hardware.

| `alg` | Public key JWK | Signature |
|-------|----------------|-----------|
| `ES256` | `{"kty":"EC","crv":"P-256","x":"…","y":"…","alg":"ES256"}` | ECDSA P-256 SHA-256. `sig` may be DER **or** 64-byte raw r‖s |
| `RS256` | `{"kty":"RSA","n":"…","e":"AQAB","alg":"RS256"}` | RSASSA-PKCS1-v1_5 SHA-256 |

- A device signature is `{"alg": "ES256" | "RS256", "sig": "<base64url>"}`.
- `deviceKeyThumbprint` is the RFC 7638 JWK thumbprint (SHA-256, base64url) of the public key.
- The server refuses a JWK that holds private parts (`d`, `p`, `q`, …), curves other than P-256,
  points not on the curve, RSA keys under 2048 or over 4096 bits, and RSA `e` other than 65537
  (`400 BAD_DEVICE_KEY`). `alg` in the JWK is optional, but if present it must match the key type.
- **(V18 server choice)** One active card per device key. Make a new key for each card.

**Signing strings** (UTF-8, fields joined with `\n`, no newline at the end):

| Action | String |
|--------|--------|
| Issue card, and start a device link | `v18-card-issue\n<challenge>\n<deviceKeyThumbprint>` |
| Ticket | `v18-ticket-request\n<cardId>\n<challenge>\n<keyId>\n<blindedMessage>` |
| Approve device link | `v18-link-approve\n<cardId>\n<challenge>\n<linkId>` |
| Delete card | `v18-card-delete\n<cardId>\n<challenge>` |

`blindedMessage` in the ticket string is the exact base64url text sent in the request.

---

## 5. Age cards

### `POST /v1/card/issue`

```json
{ "method": "test_dev" | "anon_aadhaar" | "emrtd_attested" | "passport_attested" | "philsys_qr_attested"
            | "mynumber_attested" | "face_estimate" | "mdoc_app" | "passport_zk",
  "challenge": "<from POST /v1/challenge>",
  "devicePublicKey": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "alg": "ES256" },
  "deviceSignature": { "alg": "ES256", "sig": "<over v18-card-issue\\n<challenge>\\n<thumbprint>>" },
  "proof": { "...depends on method..." },
  "keyAttestation": ["<base64 DER leaf>", "...", "<root>"] }
```

`keyAttestation` is needed by the Android-attested methods (section 13) and optional for `mdoc_app`.

**Answer `201`:**

```json
{ "cardId": "card_<22 base64url chars = 16 random bytes>",
  "method": "test_dev",
  "assuranceLevel": "test",
  "minAgeCertified": 18,
  "validUntil": "2026-12-09T12:00:00.000Z",
  "attestation": { "hardwareVerified": true, "kind": "chain", "securityLevel": "StrongBox",
                   "verifiedBootState": "Verified", "deviceLocked": true, "devModeExceptions": [] } }
```

`method` is echoed as sent (`passport_attested` stays `passport_attested`; it is stored as
`emrtd_attested`). `attestation` is there only for attested methods. In dev mode,
`devModeExceptions` lists every production check that was let through (for example
`["untrusted_root","software_security_level"]` for an emulator, or `["no_attestation"]`), with a
`note` saying a production server would refuse it.

`assuranceLevel` (4b item 4, 4c, 4d.4): `test` (test_dev, or an Anon Aadhaar TEST key: never real),
`low` (face_estimate), `substantial` (Anon Aadhaar, chip documents, PhilSys, My Number, wallets,
most connectors), `high` (eIDAS-high or national login schemes).

Card length: 30 days for `test_dev` and `face_estimate`; 180 days for the others; never past the
document's own end date (`docExpiry`, `certExpiry`, the wallet credential's `validUntil`).

**Proof by method:**

- `test_dev` (**TEST ONLY**, dev mode only):
  `{"testSubjectId": "1 to 128 chars", "birthDate": "YYYY-MM-DD", "idValidUntil": "YYYY-MM-DD"}`.
  `idValidUntil` is optional **(V18 server choice)**: the card then ends no later than the end of
  that day. The server keeps neither value. `testSubjectId` only feeds the nullifier hash.
- `anon_aadhaar`: the Anon Aadhaar proof object from `@anon-aadhaar/core`
  (`{type, id, claim, proof}`), or its serialized form `{"type":"anon-aadhaar","pcd":"<json>"}`.
  The server reads only `proof.proof` (the public signals) and checks these, in this order:
  1. `pubkeyHash` is UIDAI's real key. The TEST key is accepted **only in dev mode**.
  2. `nullifierSeed` equals `V18_AADHAAR_NULLIFIER_SEED` (shown in `GET /v1/health`).
  3. `signalHash` binds this request. **(V18 rule; the protocol's plain string cannot be fed to
     Anon Aadhaar's `hash()`):**
     ```
     signal     = "0x" + hex( SHA-256( UTF-8( challenge + "|" + deviceKeyThumbprint ) ) )
     signalHash = hash(signal)        // hash() from @anon-aadhaar/core
     ```
     So the app passes `signal` (the `0x…` string) to `generateArgs`.
  4. Only "age above 18" is revealed: `ageAbove18` is `1`; `gender`, `pincode` and `state` are `0`.
  5. The Groth16 proof verifies with snarkjs and the **pinned** `vkey.json` (section 11), in the
     same public-signal order as `@anon-aadhaar/core`. This runs before step 4, so a changed
     public signal always fails as `bad_proof`.
  The UIDAI keys come from `server/assets/uidai/production/` (and `test/`, dev mode only); their
  Poseidon hashes are computed at start-up. The card's nullifier comes from `proof.proof.nullifier`.
- `emrtd_attested` (alias `passport_attested`), Android only, needs `keyAttestation`:
  `{over18: true, docExpiry: "YYYY-MM-DD", issuingState: "IND", docType: "P"|"I"|"A"|"C", passiveAuth: "ok",
  chipAuth: "chip_auth"|"active_auth"|"none", nullifier, nullifierKeyId: "v18-nullifier-1"}`.
  `docType` is the first MRZ letter; with the `passport_attested` alias it may be left out and means `P`.
  `issuingState` is the 3-letter MRZ code (`<` filler allowed, for example `D<<`). `nullifier` is
  base64url(SHA-256(signature)) from section 12, 43 characters. **No other field is allowed**
  (`PROOF_INVALID` reason `unexpected_field`), so a name or number can never slip in.
- `philsys_qr_attested`, Android only: `{over18: true, qrSignature: "ok", nullifier, nullifierKeyId}`
  (nullifier message `v18-philsys-v1|<PCN>`).
- `mynumber_attested`, Android only: **not in v1 (PROTOCOL.md 4d.4b), off by default** (`501 METHOD_DISABLED`,
  `disabled` in health, never in the catalog). The code is kept; `V18_ENABLE_MYNUMBER=1` turns it on for tests.
  `{over18: true, jpkiChain: "ok", certExpiry: "YYYY-MM-DD", nullifier, nullifierKeyId}`
  (nullifier message `v18-jpki-v1|<SHA-256 of the certificate's subject and serial>`).
- `face_estimate`, Android only, only with `V18_FACE_MODELS` (otherwise `501 METHOD_DISABLED`):
  `{estimator: "<model id in V18_FACE_MODELS>", challengeAge: 25 or more, passed: true, liveness: "passed"}`.
  One card per device key.
- `mdoc_app`: `proof` is the `DigitalCredential` the phone got from Credential Manager, exactly
  `{protocol, data}`, for the request from `POST /v1/wallet/app-request` made with the SAME
  challenge (section 14). The wallet credential's holder key is the nullifier, so one wallet ID
  gives at most 3 cards.
- `passport_zk`: not in v1. Always `501 METHOD_NOT_READY`.

What the server checks for the attested methods: the attestation (section 13) and the fields above.
It cannot re-check the chip or QR itself, because the phone sends nothing that identifies the person.

**Nullifier cap:** at most `V18_MAX_CARDS_PER_ID` (default 3) active, unexpired cards per ID.
Deleted and expired cards free their place.

**Errors**, in the order the server checks them:

| Status | `code` | When |
|--------|--------|------|
| 400 | `METHOD_UNKNOWN` | `method` is not one of the names above (connectors use section 16). |
| 401 | `CHALLENGE_INVALID` | Bad, used or expired challenge. |
| 501 | `METHOD_NOT_READY` | `passport_zk`. |
| 501 | `METHOD_DISABLED` | `test_dev` on a production server; `face_estimate` without `V18_FACE_MODELS`; `mynumber_attested` without `V18_ENABLE_MYNUMBER=1`. |
| 400 | `BAD_DEVICE_KEY` | See section 4. |
| 401 | `BAD_DEVICE_SIGNATURE` | The proof-of-possession signature does not verify. |
| 400 | `BAD_REQUEST` | test_dev: bad `testSubjectId`, `birthDate` or `idValidUntil`. |
| 403 | `UNDER_AGE` | Under 18 (test_dev), or the Aadhaar proof does not show age above 18. |
| 400 | `ID_EXPIRED` | test_dev: `idValidUntil` is in the past. |
| 503 | `METHOD_NOT_CONFIGURED` | anon_aadhaar without the pinned `vkey.json` or the seed; attested methods in production without `V18_ANDROID_CERT_DIGESTS`; mdoc_app without a trusted IACA or app origin. |
| 400 | `ATTESTATION_REQUIRED` / `ATTESTATION_INVALID` | Attested methods: see section 13. |
| 503 | `ATTESTATION_UNAVAILABLE` | Production: Google's revocation list could not be refreshed for 3 days. |
| 400 | `PROOF_INVALID` | Attested methods: `reason` is `malformed`, `unexpected_field`, `wrong_nullifier_key`, `passive_auth_failed`, `qr_signature_failed`, `jpki_chain_failed`, `unknown_estimator`, `challenge_age_too_low` or `liveness_failed`. |
| 400 | `WALLET_INVALID` / `WALLET_UNTRUSTED_ISSUER` | mdoc_app: see section 14. |
| 409 | `WALLET_NO_REQUEST` | mdoc_app: no `app-request` was made with this challenge. |
| 400 | `PROOF_INVALID` | anon_aadhaar. `reason` is `malformed`, `test_key_rejected`, `unknown_issuer_key`, `wrong_nullifier_seed`, `signal_mismatch`, `reveals_too_much` or `bad_proof`. |
| 409 | `DEVICE_KEY_IN_USE` | This device key already has an active card. |
| 409 | `NULLIFIER_OVERUSED` | This ID already has the maximum number of active cards. |

### `GET /v1/card/:cardId/status`

Answer `200`: `{"status": "active" | "revoked" | "expired", "validUntil": "<ISO>"}`. Nothing else.

| Status | `code` | When |
|--------|--------|------|
| 404 | `CARD_NOT_FOUND` | No such card. |

### `DELETE /v1/card/:cardId`

Body: `{"challenge": "…", "deviceSignature": {"alg": "…", "sig": "<over v18-card-delete\\n<cardId>\\n<challenge>>"}}`

Answer `200`: `{"cardId": "card_…", "status": "revoked"}`. Deleting twice is fine. The card stops
working at once and frees its nullifier place.

| Status | `code` | When |
|--------|--------|------|
| 401 | `CHALLENGE_INVALID` | Bad, used or expired challenge. |
| 404 | `CARD_NOT_FOUND` | No such card. |
| 400 | `BAD_REQUEST` | `deviceSignature` missing or malformed. |
| 401 | `BAD_DEVICE_SIGNATURE` | The signature is not from this card's device key. |

---

## 6. Tickets

### `POST /v1/ticket/blind-sign`

```json
{ "cardId": "card_…",
  "challenge": "<from POST /v1/challenge>",
  "keyId": "v18-age18-20261109",
  "blindedMessage": "<base64url, exactly the key's modulus length (256 bytes for RSA-2048)>",
  "deviceSignature": { "alg": "ES256", "sig": "<over v18-ticket-request\\n<cardId>\\n<challenge>\\n<keyId>\\n<blindedMessage>>" } }
```

**Answer `200`:**

```json
{ "blindSignature": "<base64url>", "keyId": "v18-age18-20261109",
  "algorithm": "RSABSSA-SHA384-PSS-Randomized" }
```

The server never sees the ticket itself, only the blinded message. The app builds the ticket
message (protocol 3.6), runs RFC 9474 `prepare` and `blind`, sends the blinded message, then
`finalize`s. The ticket string is `<keyId>.<base64url(prepared)>.<base64url(signature)>`.

To pick `keyId`: take the key from `GET /v1/keys` with `nbf <= now < exp` whose `v18_min_age` is
at least the site's age and at most the card's `minAgeCertified`.

**Errors**, in the order the server checks them:

| Status | `code` | When |
|--------|--------|------|
| 401 | `CARD_REQUIRED` | `reason: "missing_card"` or `"missing_signature"`: no `cardId` or no `deviceSignature`. |
| 401 | `CHALLENGE_INVALID` | Bad, used or expired challenge. |
| 400 | `BAD_REQUEST` | `keyId` missing, or `blindedMessage` not base64url. |
| 401 | `CARD_REQUIRED` | `reason` is `unknown_card`, `bad_signature`, `card_revoked` or `card_expired`. |
| 400 | `KEY_NOT_CURRENT` | `keyId` is unknown, already expired, or the next key that has not started. Fetch `GET /v1/keys` again. |
| 403 | `MIN_AGE_NOT_CERTIFIED` | The key's `v18_min_age` is higher than the card's `minAgeCertified`. |
| 400 | `BAD_BLINDED_MESSAGE` | Wrong length, or not smaller than the key's modulus. |
| 429 | `RATE_LIMITED` | More than `V18_TICKETS_PER_HOUR` (default 30) tickets for this card in the last hour. Has a `Retry-After` header and `retryAfterSeconds`. |

`CARD_REQUIRED` is used for every "no valid card plus device signature" case, as the protocol
says. The extra `reason` field **(V18 server choice)** tells the app what to show.

---

## 7. QR hand-off (pairing)

A website's widget opens a session and shows a QR. The phone (or the Windows app) scans it, makes a
ticket and drops it here. The widget picks it up. All in memory.

### `POST /v1/pairing/session`

```json
{ "origin": "http://localhost:3000", "challenge": "<the website's challenge>",
  "minAge": 18, "ttlSeconds": 120 }
```

- `origin`: a full web origin (`scheme://host[:port]`, http or https, no path).
- If the request has an HTTP `Origin` header, it must equal `origin`.
- `challenge` is required (PROTOCOL.md 4b items 7 and 15): the website's own challenge for this
  visit, **16 to 256 URL-safe characters** (`A-Z a-z 0-9 - . _ ~`). The verify libraries make
  32 random bytes as hex (64 characters).
- **Any website may call this** (see [CORS](#9-cors)), so it is limited per IP:
  `V18_PAIRING_SESSIONS_PER_MINUTE` (default 30) per minute. Every call counts, even a bad one.
- `minAge`: default 18. It must not be higher than the server's highest key threshold.
- `ttlSeconds`: default 120, kept between 30 and 300.

**Answer `201`:**

```json
{ "sessionId": "pair_<22 base64url chars = 128 random bits>",
  "deepLink": "v18://verify?session=pair_…&origin=http%3A%2F%2Flocalhost%3A3000&challenge=…&minAge=18&server=http%3A%2F%2Flocalhost%3A8080",
  "qrData": "<same as deepLink>",
  "expiresAt": "<ISO>", "expiresIn": 120,
  "pollUrl": "/v1/pairing/pair_…",
  "origin": "http://localhost:3000", "challenge": "…", "minAge": 18 }
```

`server=` is the server's public base URL **without** `/v1` (`V18_PUBLIC_URL`, default
`http://localhost:<port>`).

| Status | `code` | When |
|--------|--------|------|
| 429 | `RATE_LIMITED` | Too many sessions from this IP in the last minute. Has a `Retry-After` header and `retryAfterSeconds`. |
| 400 | `BAD_ORIGIN` | `origin` is not a web origin. |
| 403 | `ORIGIN_MISMATCH` | The `Origin` header differs from `origin`. |
| 400 | `BAD_REQUEST` | `challenge` missing or not 16 to 256 URL-safe characters, or `minAge`/`ttlSeconds` not numbers. |
| 400 | `MIN_AGE_UNSUPPORTED` | No ticket key that high. |

### `GET /v1/pairing/:sessionId` (polled by the widget)

```json
{ "sessionId": "pair_…", "status": "waiting" | "connected" | "approved" | "expired" | "cancelled",
  "origin": "…", "challenge": "…", "minAge": 18, "expiresAt": "<ISO>", "expiresIn": 87,
  "ticket": "<only once, on the first poll after approval>" }
```

The ticket is handed out **once**, then cleared. Later polls show `"status": "approved"` and
`"ticketDelivered": true`. **Only the website's widget should poll.** The phone must not poll
after it submits, or it would take the ticket.

| Status | `code` | When |
|--------|--------|------|
| 404 | `SESSION_NOT_FOUND` | Unknown, or removed (5 minutes after it expired). Also carries `"status": "expired"`. |

### `POST /v1/pairing/:sessionId/connect` (phone scanned the QR)

No body. Answer `200`: `{"success": true, "status": "connected"}`.

| Status | `code` | When |
|--------|--------|------|
| 404 | `SESSION_NOT_FOUND` | Unknown session. |
| 410 | `SESSION_EXPIRED` | The QR has expired. |
| 409 | `WRONG_STATE` | Not waiting any more (already connected, approved or cancelled). Has `status`. |

### `POST /v1/pairing/:sessionId/submit` (phone delivers the ticket)

Body: `{"ticket": "<keyId>.<base64url>.<base64url>"}`. Answer `200`:
`{"success": true, "status": "approved"}`. Works **once**. The relay does not open or check
the ticket. The website does that.

| Status | `code` | When |
|--------|--------|------|
| 404 | `SESSION_NOT_FOUND` | Unknown session. |
| 400 | `BAD_TICKET` | Not shaped like a ticket string. |
| 409 | `ALREADY_SUBMITTED` | A ticket was already submitted. |
| 410 | `SESSION_EXPIRED` | The QR has expired. |
| 409 | `WRONG_STATE` | The session was cancelled. |

### `POST /v1/pairing/:sessionId/cancel`

No body. Answer `200`: `{"success": true, "status": "cancelled"}`. Any waiting ticket is dropped.

| Status | `code` | When |
|--------|--------|------|
| 404 | `SESSION_NOT_FOUND` | Unknown session. |

---

## 8. Device link

This copies an age card onto a second device, such as the PC, without scanning the ID again.

### `POST /v1/card/link/start` (PC)

```json
{ "devicePublicKey": { "...PC's new public JWK...", "alg": "RS256" },
  "challenge": "…",
  "deviceSignature": { "alg": "RS256", "sig": "<over v18-card-issue\\n<challenge>\\n<PC thumbprint>>" } }
```

**Answer `201`:**

```json
{ "linkId": "link_<22 base64url chars>",
  "deepLink": "v18://link?id=link_…&server=http%3A%2F%2Flocalhost%3A8080",
  "expiresIn": 120, "expiresAt": "<ISO>" }
```

The link lasts 120 seconds and works once.

| Status | `code` | When |
|--------|--------|------|
| 401 | `CHALLENGE_INVALID` | Bad, used or expired challenge. |
| 400 | `BAD_DEVICE_KEY` | See section 4. |
| 401 | `BAD_DEVICE_SIGNATURE` | The proof-of-possession signature does not verify. |

### `POST /v1/card/link/:linkId/approve` (phone, after a fingerprint)

```json
{ "cardId": "<phone's card>", "challenge": "…",
  "deviceSignature": { "alg": "ES256", "sig": "<over v18-link-approve\\n<cardId>\\n<challenge>\\n<linkId>>" } }
```

**Answer `200`:** `{"status": "approved", "validUntil": "<ISO of the new PC card>"}`

The new card is bound to the PC's key. It has the same method, assurance level, certified age and
nullifier as the phone card, so it **counts toward the cap**, and it ends at the same time as the
phone card.

| Status | `code` | When |
|--------|--------|------|
| 404 | `LINK_NOT_FOUND` | Unknown link. |
| 409 | `LINK_USED` | Already approved. |
| 410 | `LINK_EXPIRED` | Older than 120 seconds. |
| 401 | `CHALLENGE_INVALID` | Bad, used or expired challenge. |
| 401 | `CARD_REQUIRED` | The phone card is unknown, revoked or expired, or the signature is wrong (see `reason`). |
| 409 | `DEVICE_KEY_IN_USE` | The PC key already has an active card. |
| 409 | `NULLIFIER_OVERUSED` | This ID already has the maximum number of active cards. The link stays `waiting`. |

### `GET /v1/card/link/:linkId` (polled by the PC)

- Waiting: `{"status": "waiting", "expiresIn": 87}`
- Approved, first poll: `{"status": "approved", "card": {cardId, method, assuranceLevel, minAgeCertified, validUntil}}`
- Approved, later polls: `{"status": "approved", "cardDelivered": true}` (the card is returned **once**)
- Expired: `{"status": "expired"}`

| Status | `code` | When |
|--------|--------|------|
| 404 | `LINK_NOT_FOUND` | Unknown, or removed (5 minutes after it expired). |

---

## 9. CORS

CORS decides which websites' browser code may read the server's answers (PROTOCOL.md 4b item 5).
There are two groups.

**Widget endpoints: open to any website.** The widget runs on the website's own page, so these
work from any origin:

- `GET /v1/health`
- `GET /v1/keys`
- `GET /v1/keys/pem`
- `POST /v1/pairing/session` (the `Origin` header must still equal `origin`, and there is a per-IP limit)
- `GET /v1/pairing/:sessionId`
- `POST /v1/pairing/:sessionId/cancel`
- `GET /v1/keys/nullifier`, `GET /v1/artifacts/manifest`, `GET /v1/artifacts/:name`, `GET /v1/catalog`
- `POST /v1/wallet/request` and `POST /v1/wallet/verify` (the `Origin` header must equal the session origin)

The answer has `Access-Control-Allow-Origin: <the request's origin>` and `Vary: Origin`, with
`Access-Control-Allow-Methods: GET, POST, OPTIONS`, `Access-Control-Allow-Headers: Content-Type, Range` and
`Access-Control-Expose-Headers: Content-Length, Content-Range, Accept-Ranges, ETag` (so browsers can resume artifact downloads).
There is **no** `Access-Control-Allow-Credentials`, because V18 never uses cookies. Only real web
origins are echoed (`scheme://host[:port]`). `null` and malformed values get no CORS headers.

**App endpoints: allowlist only.** These are everything else: challenge, card issue, status and
delete, ticket, device link, and pairing `connect` and `submit`. Browsers may read them only from:

- Dev mode: `http://localhost:3000` and `http://127.0.0.1:3000` (the demo site), plus `V18_CORS_ORIGINS`.
- Production: only `V18_CORS_ORIGINS` (comma-separated full origins).

For listed origins, the allowed methods are `GET, POST, DELETE, OPTIONS` and the allowed header is
`Content-Type`.

Preflight (`OPTIONS`) always answers `204`. CORS headers come only when the origin is allowed for
that path and the method in `Access-Control-Request-Method`. Apps that are not browsers (the phone,
the Electron main process) send no `Origin` header and are not affected.

---

## 10. Settings (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `V18_DEV_MODE` | off | `1` turns on `test_dev` and the Anon Aadhaar TEST key. `npm run dev` and `npm start` set it. `npm run start:prod` does not. |
| `PORT` | `8080` | HTTP port. |
| `V18_PUBLIC_URL` | `http://localhost:<PORT>` | Base URL put in deep links as `server=`. For the Android emulator, use `http://10.0.2.2:8080`. |
| `V18_DATA_DIR` | `server/data` | Folder for dev keys and the database (gitignored). |
| `V18_DATABASE_URL` (or `DATABASE_URL`) | none | `postgres://...`: keep ALL state in PostgreSQL (production; several server copies). Without it, SQLite. |
| `V18_DB_PATH` (or `DB_PATH`) | `<data>/v18.sqlite` | SQLite file, or `memory` for an in-memory database (dev). |
| `V18_KEY_STORE` | dev without PostgreSQL: `file`; otherwise `db` | `file`: plain JSON key files (DEV ONLY, refused in production). `db`: keys in the database, sealed with `V18_KEK`. |
| `V18_KEK` | none | 32-byte key-encryption key (64 hex characters or base64). Required for `db`. Keep it in a secret manager; losing it loses the keys. A KMS can be plugged in through the `KmsClient` interface (`src/keys/wrap.ts`). |
| `V18_NULLIFIER_KEY_BITS` | dev `2048`, production `3072` | Size of the long-lived `v18-nullifier-1` key (made once, never rotated). |
| `V18_ANDROID_PACKAGE` | `com.v18.app` | Package that must appear in key attestation. |
| `V18_ANDROID_CERT_DIGESTS` | none | Comma list of SHA-256 digests of the app signing certificates (hex with or without colons, or base64). Production needs it for the attested methods and `mdoc_app`. |
| `V18_NULLIFIER_PER_DEVICE_PER_DAY` / `V18_NULLIFIER_PER_IP_PER_HOUR` | `5` / `20` | Nullifier blind-sign limits (4c.2). |
| `V18_FACE_MODELS` | none | Face model IDs accepted for `face_estimate`. Empty: method off. |
| `V18_ENABLE_MYNUMBER` | off | `1` turns `mynumber_attested` back on. It is not in v1 (PROTOCOL.md 4d.4b): no public OID for the birth date, J-LIS revocation lists only for certified verifiers, Digital Agency certification needed. |
| `V18_FACE_CHALLENGE_AGE` | `25` | Lowest `challengeAge` accepted (at least 25). |
| `V18_IACA_DIR` | `server/assets/iaca` | Trusted IACA certificates for wallets. |
| `V18_DEV_IACA_PEMS` | none | DEV ONLY: extra IACA PEM files to trust (comma-separated paths). |
| `V18_WALLET_PER_IP_PER_MINUTE` | `30` | Wallet request and verify limit per IP. |
| `V18_NULLIFIER_SECRET` | dev: a fixed TEST value; production: none | HMAC secret for connector nullifiers (4d.4), at least 32 characters. Required when any connector is configured. Never change it (it would reset the card caps). |
| `V18_CONNECTOR_<ID>_*` | none | Connector credentials, read by `@v18/connectors` (see `docs/connectors/`). A connector without them is hidden. |
| `V18_CATALOG_PATH` | `<repo>/catalog/countries.json` | The country catalog file. |
| `V18_METRICS_TOKEN` | none | If set, `GET /metrics` needs `Authorization: Bearer <token>`. |
| `V18_PLAY_INTEGRITY` | off | Not built in v1. Setting it stops the server with a clear message. |
| `V18_KEY_DIR` | `<data>/keys` | File key store folder. It holds PRIVATE keys. |
| `V18_AGE_THRESHOLDS` | `18` | Comma list, for example `16,18,21`. One key chain each. |
| `V18_KEY_ROTATION_DAYS` | `7` | Key period, 1 to 90 days. |
| `V18_KEY_BITS` | `2048` | `2048`, `3072` or `4096`. |
| `V18_MAX_CARDS_PER_ID` | `3` | Nullifier cap. |
| `V18_TICKETS_PER_HOUR` | `30` | Rate limit per card. |
| `V18_AADHAAR_NULLIFIER_SEED` | dev: `180018001800180018`; production: none | Anon Aadhaar nullifier seed (decimal). |
| `V18_CORS_ORIGINS` | none | Extra browser origins allowed on the APP endpoints. Widget endpoints are open anyway. |
| `V18_PAIRING_SESSIONS_PER_MINUTE` | `30` | Per-IP limit on `POST /v1/pairing/session`. IPs are kept only as salted hashes (the salt is shared by all server copies), in the `rate_limits` table, for one minute. |
| `V18_TRUST_PROXY` | off | Set it when the server runs behind a reverse proxy, so the per-IP limit sees real client IPs (Express `trust proxy`: `true`, a hop count such as `1`, or a value such as `loopback`). Do not set it without a proxy, or clients could fake their IP. |

---

## 11. Anon Aadhaar artifacts (4c.1)

`npm run fetch-artifacts` downloads the official Anon Aadhaar v2 circuit files from the bucket
named in `@anon-aadhaar/core` (`https://anon-aadhaar-artifacts.s3.eu-central-1.amazonaws.com/v2.0.0/`)
into `server/assets/artifacts/` and refuses any file whose SHA-256 differs from the pin in
`server/assets/artifacts/manifest.json`. `-- --chunks` also gets the 10 optional gzip zkey chunks.

| File | Bytes | SHA-256 |
|------|-------|---------|
| `vkey.json` | 4,388 | `40f2ea24b56ffe2b6e6e3578053cbda15e773cb560697bac883a404077fcf177` |
| `aadhaar-verifier.wasm` | 10,469,686 | `4894923663fafda95beb70abca4112ea97a62058c9a46419a274f04236f10d4f` |
| `circuit_final.zkey` | 612,082,146 | `0d443ea85279b0370b53202f5e768ca9098cfcb5bb14f8ca8323d2266822c492` |
| `circuit_final_0.gz` ... `_9.gz` (optional) | 295,909,375 in total | in the manifest |

When the pins were made, the script also checked the S3 ETag (MD5) of every single-part file and
that `vkey.json` is exactly the key inside `circuit_final.zkey` (snarkjs `exportVerificationKey`).

### `GET /v1/artifacts/manifest` (open to any origin)

```json
[ { "name": "circuit_final.zkey", "sha256": "0d443e...", "bytes": 612082146,
    "url": "http://localhost:8080/v1/artifacts/circuit_final.zkey",
    "role": "proving_key", "optional": false, "available": true,
    "sourceUrl": "https://anon-aadhaar-artifacts.s3.eu-central-1.amazonaws.com/v2.0.0/circuit_final.zkey" }, ... ]
```

`url` is on this server (`V18_PUBLIC_URL`). `available` is true once the file is on disk AND its
SHA-256 matched the pin (checked in the background at start-up).

### `GET /v1/artifacts/:name` (open to any origin)

Sends the file with `ETag: "<sha256>"`, `X-Content-SHA256`, `Cache-Control: public, max-age=31536000,
immutable` and `Accept-Ranges: bytes`. `Range: bytes=N-` gives `206` (resume a broken download).
Apps must still check the SHA-256 themselves. Errors: `404 ARTIFACT_NOT_FOUND` (not in the manifest),
`503 ARTIFACT_NOT_READY` (not downloaded yet, or still being checked).

---

## 12. Nullifier service (4c.2)

A deterministic RSA blind signature used as an oblivious PRF: the same document always gives the
same nullifier, but the server never sees the document number and cannot compute a nullifier on
its own.

### `GET /v1/keys/nullifier` (open to any origin)

```json
{ "keys": [ { "kty": "RSA", "kid": "v18-nullifier-1", "use": "sig",
              "alg": "RSABSSA-SHA384-PSSZERO-Deterministic", "n": "...", "e": "AQAB",
              "v18_purpose": "nullifier" } ] }
```

Import only `{kty, n, e}` (4b item 3). The key is made once and never rotated (3072-bit in production).

### `POST /v1/nullifier/blind-sign`

```json
{ "challenge": "<from POST /v1/challenge>",
  "blindedMessage": "<base64url, exactly the modulus size>",
  "devicePublicKey": { "...JWK...", "alg": "ES256" },
  "deviceSignature": { "alg": "ES256", "sig": "<over v18-nullifier\n<challenge>\n<thumbprint>\n<blindedMessage>>" },
  "keyAttestation": ["<base64 DER leaf>", "...", "<root>"] }
```

The app's message is UTF-8 `v18-doc-v1|<ICAO state>|<document number, upper case, '<' removed>`
(`v18-philsys-v1|<PCN>` and `v18-jpki-v1|<...>` for 4d.3). The app runs RFC 9474 `prepare` (identity
for the deterministic variant), `blind`, this call, and `finalize`; then
**nullifier = base64url(SHA-256(signature))**.

**Answer `200`:** `{"blindSignature": "<base64url>", "keyId": "v18-nullifier-1",
"algorithm": "RSABSSA-SHA384-PSSZERO-Deterministic", "attestation": { ...as in card issue... }}`

Checks, in order: per-IP limit (`V18_NULLIFIER_PER_IP_PER_HOUR`, default 20) → challenge (used up)
→ blinded message format → device signature (`401 BAD_DEVICE_SIGNATURE`) → key attestation for
THIS challenge and THIS key (section 13) → per-device-key limit (`V18_NULLIFIER_PER_DEVICE_PER_DAY`,
default 5) → size (`400 BAD_BLINDED_MESSAGE`). One attested key per request is fine (the phone's
K1 for the nullifier and K2 for the card).

---

## 13. Android key attestation (4c.3)

`keyAttestation` is the Keystore certificate chain, leaf first, each certificate **base64 DER**
(standard base64 with padding, or base64url). The key must be made with
`setAttestationChallenge(UTF-8 bytes of the 64-hex server challenge)` of the SAME request.

The server checks (with `@peculiar/x509` and `@peculiar/asn1-android`):

1. every certificate is signed by the next, with matching names;
2. dates as in Google's own verifier: the trusted root is a trust anchor (its dates are not checked,
   so Google's 2016 root, which ran out in May 2026, still works); the leaf's dates are not checked
   (the phone sets them); "not yet valid" always fails; "expired" fails for remotely provisioned
   chains but not for factory-provisioned ones (their keys cannot be rotated);
3. the chain ends at a **Google hardware attestation root**, compared by public key. Bundled in
   `server/assets/android/google-attestation-roots.pem`: the RSA-4096 root and the EC P-384
   "Key Attestation CA1" root from `https://android.googleapis.com/attestation/root` (2026-11-19);
4. no certificate is on Google's revocation list (`https://android.googleapis.com/attestation/status`,
   refreshed every 6 hours, cached in the data folder, bundled snapshot to start; production fails
   closed with `503 ATTESTATION_UNAVAILABLE` if it could not be refreshed for 3 days);
5. the leaf's key is `devicePublicKey`;
6. the attestation challenge is the request's challenge;
7. attestation and KeyMint security level are TrustedEnvironment or StrongBox;
8. origin GENERATED (made inside the secure hardware, not imported);
9. `attestationApplicationId` is exactly one package, `com.v18.app`, signed with a certificate whose
   SHA-256 is in `V18_ANDROID_CERT_DIGESTS`;
10. verified boot state Verified and a locked bootloader.

Errors: `400 ATTESTATION_REQUIRED` (production, no chain) and `400 ATTESTATION_INVALID` with
`reason`: `malformed`, `bad_chain_signature`, `bad_chain_name`, `certificate_not_yet_valid`,
`certificate_expired`, `untrusted_root`, `revoked`, `key_mismatch`, `no_key_description`,
`bad_key_description`, `challenge_mismatch`, `software_security_level`, `key_not_generated`,
`no_application_id`, `bad_application_id`, `wrong_package`, `wrong_signing_certificate`,
`boot_not_verified`.

**Dev mode** lets `untrusted_root` (emulator/software roots), `software_security_level`,
`key_not_generated`, `cert_digest_not_checked` and `boot_not_verified` through, and also accepts a
request with no chain at all (`no_attestation`). Every exception is listed in
`attestation.devModeExceptions`. Play Integrity (`V18_PLAY_INTEGRITY`) is not built in v1.

---

## 14. Phone wallets (4c.5, 4d.3)

Protocol: **OpenID4VP 1.0 over the Digital Credentials API, unsigned request**
(`protocol: "openid4vp-v1-unsigned"`), DCQL asking ONLY for `age_over_18` from an mDL
(`org.iso.18013.5.1.mDL`) or an EU PID (`eu.europa.ec.eudi.pid.1`), `response_mode: "dc_api.jwt"`
(the wallet encrypts its answer, ECDH-ES with A128GCM or A256GCM, to a fresh P-256 key made for
this request only). The server verifies with `@auth0/mdl`: issuer signature and certificate chain
to the IACA trust list, MSO validity, value digests, and the device signature over

```
SessionTranscript = [null, null, ["OpenID4VPDCAPIHandover",
                     SHA-256(CBOR([origin, nonce, SHA-256 JWK thumbprint of the encryption key]))]]
```

so the answer is bound to the website's origin (or the app's origin) and to this request's nonce.

**Trust list:** every certificate file in `server/assets/iaca/` (see its README). Dev mode also
trusts `server/assets/iaca/test/v18-test-iaca.pem` (a TEST IACA the dev server makes on first start,
with its TEST document signer `v18-test-ds.cert` and key `v18-test-ds.key.json`) and any files in
`V18_DEV_IACA_PEMS`. **For the web test wallet:** either sign test mdocs with the TEST document
signer in `server/assets/iaca/test/`, or point `V18_DEV_IACA_PEMS` at your own TEST IACA, or run
`npm run dev-wallet -- --session <id>` (section 18).

### `POST /v1/wallet/request {sessionId}` (widget; open to any origin)

The `Origin` header (if any) must equal the session's origin (`403 ORIGIN_MISMATCH`). The session
must be `waiting` or `connected`, with `minAge` 18 or less (`400 MIN_AGE_UNSUPPORTED`).

```json
{ "sessionId": "pair_...",
  "digital": { "requests": [ { "protocol": "openid4vp-v1-unsigned",
      "data": { "response_type": "vp_token", "response_mode": "dc_api.jwt", "nonce": "<43 chars>",
                "dcql_query": { "credentials": [ {"id": "mdl", ...}, {"id": "pid", ...} ],
                                "credential_sets": [ { "options": [["mdl"], ["pid"]] } ] },
                "client_metadata": { "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", ... } ] },
                                     "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
                                     "vp_formats_supported": { "mso_mdoc": { ... } } } } } ] },
  "expiresAt": "<ISO>" }
```

Pass `digital` to `navigator.credentials.get({mediation: "required", digital})` untouched. A new
request replaces the previous one for that session.

### `POST /v1/wallet/verify {sessionId, response}` (widget; open to any origin)

`response` is the browser's `DigitalCredential` as `{protocol, data}` (`data` may be an object or a
JSON string). Each request works ONCE: the first verify uses it up, whatever the result.

**Answer `200`:** `{"status": "approved"}`. The server has put a normal ticket (format 3.6, signed with
the current age-18 key, for the session's origin and challenge) on the pairing session; the widget
gets it through the usual poll.

Errors: `409 WALLET_NO_REQUEST` (no open request), `410 SESSION_EXPIRED`/`WALLET_REQUEST_EXPIRED`,
`403 UNDER_AGE` (`age_over_18` is false), `400 WALLET_UNTRUSTED_ISSUER` (not from a trusted IACA),
`400 WALLET_INVALID` with `reason`: `wrong_protocol`, `not_encrypted`, `decrypt_failed`, `malformed`,
`tampered` (issuer signature or digest), `expired`, `device_auth_failed` (wrong nonce or origin),
`wrong_doctype`, `age_over_18_missing`; `503 METHOD_NOT_CONFIGURED` (no trusted IACA).
Rate limit: `V18_WALLET_PER_IP_PER_MINUTE` (30).

### `POST /v1/wallet/app-request {challenge}` (the V18 phone app, `mdoc_app`)

The challenge must be open (it is NOT used up here). The answer is `{digital: {requests: [...]},
expiresAt}`, the same request as above but with **nonce = the server challenge**. The app passes
it to Android Credential Manager (`GetDigitalCredentialOption`), then calls
`POST /v1/card/issue {method: "mdoc_app", challenge, devicePublicKey, deviceSignature, proof: <the
DigitalCredential {protocol, data}>}`. The expected origin is the app's Credential Manager origin,
`android:apk-key-hash:<base64url SHA-256 of the signing certificate>` for each
`V18_ANDROID_CERT_DIGESTS` entry. In dev mode without that setting, the TEST app may add
`"origin": "android:apk-key-hash:..."` to `proof`.

---

## 15. Country catalog (4d.2)

### `GET /v1/catalog?country=XX&platform=android|windows|web` (open to any origin)

The catalog from `catalog/countries.json` (`V18_CATALOG_PATH`),
checked against the 4d.2 schema and **filtered to this deployment**: a method stays only if
`methods[method]` in `GET /v1/health` is `ready` (so connectors only with credentials, face only with
`V18_FACE_MODELS`, `anon_aadhaar` only with the pinned key, wallets only with a trusted IACA,
`test_dev` only in dev mode). Methods this server does not know are left out. A country with no
method left is left out. `country` is case-insensitive; `platform` keeps methods whose `platforms`
include it.

```json
{ "version": 1, "countries": [ { "code": "SG", "name": "Singapore", "region": "asia",
    "methods": [ { "method": "emrtd_attested", "label": "Passport (chip)", "documents": ["Singapore passport"],
                   "docTypes": ["P"], "needs": ["nfc"], "privacy": "on_device", "platforms": ["android"] } ] } ] }
```

Errors: `400 BAD_REQUEST` (bad `country` or `platform`), `503 CATALOG_MISSING` (no file),
`503 CATALOG_INVALID` (the file breaks the schema; the log names the first problems). The file is
re-read when it changes.

---

## 16. Login connectors (4d.4)

The connectors come from `@v18/connectors` (the package in `connectors/`,
a `file:` dependency). A connector is enabled only when its credentials are set
(`V18_CONNECTOR_<ID>_...`) AND `V18_NULLIFIER_SECRET` is set; others are hidden everywhere.

### `POST /v1/connect/:id/start` (app)

```json
{ "challenge": "...", "devicePublicKey": { ... }, "deviceSignature": { "alg": "...", "sig": "<over v18-card-issue\n<challenge>\n<thumbprint>>" },
  "keyAttestation": ["..."], "idp": "<SPID/CIE only: the chosen identity provider entityId>" }
```

The signing string is the card-issue proof of possession (4d.4 names none; the same as device
link start). `keyAttestation` is optional and checked if present. **Answer `201`:**
`{"authUrl": "https://...", "state": "<43 chars>", "expiresIn": 600}`. Open `authUrl` in a Custom Tab
(Android) or the system browser (Windows). PKCE S256; `state`, `nonce` and the code verifier are
random 32 bytes, kept server-side with the device key for 10 minutes. Errors:
`404 CONNECTOR_NOT_ENABLED`, `401 CHALLENGE_INVALID`, `401 BAD_DEVICE_SIGNATURE`,
`502 CONNECTOR_ERROR` (with the connector's fixed `reason` code).

### `GET` or `POST /v1/connect/:id/callback` (the provider sends the browser here)

The redirect URI to register with each provider is `<V18_PUBLIC_URL>/v1/connect/<id>/callback`.
The connector reads ONLY the birth date or age answer and a subject ID. The server computes
`nullifier = HMAC-SHA256(V18_NULLIFIER_SECRET, id + "|" + subject)`, stores only its hash, and
forgets everything else at once. Nothing from the provider is logged. If over 18, it issues a
card bound to the device key from `start` (method `connector:<id>`, assurance from the connector:
`high` or `substantial`, 180 days, the nullifier cap applies).

It always answers `302` to the app link (with a small HTML page linking to it):
`v18://connect?status=ok&state=...&cardId=...`, `status=under_age`, `status=pending` (BankID: the
person has not finished; the next callback finishes), or `status=error&code=...` (`STATE_MISMATCH`,
`ALREADY_USED`, `EXPIRED`, `PROVIDER_ERROR`, `INVALID_RESPONSE`, `MISSING_BIRTHDATE`,
`NULLIFIER_OVERUSED`, `DEVICE_KEY_IN_USE`, ...). Apps must not trust the link: read the result below.

### `GET /v1/connect/session/:state` (app)

`{status: "waiting", expiresIn}`, `{status: "ok", card}` (the card ONCE, like the /card/issue answer;
later `{status: "ok", cardDelivered: true}`), `{status: "under_age", code}`, `{status: "error", code}`,
`{status: "expired"}`, or `404` with `status: "expired"`.

### `GET /v1/connect/session/:state/qr` (app; BankID Sweden only)

For a person on a PC whose BankID is on their phone: `{qrData: "bankid.<token>.<seconds>.<hmac>",
refreshMs: 1000}`. Draw `qrData` as a QR code and fetch it again every second (a BankID order lasts
30 seconds). The secret behind it stays on the server. `404` once the login is no longer waiting,
or for other connectors. (On the same device, `authUrl` opens the BankID app, which then opens the
callback itself.)

### Routes the providers and apps fetch

| Route | For | Answer |
|-------|-----|--------|
| `GET /v1/connect/:id/jwks` | Providers that check V18's signed requests or encrypt to V18 (Singpass, itsme, any connector with a `SIGNING_KEY`) | `{keys: [...]}`, public parts only (the server refuses to publish a private part), cached 1 hour. Register this URL with the provider. |
| `GET /v1/connect/:id/metadata` | SAML providers (SPID, CIE) | Signed SP metadata (`application/samlmetadata+xml`) whose AssertionConsumerService is the callback URL (form POST). Register it with AgID / the CIE portal. |
| `GET /v1/connect/:id/identity-providers` | Apps, for SPID and CIE | `{identityProviders: [{entityId, name}]}`. Pass the chosen `entityId` as `idp` to `start`. |

All three answer `404 CONNECTOR_NOT_ENABLED` for an unconfigured connector and `404 NOT_FOUND` when the
connector has no such data.

---

## 17. Metrics

### `GET /metrics` (not under `/v1`)

Prometheus text format: `v18_http_requests_total{method,route,status}` (route PATTERNS only, never
IDs), `v18_http_request_seconds`, `v18_cards_issued_total{method}`, `v18_tickets_signed_total`,
`v18_nullifier_signs_total`, `v18_wallet_results_total{result}`, and gauges `v18_cards_active`,
`v18_challenges_open`, `v18_pairing_sessions`. No origins, IDs or IPs. Set `V18_METRICS_TOKEN` to
require `Authorization: Bearer <token>`, and keep it off the public internet at the load balancer.

---

## 18. Test tools (TEST ONLY)

| Command | What it does |
|---------|--------------|
| `npm run dev-client` | Phase 1 happy path: TEST card, ticket (`--pair`, `--link`, `--rsa` as before). |
| `npm run dev-wallet -- --session <id or v18://verify link> [--under18] [--pid]` | Plays a phone wallet for a pairing session: asks `/wallet/request` (with the session's `Origin`), makes a TEST mdoc signed by the dev TEST IACA, answers `/wallet/verify`. The widget's poll then gets the ticket. |
| `npm run make-aadhaar-fixtures` | Makes real Anon Aadhaar proofs (about 19 s each) for the tests, from UIDAI's public SAMPLE QR re-signed with the Anon Aadhaar TEST key. |
| `npm run fetch-artifacts [-- --chunks] [-- --check]` | Downloads or checks the circuit files. |
| `npm run test:pg` | The whole test suite on a real PostgreSQL (embedded-postgres). |
