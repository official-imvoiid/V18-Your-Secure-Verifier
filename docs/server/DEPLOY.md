# Deploying the V18 server

This is how to run the V18 server for real users. For every setting, see [API.md](API.md)
section 10. For what the server does, see [WALKTHROUGH.md](WALKTHROUGH.md).

> **Not tested here:** Docker is not installed on the build machine, so the `Dockerfile` and
> `docker-compose.yml` in `server/` were written but **never built or run**. Everything else on
> this page (PostgreSQL, the encrypted key store, several server copies on one database) is
> covered by the test suite, which runs against a real PostgreSQL 17 through `embedded-postgres`.

## 1. What a production server needs

| Need | Setting | Notes |
|------|---------|-------|
| Production mode | do NOT set `V18_DEV_MODE` | Turns off `test_dev`, the Anon Aadhaar TEST key, the TEST IACA and every dev-mode attestation exception. |
| PostgreSQL 14 or newer | `V18_DATABASE_URL=postgres://user:pass@host:5432/v18` | ALL state lives here, so you can run several copies behind a load balancer. Migrations run by themselves at start-up, once, under a lock. Each applied migration's SHA-256 is recorded; the server refuses to start if an applied migration file was edited (add a new numbered migration instead). |
| Key-encryption key | `V18_KEK=<64 hex characters or base64 of 32 random bytes>` | Seals every signing key (AES-256-GCM) in the `signing_keys` table. Keep it in a secret manager. **Losing it means new keys: every card's tickets keep working with new keys, but the nullifier key would change, which resets every passport's card cap.** Back it up. |
| Public URL | `V18_PUBLIC_URL=https://api.v18.example` | Goes into deep links (`server=`) and the connector redirect URIs. Use your real domain. |
| HTTPS | at your load balancer or proxy | The server speaks plain HTTP and sends HSTS in production. Set `V18_TRUST_PROXY=1` (one proxy hop) so per-IP limits see real client IPs. |
| Anon Aadhaar | `V18_AADHAAR_NULLIFIER_SEED=<your own decimal seed>` and the artifacts | Pick the seed once, publish it (it is in `/v1/health`) and never change it. The Docker build runs `npm run fetch-artifacts`. |
| Android app | `V18_ANDROID_CERT_DIGESTS=<SHA-256 of your release signing certificate>` | From `apksigner verify --print-certs` or the Play Console (App signing key certificate, SHA-256). The current upload certificate is `1447a2a752b997fa768f2f198cb8e1c90ee0c8ba8149b94a12ab36ea2b4edae3` (see `docs/mobile/RELEASE.md`); with Play App Signing, add Google's app-signing certificate too (comma-separated). Without it, the attested methods and `mdoc_app` are off. |
| Login connectors | `V18_NULLIFIER_SECRET=<32+ random characters>` and each provider's `V18_CONNECTOR_<ID>_*` | See `docs/connectors/`. Register `<V18_PUBLIC_URL>/v1/connect/<id>/callback` with each provider; for Singpass and itsme also the key URL `<V18_PUBLIC_URL>/v1/connect/<id>/jwks`; for SPID and CIE the metadata URL `<V18_PUBLIC_URL>/v1/connect/<id>/metadata`. You must sign up with each provider yourself. Never change the secret. |
| Wallet IDs | IACA certificates in `server/assets/iaca/` | See that folder's README. Without any, the wallet methods are off. |
| Face estimate | `V18_FACE_MODELS=<model id>` | Only if a face model meets PROTOCOL.md 4c.6 (today it does not). |
| Metrics | `V18_METRICS_TOKEN=<random>` | Scrape `GET /metrics` with `Authorization: Bearer <token>`. Keep `/metrics` off the public internet. |

Make the random values with, for example:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 2. With Docker Compose (server + PostgreSQL)

From the repository root (the image needs `server/`, `connectors/` and `catalog/`):

1. Create `server/.env` (never commit it):

   ```
   V18_DB_PASSWORD=<random>
   V18_KEK=<64 hex characters>
   V18_PUBLIC_URL=https://api.v18.example
   V18_AADHAAR_NULLIFIER_SEED=<decimal number>
   V18_ANDROID_CERT_DIGESTS=<sha256 of the release signing certificate>
   V18_NULLIFIER_SECRET=<random, 32+ characters>
   V18_METRICS_TOKEN=<random>
   ```

2. Build and start:

   ```bash
   docker compose -f server/docker-compose.yml up --build -d
   ```

3. Check it:

   ```bash
   curl http://localhost:8080/v1/health
   ```

   `devMode` must be `false`, `storage` must be `postgres`, and `artifacts` must be `ready`.

The image build downloads the Anon Aadhaar files (612 MB zkey plus 296 MB of optional chunks;
`--build-arg FETCH_CHUNKS=0` skips the chunks) and fails if any SHA-256 differs from the pin. The
image runs as the unprivileged `node` user and keeps only the attestation revocation cache and the
artifact check cache in `/data`.

## 3. Without Docker

```bash
cd connectors && npm ci && npm run build && cd ..
```

```bash
cd server && npm ci && npm run build && npm run fetch-artifacts
```

Then, with the settings from section 1 in the environment:

```bash
npm run start:prod --prefix server
```

## 4. Several server copies

Run as many copies as you like against the same `V18_DATABASE_URL` and the same `V18_KEK`.
They share challenges, rate limits, pairing sessions, device links, wallet requests, connector
logins, cards, nullifiers and keys, so a request may go to any copy. Tested: a challenge from one
copy used on another, a QR session filled on one and collected once on another, a device link
across copies, shared rate limits, the same JWKS, and six cards for one ID issued at the same
time on two copies stopping at exactly 3 (PostgreSQL row locks).

SQLite (`V18_DB_PATH`) is for development and for ONE server copy only.

## 5. Key store options

- `V18_KEY_STORE=db` (the production default): keys in PostgreSQL, sealed with `V18_KEK`.
- A cloud KMS instead of a plain KEK: implement the two-call `KmsClient` interface in
  `server/src/keys/wrap.ts` (for example with AWS KMS `Encrypt`/`Decrypt` or Google Cloud KMS
  `encrypt`/`decrypt`, passing the context string as encryption context) and pass
  `keyWrapper: new KmsKeyWrapper(client)` to `createV18`. Each key then gets its own data key, and
  only the KMS can open it. No cloud SDK ships with V18, because it needs your own cloud account.
- An HSM: implement the `KeyStore` interface in `server/src/keys/keystore.ts` (it needs only
  "make key", "list public keys", "raw RSA sign of a blinded value" and "delete").
- `V18_KEY_STORE=file` is refused in production.

## 6. Things you must do yourself

- Buy a domain and a TLS certificate, and set `V18_PUBLIC_URL`.
- Register with each login provider you want (Singpass, BankID, FranceConnect, ...). The sessions
  were told not to do this.
- Choose which wallet issuers to trust and put their IACA certificates in `server/assets/iaca/`.
- Back up PostgreSQL and `V18_KEK`.
- Keep the Android revocation list reachable: the server fetches
  `https://android.googleapis.com/attestation/status` every 6 hours and refuses attested requests
  (503) if it could not refresh for 3 days.
