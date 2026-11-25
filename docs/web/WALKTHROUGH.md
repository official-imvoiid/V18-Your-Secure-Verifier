# Web SDK walkthrough (`sdk-web/`)

This covers everything a **website** needs for V18 protocol v1 (`PROTOCOL.md`): the widget visitors
see, the libraries a website's server uses to check tickets, and a demo site that ties it together.
For website owners, the short guide is [`INTEGRATION.md`](INTEGRATION.md).

## 0. Protocol v1.2 and v1.3 additions: read this first

Sections 1 to 9 below are the phase 1 walkthrough. Where they differ, this section wins.

**What changed**
- **Phone wallet IDs (4c.5) are built.** `widget/src/wallet.ts` + `controller.ts`: the option shows only
  when the browser has the Digital Credentials API **and** `/v1/health` says `methods.mdoc_wallet: "ready"`.
  Flow: site challenge -> pairing session -> `POST /v1/wallet/request` -> `navigator.credentials.get`
  (request passed untouched) -> `POST /v1/wallet/verify` -> normal pairing poll -> ticket. New screens:
  open my wallet (when the click is too old), waiting for your browser, checking, and refusals
  (nothing shared, under 18, untrusted issuer). Expiry or closing aborts the browser request.
- **No stub text.** "Not available yet" and "coming soon" are gone (a widget test fails if they come back);
  app-store wording is now "Install V18 ...". The browser test wallet stays, dev only.
- **TEST wallet + TEST IACA** (`demo-site/src/wallet-test/`, test only) make real mdoc answers
  (`@auth0/mdl`, device-signed, JWE-encrypted). The **mock V18** checks them for real (`mock-v18/wallet.ts`).
- **Release** (`npm run release --prefix sdk-web`, outputs in `sdk-web/release/`): `v18-1.0.0.min.js`
  (SRI `sha384-tcKbdf6aC+sdgJWk92+rILbbF4VcEv1EQedM0Dx4XyzEkRg/bkIK3xYpzUrm0BOy`), `embed.html`,
  `v18-verify-1.0.0.tgz`, `v18-widget-1.0.0.tgz`, `v18_verify-1.0.0` wheel and sdist, CHANGELOG, LICENSE,
  SHA256SUMS. The script installs both npm tarballs and the wheel in a temp folder and loads them.
  Licence: `UNLICENSED` (Python: `LicenseRef-UNLICENSED`, plus "Private :: Do Not Upload").
- **Demo production mode** (`npm run start:prod`, `V18_SERVER`, `SITE_ORIGIN`): no dev tools at all,
  release widget with SRI, CSP with nonces. `Dockerfile` written but **not run** (no Docker); its steps
  were replayed by hand instead. See `DEPLOY-DEMO.md`.
- **Countries (4d):** `npm run countries --prefix sdk-web` writes the tables in INTEGRATION.md section 6
  from `catalog/countries.json`. Last generated 2026-11-24 from the catalog updated that day (no longer
  marked draft): **54 countries, 124 ways**, all 127 table rows well formed. Sri Lanka (LK) is in the
  catalog with no ways listed. If the catalog changes again, re-run it (`-- --check` tells you if the
  guide is out of date).

**Test results (2026-11-24, real counts, fresh build):** verify-node 67/67, verify-python 62/62,
widget 37/37, demo-site 29/29 = **195 passed, 0 failed**, plus 4/4 country-script tests. The release
was rebuilt from the same source: same SRI hash, npm tarballs and wheel install and load.

**Live runs**
- **Phone wallet against the real dev server (0.3.0, protocol 1.3, dev mode), 2026-11-24:
  `npm run live:wallet --prefix sdk-web` ALL PASSED (8 of 8).** The widget's real state machine,
  a demo-site instance and a TEST phone wallet whose mdoc was sealed by the server's TEST document
  signer (`server/assets/iaca/test/`, read only):
  1. the widget offered "Use a phone wallet ID" (`methods.mdoc_wallet: "ready"`);
  2. adult TEST mDL: starting -> wallet_waiting -> wallet_checking -> approved -> done;
  3. the ticket came from the server's age-18 key (`v18-age18-20261123`);
  4. the demo site checked it with `@v18/verify` and opened the 18+ page;
  5. adult TEST EU PID: done;
  6. under-18 TEST ID: `UNDER_AGE`, site stayed locked;
  7. ID from an IACA the server does not trust: `WALLET_UNTRUSTED_ISSUER`;
  8. answer made for another site: `WALLET_INVALID` (device signature over origin and nonce fails).
- **Same flow in a real browser against the real server, 2026-11-24:** the in-app browser (which has
  `DigitalCredential`) showed the wallet option, the server's request reached `navigator.credentials.get`
  untouched (OpenID4VP, `dc_api.jwt`, only `age_over_18`), the TEST wallet's answer was relayed in by
  hand, and the page went to "You're verified as 18+" and the 18+ page. The page's CSP also blocked a
  test fetch to an address it does not allow, as it should.
- Earlier, against server 0.2.0 (2026-11-23): the demo in production mode (replayed Docker image)
  loaded the release widget with SRI under CSP, showed only the two options that server supported, and
  a QR hand-off with the server's dev client as the phone opened the 18+ page.
- No real phone wallet app was used anywhere: there is none on this machine.

**Design notes (v1.2 and v1.3)**
1. 4c.5 does not name the health flag; the widget uses `methods.mdoc_wallet === "ready"` (the server's
   `methods` map). It does not say the wallet endpoints are widget endpoints (open CORS); they must be.
2. With a wallet, V18 sees the wallet's answer and makes the ticket itself, so it is not blind-signed.
   The widget says so ("V18 makes the ticket from the wallet's answer, then forgets it").
3. Browsers open a wallet only right after a click, so the widget adds an "Open my wallet" step when
   the click is too old.
4. 4d.5 asks web only for docs; the catalog has no web rows, so wallet support is explained apart from
   the country table.

**Not in v1 (web):** no real phone wallet was tested (no wallet app here); `org-iso-mdoc` is not used
(the server asks with OpenID4VP only); Docker image not built; nothing published to npm, PyPI or a CDN;
the widget needs `style-src 'unsafe-inline'` on sites with a CSP.

## 1. What is in `sdk-web/`

| Folder | What it is | Tech |
|--------|------------|------|
| `widget/` | The age-check pop-up. Bundle: `widget/dist/v18.js` (72.6 KB) | TypeScript, Shadow DOM, no framework. Only dependency: `qrcode-generator` |
| `verify-node/` | `@v18/verify`: checks tickets on a Node.js server, plus `ChallengeStore` | TypeScript, Node's built-in `crypto` only |
| `verify-python/` | `v18_verify`: the same for Python, plus `examples/flask_site.py` | Python 3.9+, `cryptography` |
| `demo-site/` | "Reserve Cellar", an example 18+ shop on port 3000. Also the **browser test wallet (dev only)** and a **mock V18 server (test only)** | Express, TypeScript, `@cloudflare/blindrsa-ts` |
| `test-vectors/` | `v1-tickets.json`: 24 real tickets that both libraries must judge the same way | made by `verify-node/scripts/make-vectors.mjs` |

## 2. How to run it

Build (verify-node first, because the demo site uses it):

```bash
npm run build --prefix sdk-web/verify-node
```

```bash
npm run build --prefix sdk-web/widget
```

```bash
npm run build --prefix sdk-web/demo-site
```

Tests:

```bash
npm test --prefix sdk-web/verify-node
```

```bash
npm test --prefix sdk-web/widget
```

```bash
npm test --prefix sdk-web/demo-site
```

```bash
python -m pytest sdk-web/verify-python/tests/test_verifier.py -v
```

Try it in a browser: start the V18 server, then the demo site, then open http://localhost:3000.

```bash
npm run dev --prefix server
```

```bash
npm start --prefix sdk-web/demo-site
```

No V18 server handy? `npm run mock-v18 --prefix sdk-web/demo-site` starts the **mock** on port
8080 instead. It prints "MOCK V18 SERVER (TEST ONLY)" and its key IDs start with `v18mock-`.

## 3. Test results (real counts, run on 2026-11-10 and again on 2026-11-18)

| Part | Tests | Result |
|------|-------|--------|
| verify-node | 67 (31 rule and format tests, 12 JWKS and challenge tests, 24 shared vectors) | 67 passed, 0 failed |
| verify-python | 62 | 62 passed, 0 failed |
| widget | 30 | 30 passed, 0 failed |
| demo-site | 12 (end to end over real HTTP, with the mock V18 server) | 12 passed, 0 failed |
| **Total** | **171** | **171 passed** |

Plus a **live run against the real dev server** (section 7).

## 4. The verify libraries

Both libraries do the same thing and pass the same 24 shared test vectors (real blind-signed
tickets made with `@cloudflare/blindrsa-ts`).

**Every rule in PROTOCOL.md 3.7, in code:**

| Rule | How it is done |
|------|----------------|
| 1. `keyId` in the JWKS, now ≤ `exp` + 600 | `JwksKeyStore` downloads `GET /v1/keys`. It keeps only keys with `alg: RSABSSA-SHA384-PSS-Randomized`, a whole-number `v18_min_age`, `nbf` and `exp`, and RSA of at least 2048 bits. Keys that disappear from the JWKS are dropped. An unknown key ID triggers a re-download at most every 30 seconds, so junk tickets cannot flood V18. If V18 is down, already-downloaded keys keep working |
| 2. RSA-PSS, SHA-384, MGF1-SHA-384, salt 48, over `prepared` | Node `crypto.verify` / Python `cryptography`. Wrong salt length or hash fails |
| 3. `v == 1` | Exactly the number 1 (`true` or `"1"` fail) |
| 4. origin | Exact string match. The site's own origin must be a real origin (`https://x.com`, no slash), or the result is `CONFIG_ERROR` |
| 5. challenge | Required. A string, or a checker function from `ChallengeStore` that uses the challenge up |
| 6. age | Uses the **key's** `v18_min_age`. The ticket's own `minAge` is ignored for this |
| 7. time | `iat - 60 ≤ now ≤ expiresAt + 60`, and `0 ≤ expiresAt - iat ≤ 300` |
| 8. replay | `MemoryReplayCache` remembers accepted ticket IDs until they can no longer pass rule 7. Only fully valid tickets are remembered, so a refused ticket cannot "burn" an ID. The cache is an interface, so sites with several servers can plug in Redis |

The numbers (600, 60, 300, 48) are constants. A site cannot loosen them.

**Challenge helper.** `ChallengeStore` makes 64-hex-character challenges, ties each to a visit,
lets each be used once, and forgets them after 5 minutes (at most 5 open per visit). In Python the
store is thread-safe.

**API (Node)**: `new V18Verifier({serverUrl, origin, minAge})`, then
`await verifier.verifyTicket(ticket, {expectedChallenge})` returns `{valid: true, ticket}` or
`{valid: false, code, error}`. **Python**: `V18Verifier(server_url=..., origin=...)`, then
`verifier.verify_ticket(ticket, expected_challenge=...)`.

## 5. The widget

**Screens:**

| Screen | Design | What it does |
|--------|--------|--------------|
| Choose a way | `WidgetChoose`, `DarkWidget` | Three options, "what the site gets / never gets" |
| Scan with your phone | `QrWaiting` | Asks the site for a challenge, then `POST /v1/pairing/session {origin, challenge, minAge, ttlSeconds: 120}`. Shows the QR (the `v18://verify?...&server=...` link), a live 2-minute countdown, and polls every second |
| Phone connected | `QrConnected` | When the poll says `connected` |
| Getting your ticket | `QrApproved` | When the poll says `approved`, then "Giving it to example.com" while the site checks it |
| You're verified | `QrDone` | After the site's server says yes. Closes by itself after 3 seconds |
| Code expired | `QrExpired` | Timer hit 0, or V18 says expired / 404. "Get a new code" fetches a **new** challenge and session |
| Connection lost | `QrRetry` | 8 failed polls in a row, or V18 / the site cannot be reached |
| Site said no | (new) | The site's server refused the ticket. Shows its reason and "Try again" |
| V18 for Windows | (new, in the same style) | Creates a hand-off session and opens the `v18://verify?...&server=...` link. The Windows app submits the ticket to that session, so the widget waits the same way. After 6 seconds with no sign the app opened, it shows "Nothing happened?" and a **Don't have the app?** screen (get the app, or use your phone instead). Browsers don't tell pages whether an app opened, so the widget only uses "this page lost focus" as a hint and says so |
| Phone wallet ID | `WidgetWallet` (honest version) | Detects the Digital Credentials API. Without it: **"not available in this browser yet"**. With it: "coming soon", because V18 has no server step for wallet answers yet. Nothing is faked |
| How it works | (new) | Three plain steps |

**Also:**

- **TEST MODE banner** whenever `GET /v1/health` says `"devMode": true`.
- **Dark theme**: `auto` (follows the system, and changes live), `light` or `dark`, using the
  design's colour tokens.
- **Accessibility**: a real modal dialog (`role="dialog"`, `aria-modal`, labelled by the screen's
  heading), focus moves to each new screen's heading, Tab stays inside the dialog, Escape
  closes, focus goes back to the button you pressed, options are real buttons, a polite live
  region announces screen changes and "30 seconds left", visible focus rings, reduced-motion and
  high-contrast support, and a stacked layout under 720 px.
- **Privacy**: no web fonts or other third-party requests. Everything the widget writes into the
  page is escaped.
- **Closing or "Choose another way"** cancels the hand-off session on V18.
- **2-line embed and `V18.verify({...})`** both kept (see INTEGRATION.md).
- **Test wallet hook (dev only)**: `V18.registerTestWallet(...)`. The "Simulate a phone with the
  test wallet" button shows **only** when a test wallet is registered **and** V18 is in dev mode.

The logic is a small state machine (`widget/src/controller.ts`) with no browser code, so the tests
drive every flow against a fake V18 server and a fake website server.

## 6. The demo site

- `POST /v18/challenge` and `POST /v18/verify`: exactly what INTEGRATION.md tells sites to build,
  using `@v18/verify`. A random visit ID lives in an HttpOnly, SameSite=Lax cookie. The "18+" state
  lives on the server for one hour. POSTs from other origins are refused.
- `/adult-content` is only served to a verified visit.
- **Browser test wallet (dev only)** (`demo-site/src/client/`). It acts as the phone app inside the
  browser and runs the **real** protocol flow: a WebCrypto ES256 device key (private key not
  extractable, kept in IndexedDB), a `test_dev` age card (test birth date `1990-01-01`, or
  `2012-06-01` to watch V18 refuse), then a ticket: write the message, blind it with
  `@cloudflare/blindrsa-ts`, get a fresh V18 challenge, sign the protocol signing string, call
  `/v1/ticket/blind-sign`, unblind. It can also delete its card (`DELETE /v1/card/:id`). Two ways
  to use it: the **Run the test wallet in this browser** button (no widget), or the widget's
  **Simulate** button, which goes through the real QR hand-off session.
- **Crypto inspector**: every test-wallet step with real values (thumbprint, challenges, key ID,
  blinded message, blind signature, ticket).
- **Replay-attack demo** (on the unlocked page): takes this visit's accepted ticket and attacks
  with it: (1) send it again, refused with `CHALLENGE_MISMATCH`; (2) skip the challenge check
  (demo only), refused by the replay cache with `REPLAY_DETECTED`; (3) change one byte of the
  seal, refused with `INVALID_SIGNATURE`. It never unlocks anything.
- **Mock V18 server (test only)** (`demo-site/src/mock-v18/`). Strict on purpose: it checks every
  device signature, consumes every challenge, refuses tickets without a card. The demo-site tests
  use it.

## 7. Live end-to-end run against the real server

On 2026-11-10 the rebuilt server (`npm run dev --prefix server`, version 0.2.0, dev mode) was
running, so I tested against it:

| What | Result |
|------|--------|
| Widget in the in-app browser: phone QR hand-off, test wallet as the phone | New real `test_dev` card, real blind signature, ticket through the pairing session, demo site accepted it (`keyId v18-age18-20261109`, 18+) |
| Same, with "Use V18 for Windows" | Tested with the **mock** server only (before the real server was up): the deep link opened, the help hint came after 6 s, and the test wallet finished the flow |
| Direct "Run the test wallet" button | Worked, card reused from IndexedDB |
| Replay demo | `CHALLENGE_MISMATCH`, `REPLAY_DETECTED`, `INVALID_SIGNATURE` |
| Delete the card from the browser (CORS `DELETE`) | Card deleted |
| Under-18 test birth date | V18 refused: `UNDER_AGE` |
| Blind-sign with no card | `401 CARD_REQUIRED` |
| Python `v18_verify` on a real ticket | Accepted once, then `REPLAY_DETECTED`; wrong challenge `CHALLENGE_MISMATCH` |
| INTEGRATION.md's Express code and `flask_site.py` | Both accepted a real ticket and opened the members page |
| Key rotation (re-checked 2026-11-18) | The test wallet picked the new current key `v18-age18-20261116`; Python fetched it and accepted the ticket once, then `REPLAY_DETECTED` |

One thing went wrong during the run and was fixed: the demo site had cached the **mock** server's
key, which had the same key ID as the real server's key, so the first real ticket failed with
`INVALID_SIGNATURE`. The mock's key IDs now start with `v18mock-` so this cannot happen again.

## 8. What is stubbed, test-only or not done

- **Browser test wallet**: test only. Software key in the browser, no fingerprint, test birth date.
- **Mock V18 server**: test only, in memory.
- **Phone wallet IDs**: built for v1.2 (see section 0).
- **Windows app detection**: a hint (page focus), not a guarantee.
- **No real phone or Windows app was used**: those are tested in `mobile/` and `windows/`. The QR and the deep
  link follow the protocol, but they have not been scanned by the real apps here.
- **Default V18 server URL** in the widget is `http://localhost:8080`, because there is no
  production URL yet. Real sites must set `data-v18-server`.
- **Challenges and the replay cache are in memory** by default (fine for one process). Both are
  pluggable for bigger sites.
- **Not published** to npm or PyPI. No CDN.
- **Browser support**: tested in the desktop app's Chromium-based browser only.

## 9. Design notes (unclear or missing)

1. **CORS is not in the protocol.** The widget runs on the website's page and calls V18's
   `/v1/health` and `/v1/pairing/*`. The dev server allows only `localhost:3000` plus
   `V18_CORS_ORIGINS`. For "any website in the world", those endpoints probably need to allow any
   origin (the pairing endpoint already checks `Origin == origin`).
2. **`nbf` has no rule in 3.7.** I refuse tickets whose key's `nbf` is more than 60 seconds in the
   future (`KEY_NOT_YET_VALID`), since V18 only signs with the current key.
3. **Pairing poll replies are not described.** The widget handles `waiting`, `connected`,
   `approved` (or any reply with a `ticket`), `expired`, `cancelled`, and treats 404/410 as
   expired. This matches the rebuilt server.
4. **The website challenge's format is not given.** `ChallengeStore` makes 64 hex characters (like
   V18's). The widget accepts 16 to 256 printable characters.
5. **Phone wallet IDs** are in the designs and README, but the protocol has no endpoint to turn a
   wallet's answer into a ticket.
6. **V18 for Windows on a website**: the protocol gives the deep link but does not say that the
   Windows app submits the ticket to the same pairing session. The widget assumes it does.
7. **Ticket `minAge` vs the key's age**: the protocol says to authorize with the key's age, but not
   whether a ticket whose `minAge` differs should be refused. The libraries ignore it.
8. Root `package.json` runs only `verify-python/tests/test_verifier.py`, so all Python tests stay in
   that one file.
