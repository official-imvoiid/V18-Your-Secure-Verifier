# Changelog: V18 web kit (`sdk-web/`)

All four packages share one version number. Dates are when the release was built.

## 1.0.0 (2026-11-19)

The first complete release, for protocol version 1 (PROTOCOL.md v1.2).

### Widget (`@v18/widget`, `v18-1.0.0.min.js`)

- **New: phone wallet IDs** (PROTOCOL.md 4c.5, `mdoc_wallet`). "Use a phone wallet ID" appears only
  when the browser has the Digital Credentials API **and** the V18 server reports
  `methods.mdoc_wallet: "ready"`. The widget gets the request from `POST /v1/wallet/request`, hands it
  to `navigator.credentials.get` untouched, sends the answer to `POST /v1/wallet/verify`, and then
  picks up the ticket through the normal pairing poll. New screens: open my wallet, waiting for your
  browser, checking the answer, and clear refusals (nothing shared, under 18, untrusted issuer).
  Closing the widget or the request expiring stops the browser's wallet request.
  Tested live against the V18 dev server 0.3.0 (8 of 8 checks, plus a browser run).
- **Removed** every "not available yet" and "coming soon" text. Options that can't work are not shown.
- App store wording changed to "Install V18 ..." (the apps are not in any store yet).
- Default V18 server is now the production placeholder `https://api.v18.example` (PROTOCOL.md 4c.7).
  Set `data-v18-server` on the script tag. For local work use `http://localhost:8080`.
- The bundle carries its version (`V18.version`) and a banner comment.
- Release build `v18-1.0.0.min.js` with a published SRI hash (`release/SRI.txt`) and the 2-line
  embed with `integrity` (`release/embed.html`).

### `@v18/verify` (Node) and `v18_verify` (Python)

- No change to the checks. Package metadata added: licence `UNLICENSED` (Python:
  `LicenseRef-UNLICENSED`), README, LICENSE, keywords, `exports`.
- Python builds as a wheel and an sdist (`python -m build`). Both are marked "do not upload" until a
  licence is chosen.

### Demo site

- **Production mode** (`DEMO_MODE=production` or `npm run start:prod`, with `V18_SERVER` and
  `SITE_ORIGIN`): no browser test wallet, no crypto inspector, no replay demo, no status API. The
  page loads the versioned release widget with its SRI hash.
- Dev mode: the developer tools show only when the V18 server says it is in dev mode.
- Security headers on every page: a Content Security Policy with a nonce per page, `nosniff`,
  `no-referrer`, `frame-ancestors 'none'`, and HSTS on HTTPS.
- `Dockerfile` (not run here: Docker is not installed).
- The mock V18 server (test only) now does phone wallet IDs for real against a TEST IACA, so the
  wallet flow is tested end to end.

## 0.9.0 (2026-11-10, phase 1)

- Widget with phone QR hand-off, V18 for Windows deep link, TEST MODE banner, dark theme and
  accessibility. Phone wallet IDs were detection only.
- `@v18/verify` and `v18_verify` with all eight checks of PROTOCOL.md 3.7 and 24 shared test vectors.
- Demo site with the browser test wallet (dev only) and a mock V18 server (test only).
