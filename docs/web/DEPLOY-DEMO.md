# Running the demo site in production mode

The demo site (`sdk-web/demo-site`, "Reserve Cellar") is an example 18+ shop. It has two modes.

| | Dev mode (default) | Production mode |
|---|---|---|
| How to start | `npm start --prefix sdk-web/demo-site` | `npm run start:prod --prefix sdk-web/demo-site`, or `DEMO_MODE=production` |
| Browser test wallet, crypto inspector, replay-attack demo | Yes, but shown only when the V18 server is in dev mode | **No.** The code isn't served at all (`/dev/...`, `/api/status` and `/api/demo/replay` give 404) |
| Widget file | `sdk-web/widget/dist/v18.js` | `sdk-web/release/v18-<version>.min.js`, with its `integrity` hash |
| V18 server | `V18_SERVER`, default `http://localhost:8080` | `V18_SERVER`, **required**, must be `https://` (except `localhost`) |
| Site origin | `SITE_ORIGIN`, default `http://localhost:3000` | `SITE_ORIGIN`, **required** |

Both modes send security headers on every page: a Content Security Policy (scripts only from the
site itself plus a fresh nonce for each page, connections only to the site and the V18 server,
no framing), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and HSTS when
`SITE_ORIGIN` is `https://`. Cookies are `Secure` on HTTPS.

## Settings

| Variable | What it is |
|----------|------------|
| `DEMO_MODE` | `production` for production mode (`npm run start:prod` sets it for you) |
| `V18_SERVER` | The V18 server, for example `https://api.v18.example` (`V18_SERVER_URL` still works) |
| `SITE_ORIGIN` | This site's address exactly as visitors see it, for example `https://shop.example` |
| `PORT` or `DEMO_PORT` | Port to listen on (default 3000) |
| `TRUST_PROXY=1` | Set this behind a TLS proxy or load balancer |

## Run it without Docker

Build the web kit and the release (the release makes `v18-<version>.min.js`):

```bash
npm run release --prefix sdk-web
```

```bash
npm run build --prefix sdk-web/demo-site
```

Then start it. In Git Bash:

```bash
V18_SERVER=https://api.v18.example SITE_ORIGIN=https://shop.example npm run start:prod --prefix sdk-web/demo-site
```

In PowerShell:

```powershell
$env:V18_SERVER = 'https://api.v18.example'; $env:SITE_ORIGIN = 'https://shop.example'; npm run start:prod --prefix sdk-web/demo-site
```

To try production mode on your own computer, use `http://localhost:8080` and
`http://localhost:3000` instead. Check it is up at `/healthz` (it answers `{"ok":true,"mode":"production"}`).

## Run it with Docker

`sdk-web/demo-site/Dockerfile` builds `@v18/verify`, the widget and the demo site, makes the
versioned widget file, removes all dev and test code, and runs as the unprivileged `node` user
with a health check. Its build context is the `sdk-web/` folder. From the repository root:

```bash
docker build -f sdk-web/demo-site/Dockerfile -t v18-demo-site sdk-web
```

```bash
docker run -p 3000:3000 -e V18_SERVER=https://api.v18.example -e SITE_ORIGIN=https://shop.example -e TRUST_PROXY=1 v18-demo-site
```

**Not run here:** Docker is not installed on the build machine, so the image was never built.
What was checked instead (2026-11-23): every step of the Dockerfile was replayed by hand in a
scratch folder (same `npm ci`, builds, file removals and `npm ci --omit=dev`, same folder layout),
the replayed image started in production mode against the dev V18 server, its widget file was
byte-identical to `sdk-web/release/v18-1.0.0.min.js`, the page carried the matching `integrity`
hash, the dev tools gave 404, and a full age check (QR hand-off, with the V18 server's dev client
playing the phone) opened the 18+ page in the in-app browser with no console errors.

## Things to know

- **Put HTTPS in front.** The demo itself speaks plain HTTP; run it behind a TLS proxy and set
  `TRUST_PROXY=1`.
- **One instance.** The demo keeps visits and challenges in memory, so run one copy (or use
  sticky sessions). A real site would keep them in its session store (see INTEGRATION.md,
  section 3).
- **The V18 server must be reachable from visitors' browsers**, not only from the demo's server:
  the widget talks to it directly.
