// LIVE end-to-end run of phone wallet IDs (PROTOCOL.md 4c.5) against a RUNNING V18 server.
//
//   npm run live:wallet --prefix sdk-web -- [--server http://localhost:8080] [--iaca-dir <dir> | --iaca-cert <pem> --iaca-key <pem>]
//
// What it does, with real HTTP everywhere:
//   1. starts this demo site (dev mode) on a free port, pointed at the V18 server;
//   2. makes a TEST phone wallet whose TEST mdoc is sealed by the server's TEST document signer
//      (dev servers only; from server/assets/iaca/test/, or an IACA given with --iaca-cert/--iaca-key);
//   3. runs the widget's real state machine: site challenge -> pairing session ->
//      POST /v1/wallet/request -> TEST wallet answer -> POST /v1/wallet/verify -> poll -> ticket ->
//      the demo site checks the ticket with @v18/verify -> the 18+ page opens;
//   4. checks refusals: an under-18 TEST ID (UNDER_AGE) and an ID from an IACA the server does not trust.
// Needs the demo site and the widget built (npm run build --prefix sdk-web).
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { createServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const DEMO = resolve(HERE, '..');
const REPO = resolve(DEMO, '..', '..');
const { createDemoApp } = require(join(DEMO, 'dist', 'server.js'));
const { TestPhoneWallet } = require(join(DEMO, 'dist', 'wallet-test', 'test-phone-wallet.js'));
const { createTestIssuer } = require(join(DEMO, 'dist', 'wallet-test', 'test-iaca.js'));
const { WidgetController } = require(join(DEMO, '..', 'widget', 'dist', 'controller.js'));
const { PairingClient } = require(join(DEMO, '..', 'widget', 'dist', 'pairing-client.js'));

const arg = (n, d) => (process.argv.includes(n) ? process.argv[process.argv.indexOf(n) + 1] : d);
const SERVER = (arg('--server', process.env.V18_SERVER || 'http://localhost:8080')).replace(/\/+$/, '').replace(/\/v1$/, '');
const say = (t) => console.log(`[live-wallet] ${t}`);
const fail = (t, code = 1) => {
  console.error(`[live-wallet] ${t}`);
  process.exit(code);
};

/**
 * Finds the server's TEST issuer (dev only). Two layouts:
 *   - the server's own: server/assets/iaca/test/v18-test-iaca.pem + v18-test-ds.cert + v18-test-ds.key.json
 *     (a document signer certificate and its private key, issued under the TEST IACA);
 *   - --iaca-cert <pem> --iaca-key <pkcs8 pem>: an IACA and its key (a fresh document signer is made).
 */
const stripToPem = (t) => t.slice(t.indexOf('-----BEGIN'));
/** The country (C=) of the certificate that issued `pem`; the mDL's issuing_country must match it. */
const countryOf = (pem) =>
  new X509Certificate(stripToPem(pem)).issuer.split(/\n|,\s*/).map((p) => /^C=([A-Z]{2})$/.exec(p.trim())?.[1]).find(Boolean) ?? 'UT';
async function findTestIssuer() {
  const certFile = arg('--iaca-cert');
  const keyFile = arg('--iaca-key');
  if (certFile && keyFile) {
    return { from: certFile, issuer: await createTestIssuer({ iaca: { certPem: readFileSync(certFile, 'utf8'), keyPem: readFileSync(keyFile, 'utf8') } }) };
  }
  const dir = resolve(arg('--iaca-dir', join(REPO, 'server', 'assets', 'iaca', 'test')));
  const f = { iaca: join(dir, 'v18-test-iaca.pem'), ds: join(dir, 'v18-test-ds.cert'), key: join(dir, 'v18-test-ds.key.json') };
  if (![f.iaca, f.ds, f.key].every((x) => existsSync(x))) return null;
  const dsPem = stripToPem(readFileSync(f.ds, 'utf8'));
  const { _note, ...dsPrivateJwk } = JSON.parse(readFileSync(f.key, 'utf8'));
  return { from: f.ds, issuer: { iacaPem: stripToPem(readFileSync(f.iaca, 'utf8')), dsPem, dsPrivateJwk, country: countryOf(dsPem) } };
}

const freePort = () => new Promise((r) => { const s = createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

function browser(origin) {
  let cookie = '';
  return async (input, init = {}) => {
    const url = String(input).startsWith('http') ? String(input) : origin + String(input);
    const headers = new Headers(init.headers ?? {});
    if (url.startsWith(origin) && cookie) headers.set('cookie', cookie);
    if ((init.method ?? 'GET').toUpperCase() !== 'GET' || !url.startsWith(origin)) headers.set('origin', origin);
    const res = await fetch(url, { ...init, headers, redirect: 'manual' });
    if (url.startsWith(origin)) for (const c of res.headers.getSetCookie?.() ?? []) cookie = c.split(';')[0];
    return res;
  };
}

async function runWidget(origin, wallet) {
  const f = browser(origin);
  const tickets = [];
  const c = new WidgetController(
    { origin, minAge: 18, serverUrl: SERVER, challengeUrl: `${origin}/v18/challenge`, verifyUrl: `${origin}/v18/verify`, walletSupport: true, onSuccess: (t) => tickets.push(t) },
    { fetch: f, pairing: new PairingClient(SERVER, { fetch: f, pollMs: 300 }), openDeepLink: () => {}, getTestWallet: () => null, credentials: wallet.credentialsFor(origin), hasUserActivation: () => true }
  );
  const views = [];
  c.subscribe((s, r) => { if (r === 'view' && views[views.length - 1] !== s.view) views.push(s.view); });
  await c.loadServerInfo();
  if (!c.walletOffered()) { c.dispose(); return { offered: false }; }
  await c.chooseWallet();
  const t0 = Date.now();
  while (!['done', 'wallet_failed', 'site_refused', 'retry', 'expired'].includes(c.state.view) && Date.now() - t0 < 20000) await new Promise((r) => setTimeout(r, 100));
  const out = { offered: true, view: c.state.view, code: c.state.errorCode, error: c.state.error, views, tickets, members: (await f('/adult-content')).status };
  c.dispose();
  return out;
}

// ---- 0. Is the server there, and does it do wallets?
let health;
try {
  health = await (await fetch(`${SERVER}/v1/health`)).json();
} catch (e) {
  fail(`BLOCKED: no V18 server at ${SERVER} (${e.message}). Start it: npm run dev --prefix server`, 3);
}
say(`server ${SERVER}: version ${health.version}, devMode ${health.devMode}, methods ${JSON.stringify(health.methods)}`);
const probe = await fetch(`${SERVER}/v1/wallet/request`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
if (probe.status === 404 && !(await probe.text()).includes('SESSION')) {
  fail(`BLOCKED: ${SERVER} has no POST /v1/wallet/request yet (404). The server's wallet endpoints (PROTOCOL.md 4c.5) are not built or not running.`, 3);
}
if (health.methods?.mdoc_wallet !== 'ready') fail(`BLOCKED: /v1/health says methods.mdoc_wallet is ${JSON.stringify(health.methods?.mdoc_wallet)}, so the widget hides the wallet option.`, 3);
if (health.devMode !== true) fail('This run needs a dev-mode server (it uses a TEST IACA).', 3);
const found = await findTestIssuer();
if (!found) fail('BLOCKED: no TEST issuer in server/assets/iaca/test/ (the dev server makes it when it starts). Or pass --iaca-cert and --iaca-key.', 3);
say(`TEST issuer: ${found.from} (country ${found.issuer.country})`);

// ---- 1. The demo site, pointed at the live server.
const port = await freePort();
const origin = `http://localhost:${port}`;
const site = createDemoApp({ port, siteOrigin: origin, v18ServerUrl: SERVER }).listen(port, 'localhost');
say(`demo site on ${origin}`);

let failed = 0;
const check = (ok, text) => { console.log(`${ok ? '  PASS' : '  FAIL'}  ${text}`); if (!ok) failed++; };
try {
  const issuer = found.issuer;

  const adult = await runWidget(origin, await TestPhoneWallet.create({ issuer }));
  check(adult.offered, 'the widget offers "Use a phone wallet ID"');
  check(adult.view === 'done', `adult TEST mDL: widget finished (${adult.views?.join(' -> ')}${adult.code ? `; ${adult.code}: ${adult.error}` : ''})`);
  check(adult.tickets?.length === 1 && /^v18(mock)?-age18-\d{8}\./.test(adult.tickets[0]), `a normal ticket from the server's age-18 key (${adult.tickets?.[0]?.split('.')[0]})`);
  check(adult.members === 200, 'the demo site accepted the ticket and opened the 18+ page');

  const pid = await runWidget(origin, await TestPhoneWallet.create({ issuer, doc: 'pid' }));
  check(pid.view === 'done', `adult TEST EU PID: widget finished${pid.code ? ` (${pid.code}: ${pid.error})` : ''}`);

  const child = await runWidget(origin, await TestPhoneWallet.create({ issuer, ageOver18: false }));
  check(child.view === 'wallet_failed' && child.members === 302, `under-18 TEST ID refused (${child.code}: ${child.error})`);

  const stranger = await runWidget(origin, await TestPhoneWallet.create({ issuer: await createTestIssuer({ label: 'Untrusted TEST IACA' }) }));
  check(stranger.view === 'wallet_failed' && stranger.members === 302, `ID from an untrusted IACA refused (${stranger.code}: ${stranger.error})`);

  const phish = await runWidget(origin, await TestPhoneWallet.create({ issuer, pretendOrigin: 'https://evil.test' }));
  check(phish.view === 'wallet_failed' && phish.members === 302, `answer made for another site refused (${phish.code}: ${phish.error})`);
} finally {
  site.close();
}
say(failed === 0 ? 'ALL PASSED' : `${failed} check(s) FAILED`);
process.exit(failed === 0 ? 0 : 1);
