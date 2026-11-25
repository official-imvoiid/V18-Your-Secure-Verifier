// LIVE login-connector test (PROTOCOL 4d.4) through the SYSTEM BROWSER.   npm run test:live-connector
//
// The shared dev server on :8080 has no connector credentials (connectors are hidden unless set),
// so this test starts its OWN V18 server on 127.0.0.1:8091, in this process, from server/src
// (the real server code, in-memory database, temp data folder), with the REAL FranceConnect
// connector from @v18/connectors pointed at the local oidc-provider mock from connectors/
// (set up like FranceConnect). This is the same setup as server/src/tests/connect.test.ts.
// The :8080 server is not touched.
//
// Then the REAL app (dist/, debug build) runs with its own profile and --v18-test-server, picks
// France > FranceConnect, and opens the login page with the real shell.openExternal, so YOUR
// DEFAULT WEB BROWSER opens a tab. The mock signs a made-up adult in by itself and sends the
// browser back to V18. If the browser asks "Open Electron?", allowing it hands the v18://connect
// link to the app; if nobody answers, the app finishes through its session poll instead.
// While the test runs, v18:// points at this test app (put back afterwards). If "Open" is clicked
// only after the test has ended, Windows starts your normal V18 instead, which refuses the link
// because it wasn't waiting for a login (seen on 2026-11-24: nothing changed).
// Finally the new card makes a ticket for a site, through a second launch with a v18://verify link.

import electronPath from 'electron';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import type { Server } from 'node:http';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { _electron as electron, type ElectronApplication, type Page } from 'playwright-core';
import { verifyTicketString } from '../../src/shared/ticket.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const repo = path.resolve(root, '..');
const shots = path.join(repo, 'docs', 'windows', 'screenshots');
const serverDir = path.join(repo, 'server');
const fromServer = createRequire(path.join(serverDir, 'package.json'));
const PORT = 8091;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const REDIRECT = `${ORIGIN}/v1/connect/franceconnect/callback`;
const SECRET = 'live-test-franceconnect-secret-0123456789abcdef';
const PROTO_CMD = 'HKCU\\Software\\Classes\\v18\\shell\\open\\command';
const log = (...a: unknown[]) => console.log('   [connector]', ...a);

function regDefault(key: string): string | null {
  const r = spawnSync('reg', ['query', key, '/ve'], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  return /REG_SZ\s+(.*)$/m.exec(r.stdout)?.[1]?.trim() ?? '';
}
function setProtocol(command: string): void {
  spawnSync('reg', ['add', 'HKCU\\Software\\Classes\\v18', '/ve', '/d', 'URL:V18 age check', '/f']);
  spawnSync('reg', ['add', 'HKCU\\Software\\Classes\\v18', '/v', 'URL Protocol', '/d', '', '/f']);
  spawnSync('reg', ['add', PROTO_CMD, '/ve', '/d', command, '/f']);
}

describe('FranceConnect login through the system browser (own server on :8091, mock provider)', { skip: process.platform !== 'win32' ? 'Windows only' : false }, () => {
  let mock: { discoveryUrl: string; account: unknown; logins: number; close(): Promise<void> };
  let v18: { app: { listen(p: number, h: string, cb: () => void): Server }; close(): Promise<void> };
  let http: Server;
  let app: ElectronApplication;
  let page: Page;
  let profile: string;
  let dataDir: string;
  let prevProtocol: string | null = null;
  let args: string[] = [];

  before(async () => {
    // 1. The mock FranceConnect (oidc-provider), from the connectors/ test helpers.
    const mocks = fromServer('@v18/connectors/dist/tests/helpers/oidc-mock.js') as { startOidcMock(p: unknown): Promise<typeof mock> };
    mock = await mocks.startOidcMock({
      signingAlg: 'ES256',
      scopes: ['openid', 'birthdate', 'profile'],
      claims: { openid: ['sub'], birthdate: ['birthdate'], profile: ['given_name', 'family_name', 'gender', 'birthdate'] },
      client: {
        client_id: 'v18-franceconnect',
        client_secret: SECRET,
        token_endpoint_auth_method: 'client_secret_post',
        redirect_uris: [REDIRECT],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        id_token_signed_response_alg: 'ES256',
        userinfo_signed_response_alg: 'ES256',
      },
    });
    // A made-up adult in FranceConnect's own "pivot identity" format (TEST data).
    mock.account = { sub: 'f'.repeat(64) + 'v1', claims: { given_name: 'Test', family_name: 'PERSONNE', gender: 'female', birthdate: '1980-05-17', birthplace: '75107', birthcountry: '99100' } };

    // 2. A V18 server from server/src with the real connector registry (test-only http switch).
    dataDir = mkdtempSync(path.join(tmpdir(), 'v18-live-connector-server-'));
    const env = {
      V18_DEV_MODE: '1',
      V18_DATA_DIR: dataDir,
      V18_NULLIFIER_SECRET: 'live-test-nullifier-secret-0123456789abcdef',
      V18_CONNECTOR_FRANCECONNECT_CLIENT_ID: 'v18-franceconnect',
      V18_CONNECTOR_FRANCECONNECT_CLIENT_SECRET: SECRET,
      V18_CONNECTOR_FRANCECONNECT_ISSUER: mock.discoveryUrl,
    };
    const { createRegistry } = fromServer('@v18/connectors') as { createRegistry(env: unknown, o: unknown): unknown };
    const { createV18 } = (await import(pathToFileURL(path.join(serverDir, 'src', 'app.ts')).href)) as {
      createV18(o: unknown): Promise<typeof v18>;
    };
    v18 = await createV18({
      env,
      aadhaarVerifier: null,
      connectorRegistry: createRegistry(env, { allowInsecureLocalhost: true }),
      config: { devMode: true, dbPath: ':memory:', publicUrl: ORIGIN },
    });
    http = await new Promise<Server>((resolve) => {
      const s = v18.app.listen(PORT, '127.0.0.1', () => resolve(s));
    });
    const h = (await (await fetch(`${ORIGIN}/v1/health`)).json()) as { connectors: string[]; version: string };
    log(`own server ${h.version} on ${ORIGIN}, connectors: ${JSON.stringify(h.connectors)}`);
    assert.deepEqual(h.connectors, ['franceconnect']);

    // 3. The real app, its own profile; v18:// points at it for the duration of the test.
    profile = mkdtempSync(path.join(tmpdir(), 'v18-live-connector-app-'));
    args = [root, '--v18-no-protocol', `--v18-profile=${profile}`, `--v18-test-server=${ORIGIN}`, '--v18-test-software-key'];
    prevProtocol = regDefault(PROTO_CMD);
    setProtocol([electronPath as unknown as string, ...args].map((a) => `"${a}"`).join(' ') + ' "%1"');
    app = await electron.launch({ executablePath: electronPath as unknown as string, args, cwd: root });
    page = await app.firstWindow();
    await page.waitForSelector('#app .win', { timeout: 15000 });
    // Count the links Windows hands over (a second launch), to tell which path finished the login.
    await app.evaluate(({ app: a }) => {
      (globalThis as any).__links = [];
      a.on('second-instance', (_e, argv) => (globalThis as any).__links.push(argv.find((x) => x.startsWith('v18:')) ?? ''));
    });
  });

  after(async () => {
    await app?.evaluate(({ app: a }) => a.exit(0)).catch(() => undefined);
    await app?.close().catch(() => undefined);
    if (prevProtocol) setProtocol(prevProtocol);
    else spawnSync('reg', ['delete', 'HKCU\\Software\\Classes\\v18', '/f']);
    await new Promise<void>((r) => (http ? http.close(() => r()) : r()));
    await v18?.close().catch(() => undefined);
    await mock?.close().catch(() => undefined);
    for (const d of [profile, dataDir]) if (d) rmSync(d, { recursive: true, force: true });
  });

  it('France > FranceConnect: the system browser signs in, and the app saves a connector card', async () => {
    await page.click('button:has-text("Continue")');
    await page.click('nav >> text=Get age card');
    await page.waitForSelector('button.cbtn:has-text("France")', { timeout: 15000 });
    await page.click('button.cbtn:has-text("France")');
    await page.click('button:has-text("Continue")');
    await page.waitForSelector('text=On this PC');
    assert.ok(await page.isVisible('text=ID card (chip)'), 'both chip documents are listed');
    await page.screenshot({ path: path.join(shots, '25-live-connector-methods-france.png') });
    const t0 = Date.now();
    await page.click('button.opt:has-text("FranceConnect")');
    await page.waitForSelector('text=Sign in with FranceConnect in your browser', { timeout: 15000 });
    await page.screenshot({ path: path.join(shots, '26-live-connector-waiting.png') });
    log('the app opened the login page in the default web browser; waiting for the card...');
    await page.waitForSelector('text=Your age card is saved', { timeout: 120000 });
    const secs = ((Date.now() - t0) / 1000).toFixed(1);
    await page.screenshot({ path: path.join(shots, '27-live-connector-card-saved.png') });
    const links = (await app.evaluate(() => (globalThis as any).__links)) as string[];
    const view = await page.evaluate(() => (window as any).v18.invoke('v18:get-view'));
    log(`card saved after ${secs} s: method ${view.card.method} ("${view.card.methodLabel}"), provider logins: ${mock.logins}`);
    log(links.some((l) => l.startsWith('v18://connect'))
      ? 'the browser handed v18://connect back to the app (second launch)'
      : 'no v18://connect hand-over arrived (the browser prompt was not answered): the session poll finished the login');
    assert.equal(view.card.method, 'connector:franceconnect');
    assert.equal(view.card.methodLabel, 'FranceConnect');
    assert.ok(mock.logins >= 1, 'the provider really ran a login');
  });

  it('the connector card makes a ticket a website can verify', async () => {
    const res = await fetch(`${ORIGIN}/v1/pairing/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://localhost:3000' },
      body: JSON.stringify({ origin: 'http://localhost:3000', challenge: 'live-connector-ticket-0001', minAge: 18, ttlSeconds: 120 }),
    });
    assert.equal(res.status, 201);
    const s = (await res.json()) as { sessionId: string; deepLink: string };
    const askWindow = app.waitForEvent('window');
    spawn(electronPath as unknown as string, [...args, s.deepLink], { cwd: root, stdio: 'ignore' });
    const ask = await askWindow;
    await ask.waitForSelector('text=Are you 18+?', { timeout: 15000 });
    await ask.click('button:has-text("Send 18+ ticket")');
    await ask.waitForSelector('text=Ticket sent', { timeout: 15000 });
    const poll = (await (await fetch(`${ORIGIN}/v1/pairing/${s.sessionId}`)).json()) as { ticket?: string };
    assert.ok(poll.ticket);
    const jwks = (await (await fetch(`${ORIGIN}/v1/keys`)).json()) as { keys: { kid: string; kty: 'RSA'; n: string; e: string }[] };
    const key = jwks.keys.find((k) => k.kid === poll.ticket!.split('.')[0])!;
    assert.equal((await verifyTicketString(poll.ticket!, key)).ok, true);
    log('ticket from the FranceConnect card verified with the JWKS');
  });
});
