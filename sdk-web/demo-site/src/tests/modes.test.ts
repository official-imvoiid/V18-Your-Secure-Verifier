/**
 * The demo site's two modes. Dev mode has the developer tools; production mode has none of them
 * and loads the versioned release widget with its SRI hash.
 */
import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Server } from 'node:http';
import { applyMode, configFromEnv, createDemoApp } from '../server.js';
import { startMockV18, MockV18 } from '../mock-v18/server.js';
import { TestWalletCore, MemoryStorage } from '../client/wallet-core.js';
import { browser, freePort } from './helpers.js';

const WIDGET_DIST = path.resolve(__dirname, '..', '..', '..', 'widget', 'dist');
const VERSION = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', '..', '..', 'widget', 'package.json'), 'utf8')).version;
const sri = (file: string) => `sha384-${crypto.createHash('sha384').update(fs.readFileSync(file)).digest('base64')}`;
const DEV_WORDS = /test wallet|Developer tools|Replay-attack|\/dev\/|Crypto inspector|dev only|TEST MODE/i;

async function listen(app: ReturnType<typeof createDemoApp>, port: number): Promise<Server> {
  return new Promise((r) => {
    const s = app.listen(port, '127.0.0.1', () => r(s));
  });
}

describe('demo site modes', () => {
  let v18: MockV18;
  let devSite: Server;
  let prodSite: Server;
  let devOrigin: string;
  let prodOrigin: string;
  let releaseDir: string;

  before(async () => {
    v18 = await startMockV18(0);
    // A release folder like `npm run release` makes (here: a copy of the dev bundle).
    releaseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-release-'));
    fs.copyFileSync(path.join(WIDGET_DIST, 'v18.js'), path.join(releaseDir, `v18-${VERSION}.min.js`));
    const p1 = await freePort();
    devOrigin = `http://127.0.0.1:${p1}`;
    devSite = await listen(createDemoApp({ port: p1, siteOrigin: devOrigin, v18ServerUrl: v18.url }), p1);
    const p2 = await freePort();
    prodOrigin = `http://127.0.0.1:${p2}`;
    prodSite = await listen(createDemoApp({ port: p2, siteOrigin: prodOrigin, v18ServerUrl: v18.url, mode: 'production', releaseDir }), p2);
  });
  after(async () => {
    devSite.close();
    prodSite.close();
    await v18.close();
    fs.rmSync(releaseDir, { recursive: true, force: true });
  });

  it('production: no test wallet, no developer tools, no replay demo, no status API', async () => {
    const b = browser(prodOrigin);
    const page = await (await b.fetch('/')).text();
    assert.doesNotMatch(page, DEV_WORDS);
    assert.equal(page.includes('<!--DEV'), false);
    for (const p of ['/dev/test-wallet.js', '/api/status', '/index.html']) assert.equal((await b.fetch(p)).status, 404, p);
    assert.equal((await b.post('/api/demo/replay')).status, 404);
  });

  it('production: the page loads the versioned release widget with its SRI hash (2-line embed)', async () => {
    const b = browser(prodOrigin);
    const page = await (await b.fetch('/')).text();
    const file = path.join(releaseDir, `v18-${VERSION}.min.js`);
    const tag = `<script src="/widget/v18-${VERSION}.min.js" integrity="${sri(file)}" crossorigin="anonymous" data-v18-server="${v18.url}"></script>`;
    assert.ok(page.includes(tag), 'script tag with integrity');
    const js = await b.fetch(`/widget/v18-${VERSION}.min.js`);
    assert.equal(js.status, 200);
    assert.match(js.headers.get('cache-control') ?? '', /immutable/);
    assert.equal(sri(file), `sha384-${crypto.createHash('sha384').update(Buffer.from(await js.arrayBuffer())).digest('base64')}`, 'served bytes match the hash');
  });

  it('production: a real ticket still opens the 18+ page, and the members page has no replay demo', async () => {
    const b = browser(prodOrigin);
    const { challenge } = await (await b.post('/v18/challenge')).json();
    const ticket = await new TestWalletCore({ serverUrl: v18.url, storage: new MemoryStorage() }).makeTicket({ origin: prodOrigin, challenge, minAge: 18 });
    assert.equal((await b.post('/v18/verify', { ticket })).status, 200);
    const members = await b.fetch('/adult-content');
    assert.equal(members.status, 200);
    const html = await members.text();
    assert.doesNotMatch(html, DEV_WORDS);
    assert.ok(html.includes('Lock the site again'));
  });

  it('both modes: strict security headers, and every inline script carries this response\'s nonce', async () => {
    for (const origin of [devOrigin, prodOrigin]) {
      const res = await browser(origin).fetch('/');
      const csp = res.headers.get('content-security-policy') ?? '';
      const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
      assert.ok(nonce, origin);
      assert.match(csp, /default-src 'self'/);
      assert.match(csp, /frame-ancestors 'none'/);
      assert.ok(csp.includes(`connect-src 'self' ${new URL(v18.url).origin}`));
      assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
      const html = await res.text();
      const inline = html.match(/<script(?![^>]*\bsrc=)[^>]*>/g) ?? [];
      for (const tag of inline) assert.ok(tag.includes(`nonce="${nonce}"`), tag);
    }
  });

  it('dev: developer tools are in the page (hidden until V18 says dev mode), and the dev widget has a matching SRI hash', async () => {
    const b = browser(devOrigin);
    const page = await (await b.fetch('/')).text();
    assert.ok(page.includes('id="devTools" hidden'));
    assert.ok(page.includes('/dev/test-wallet.js'));
    assert.ok(page.includes(`integrity="${sri(path.join(WIDGET_DIST, 'v18.js'))}"`));
    assert.equal((await b.fetch('/dev/test-wallet.js')).status, 200);
    const status = await (await b.fetch('/api/status')).json();
    assert.equal(status.mode, 'dev');
    assert.equal(status.v18.wallet, 'ready');
  });

  it('settings: production needs V18_SERVER (https) and SITE_ORIGIN; dev has safe defaults', () => {
    assert.throws(() => configFromEnv({ DEMO_MODE: 'production', SITE_ORIGIN: 'https://shop.example' }), /V18_SERVER/);
    assert.throws(() => configFromEnv({ DEMO_MODE: 'production', V18_SERVER: 'https://api.v18.example' }), /SITE_ORIGIN/);
    assert.throws(() => configFromEnv({ DEMO_MODE: 'production', V18_SERVER: 'http://api.v18.example', SITE_ORIGIN: 'https://shop.example' }), /https/);
    const prod = configFromEnv({ DEMO_MODE: 'production', V18_SERVER: 'https://api.v18.example/v1/', SITE_ORIGIN: 'https://shop.example', PORT: '8081' });
    assert.deepEqual([prod.mode, prod.v18ServerUrl, prod.siteOrigin, prod.port], ['production', 'https://api.v18.example', 'https://shop.example', 8081]);
    const dev = configFromEnv({});
    assert.deepEqual([dev.mode, dev.v18ServerUrl, dev.siteOrigin, dev.port], ['dev', 'http://localhost:8080', 'http://localhost:3000', 3000]);
    assert.equal(configFromEnv({ V18_SERVER_URL: 'http://localhost:9090' }).v18ServerUrl, 'http://localhost:9090', 'old variable name still works');
    assert.throws(() => createDemoApp({ port: 1, siteOrigin: 'https://x.example', v18ServerUrl: 'https://api.v18.example', mode: 'production', releaseDir: os.tmpdir() }), /release widget/);
  });

  it('applyMode strips dev blocks only in production', () => {
    const html = 'a<!--DEV-->secret<!--/DEV-->b';
    assert.equal(applyMode(html, 'production'), 'ab');
    assert.equal(applyMode(html, 'dev'), 'asecretb');
  });
});
