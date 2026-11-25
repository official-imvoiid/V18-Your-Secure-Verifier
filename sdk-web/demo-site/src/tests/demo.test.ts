/**
 * Demo-site tests. Everything here is real code talking over real HTTP, except the V18 server,
 * which is the MOCK in src/mock-v18 (TEST ONLY), so these tests run on their own. The live runs
 * against the real server are in scripts/ (see docs/web/WALKTHROUGH.md).
 *
 * Chain under test: widget state machine -> mock V18 (pairing, cards, blind signing)
 *   -> browser test wallet core (WebCrypto ES256 + @cloudflare/blindrsa-ts, run in Node)
 *   -> demo site server (/v18/challenge, /v18/verify) -> @v18/verify.
 */
import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import type { Server } from 'node:http';
import { createDemoApp } from '../server.js';
import { startMockV18, MockV18 } from '../mock-v18/server.js';
import { TestWalletCore, MemoryStorage, CHILD_TEST_BIRTH_DATE, V18ApiError } from '../client/wallet-core.js';
import { browser, freePort, widget } from './helpers.js';

const { WidgetController, PairingClient } = widget();

describe('demo site + browser test wallet + mock V18 (end to end)', () => {
  let v18: MockV18;
  let site: Server;
  let origin: string;

  before(async () => {
    v18 = await startMockV18(0);
    const port = await freePort();
    origin = `http://127.0.0.1:${port}`;
    const app = createDemoApp({ port, siteOrigin: origin, v18ServerUrl: v18.url });
    site = await new Promise<Server>((r) => {
      const s = app.listen(port, '127.0.0.1', () => r(s));
    });
  });
  after(async () => {
    site.close();
    await v18.close();
  });

  const wallet = () => new TestWalletCore({ serverUrl: v18.url, storage: new MemoryStorage() });

  it('the gate page is public, the 18+ page redirects without a session', async () => {
    const b = browser(origin);
    assert.equal((await b.fetch('/')).status, 200);
    const r = await b.fetch('/adult-content');
    assert.equal(r.status, 302);
    assert.equal(r.headers.get('location'), '/');
  });

  it('serves the widget bundle and the dev test wallet bundle', async () => {
    const b = browser(origin);
    const w = await b.fetch('/widget/v18.js');
    assert.equal(w.status, 200);
    assert.ok((await w.text()).includes('registerTestWallet'));
    const t = await b.fetch('/dev/test-wallet.js');
    assert.equal(t.status, 200);
    assert.ok((await t.text()).includes('Browser test wallet (dev only)'));
  });

  it('full protocol flow: site challenge -> test_dev card -> blind ticket -> site verifies -> session cookie', async () => {
    const b = browser(origin);
    const { challenge } = await (await b.post('/v18/challenge')).json();
    assert.match(challenge, /^[0-9a-f]{64}$/);
    const w = wallet();
    const ticket = await w.makeTicket({ origin, challenge, minAge: 18 });
    assert.match(ticket, /^v18mock-age18-\d{8}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

    const res = await b.post('/v18/verify', { ticket });
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(body.ok, true);
    assert.equal(body.minAge, 18);

    assert.equal((await b.fetch('/adult-content')).status, 200);
    const status = await (await b.fetch('/api/status')).json();
    assert.equal(status.verified, true);
    assert.equal(status.v18.devMode, true);

    // The card is reused for the next ticket (no second card).
    const before = v18.stats.cardsIssued;
    const { challenge: c2 } = await (await b.post('/v18/challenge')).json();
    await w.makeTicket({ origin, challenge: c2, minAge: 18 });
    assert.equal(v18.stats.cardsIssued, before);
  });

  it('replay-attack demo: same ticket again is refused three ways, and nothing unlocks', async () => {
    const b = browser(origin);
    const { challenge } = await (await b.post('/v18/challenge')).json();
    const ticket = await wallet().makeTicket({ origin, challenge, minAge: 18 });
    assert.equal((await b.post('/v18/verify', { ticket })).status, 200);

    const again = await b.post('/v18/verify', { ticket });
    assert.equal(again.status, 403);
    assert.equal((await again.json()).code, 'CHALLENGE_MISMATCH');

    const demo = await (await b.post('/api/demo/replay')).json();
    assert.deepEqual(demo.attacks.map((a: any) => a.result.code), ['CHALLENGE_MISMATCH', 'REPLAY_DETECTED', 'INVALID_SIGNATURE']);
    assert.equal(demo.unlockedAnything, false);

    // Another visitor (another cookie) cannot use the ticket either.
    const thief = browser(origin);
    await thief.post('/v18/challenge');
    const stolen = await thief.post('/v18/verify', { ticket });
    assert.equal(stolen.status, 403);
    assert.equal((await thief.fetch('/adult-content')).status, 302);
  });

  it('a ticket made for another site is refused (ORIGIN_MISMATCH)', async () => {
    const b = browser(origin);
    const { challenge } = await (await b.post('/v18/challenge')).json();
    const ticket = await wallet().makeTicket({ origin: 'https://evil.test', challenge, minAge: 18 });
    const r = await b.post('/v18/verify', { ticket });
    assert.equal(r.status, 403);
    assert.equal((await r.json()).code, 'ORIGIN_MISMATCH');
  });

  it('garbage and missing tickets are refused', async () => {
    const b = browser(origin);
    await b.post('/v18/challenge');
    for (const t of [undefined, '', 'a.b.c', 'x'.repeat(20000)]) {
      const r = await b.post('/v18/verify', { ticket: t });
      assert.ok(r.status === 403 || r.status === 413, String(r.status));
    }
  });

  it('cross-site POSTs are refused (Origin check)', async () => {
    const evil = browser(origin, 'https://evil.test');
    const r = await evil.post('/v18/challenge');
    assert.equal(r.status, 403);
    assert.equal((await r.json()).code, 'BAD_ORIGIN');
  });

  it('lock clears the session', async () => {
    const b = browser(origin);
    const { challenge } = await (await b.post('/v18/challenge')).json();
    assert.equal((await b.post('/v18/verify', { ticket: await wallet().makeTicket({ origin, challenge, minAge: 18 }) })).status, 200);
    assert.equal((await b.fetch('/adult-content')).status, 200);
    await b.post('/api/lock');
    assert.equal((await b.fetch('/adult-content')).status, 302);
  });

  it('test wallet: under-18 test birth date gets no card; no card means no ticket (CARD_REQUIRED)', async () => {
    const child = new TestWalletCore({ serverUrl: v18.url, birthDate: CHILD_TEST_BIRTH_DATE });
    await assert.rejects(child.ensureCard(), (e: any) => e instanceof V18ApiError && e.code === 'UNDER_AGE');
    const res = await fetch(`${v18.url}/v1/ticket/blind-sign`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ blindedMessage: 'AAAA' }),
    });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).code, 'CARD_REQUIRED');
  });

  it('test wallet: deleting the card revokes it on the server', async () => {
    const w = wallet();
    const card = await w.ensureCard();
    assert.equal(await w.deleteCard(), true);
    const st = await (await fetch(`${v18.url}/v1/card/${card.cardId}/status`)).json();
    assert.equal(st.status, 'revoked');
    assert.equal(await w.currentCard(), null);
  });

  it('widget + QR hand-off: the "simulate phone" test wallet drives the REAL flow to an unlocked session', async () => {
    const b = browser(origin);
    const w = wallet();
    const progress: string[] = [];
    const testWallet = {
      label: 'Browser test wallet (dev only)',
      simulatePhone: (s: any) => w.simulatePhone({ ...s, onProgress: (m: string) => progress.push(m) }),
    };
    const pairing = new PairingClient(v18.url, { pollMs: 50 });
    const done: string[] = [];
    const c = new WidgetController(
      {
        origin,
        minAge: 18,
        serverUrl: v18.url,
        challengeUrl: `${origin}/v18/challenge`,
        verifyUrl: `${origin}/v18/verify`,
        walletSupport: false,
        onSuccess: (t: string) => done.push(t),
      },
      { fetch: b.fetch, pairing, openDeepLink: () => {}, getTestWallet: () => testWallet }
    );
    await c.loadServerInfo();
    assert.equal(c.state.devMode, true);
    await c.choosePhone();
    assert.equal(c.state.view, 'qr_waiting');
    assert.ok(c.state.qrData.includes(`server=${encodeURIComponent(v18.url)}`));
    assert.equal(c.canSimulate(), true);

    await c.simulateWithTestWallet();
    assert.equal(c.state.testWallet.failed, false, c.state.testWallet.message);
    const t0 = Date.now();
    while (c.state.view !== 'done' && Date.now() - t0 < 5000) await new Promise((r) => setTimeout(r, 20));
    assert.equal(c.state.view, 'done');
    assert.equal(done.length, 1);
    assert.ok(progress.length >= 2);
    assert.equal((await b.fetch('/adult-content')).status, 200, 'the site session is unlocked');
    c.dispose();
  });

  it('mock V18 pairing hands the ticket over only once', async () => {
    const created = await (await fetch(`${v18.url}/v1/pairing/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin },
      body: JSON.stringify({ origin, challenge: 'c'.repeat(64), minAge: 18, ttlSeconds: 120 }),
    })).json();
    await fetch(`${v18.url}/v1/pairing/${created.sessionId}/submit`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ticket: 'k.a.b' }) });
    const p1 = await (await fetch(`${v18.url}/v1/pairing/${created.sessionId}`)).json();
    const p2 = await (await fetch(`${v18.url}/v1/pairing/${created.sessionId}`)).json();
    assert.equal(p1.ticket, 'k.a.b');
    assert.equal(p2.ticket, undefined);
    const bad = await fetch(`${v18.url}/v1/pairing/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://evil.test' },
      body: JSON.stringify({ origin, challenge: 'c'.repeat(64), minAge: 18 }),
    });
    assert.equal(bad.status, 403, 'Origin header must equal origin');
  });
});
