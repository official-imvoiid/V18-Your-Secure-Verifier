/**
 * Phone wallet IDs (PROTOCOL.md 4c.5, `mdoc_wallet`), end to end over real HTTP:
 *
 *   widget state machine -> demo site /v18/challenge -> mock V18 pairing session
 *     -> POST /v1/wallet/request -> TEST phone wallet (a TEST mdoc sealed by a TEST IACA,
 *        device-signed, encrypted to V18's key) -> POST /v1/wallet/verify (@auth0/mdl checks)
 *     -> ticket on the pairing session -> widget poll -> demo site /v18/verify (@v18/verify).
 *
 * The V18 server here is the MOCK (TEST ONLY). The live run against the real server is
 * scripts/live-wallet-e2e.mjs.
 */
import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import type { Server } from 'node:http';
import { parse } from '@auth0/mdl';
import { createDemoApp } from '../server.js';
import { startMockV18, MockV18 } from '../mock-v18/server.js';
import { TestPhoneWallet } from '../wallet-test/test-phone-wallet.js';
import { createTestIssuer, TestIssuer } from '../wallet-test/test-iaca.js';
import { AGE_DOCS } from '../wallet-test/mdoc-common.js';
import { browser, freePort, until, widget } from './helpers.js';

const { WidgetController, PairingClient } = widget();

describe('phone wallet IDs: widget + TEST wallet + mock V18 + demo site', () => {
  let v18: MockV18;
  let site: Server;
  let origin: string;
  let issuer: TestIssuer;

  before(async () => {
    v18 = await startMockV18(0);
    issuer = v18.walletIssuer!;
    const port = await freePort();
    origin = `http://127.0.0.1:${port}`;
    site = await new Promise<Server>((r) => {
      const s = createDemoApp({ port, siteOrigin: origin, v18ServerUrl: v18.url }).listen(port, '127.0.0.1', () => r(s));
    });
  });
  after(async () => {
    site.close();
    await v18.close();
  });

  /** Starts a pairing session the way the widget does, and returns V18's wallet request. */
  async function startSession(b: ReturnType<typeof browser>) {
    const { challenge } = await (await b.post('/v18/challenge')).json();
    const created = await (await b.fetch(`${v18.url}/v1/pairing/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ origin, challenge, minAge: 18, ttlSeconds: 120 }),
    })).json();
    const reqRes = await b.fetch(`${v18.url}/v1/wallet/request`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionId: created.sessionId }),
    });
    assert.equal(reqRes.status, 200);
    const reply = await reqRes.json();
    return { sessionId: created.sessionId as string, requests: reply.digital.requests, challenge };
  }

  const verifyAnswer = (b: ReturnType<typeof browser>, sessionId: string, response: unknown) =>
    b.fetch(`${v18.url}/v1/wallet/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionId, response }),
    });

  function makeWidget(b: ReturnType<typeof browser>, credentials: unknown, done: string[]) {
    return new WidgetController(
      {
        origin,
        minAge: 18,
        serverUrl: v18.url,
        challengeUrl: `${origin}/v18/challenge`,
        verifyUrl: `${origin}/v18/verify`,
        walletSupport: true,
        onSuccess: (t: string) => done.push(t),
      },
      {
        fetch: b.fetch,
        pairing: new PairingClient(v18.url, { fetch: b.fetch, pollMs: 50 }),
        openDeepLink: () => {},
        getTestWallet: () => null,
        credentials,
        hasUserActivation: () => true,
      }
    );
  }

  it('the request asks ONLY for age_over_18 (mDL or EU PID), with a fresh nonce and encryption key', async () => {
    const b = browser(origin);
    const one = await startSession(b);
    const two = await startSession(b);
    assert.equal(one.requests.length, 1);
    const data = one.requests[0].data;
    assert.equal(one.requests[0].protocol, 'openid4vp-v1-unsigned');
    assert.equal(data.response_type, 'vp_token');
    assert.equal(data.response_mode, 'dc_api.jwt');
    const claims = data.dcql_query.credentials.flatMap((c: any) => c.claims.map((x: any) => x.path.join('/')));
    assert.deepEqual(claims, AGE_DOCS.map((d) => `${d.nameSpace}/age_over_18`));
    assert.ok(data.dcql_query.credentials.every((c: any) => c.claims.every((x: any) => x.intent_to_retain === false)));
    assert.notEqual(data.nonce, two.requests[0].data.nonce);
    assert.notEqual(data.client_metadata.jwks.keys[0].x, two.requests[0].data.client_metadata.jwks.keys[0].x);
    assert.equal('d' in data.client_metadata.jwks.keys[0], false, 'no private key in the request');
  });

  it('the TEST wallet discloses only age_over_18 (the TEST name, birth date and number stay in the wallet)', async () => {
    const wallet = await TestPhoneWallet.create({ issuer });
    const b = browser(origin);
    const { requests } = await startSession(b);
    // Same request, unencrypted, so the test can look inside the answer.
    const plain = [{ protocol: requests[0].protocol, data: { ...requests[0].data, response_mode: 'dc_api' } }];
    const answer: any = await wallet.answer(plain, origin);
    const [presentation] = answer.data.vp_token.mdl;
    const doc: any = parse(Buffer.from(presentation, 'base64url')).documents[0];
    assert.deepEqual(Object.keys(doc.getIssuerNameSpace('org.iso.18013.5.1')), ['age_over_18']);
    assert.equal(JSON.stringify(answer).includes('TEST0001'), false);
  });

  it('widget: "Use a phone wallet ID" -> wallet -> V18 checks -> ticket -> the site unlocks', async () => {
    const b = browser(origin);
    const wallet = await TestPhoneWallet.create({ issuer });
    const done: string[] = [];
    const c = makeWidget(b, wallet.credentialsFor(origin), done);
    await c.loadServerInfo();
    assert.equal(c.walletOffered(), true, 'mock V18 says mdoc_wallet is ready');
    const views: string[] = [];
    c.subscribe((s: any, r: string) => {
      if (r === 'view' && views[views.length - 1] !== s.view) views.push(s.view);
    });
    const accepted = v18.stats.walletAnswersAccepted;
    await c.chooseWallet();
    await until(() => c.state.view === 'done' || c.state.view === 'wallet_failed' || c.state.view === 'site_refused', 8000, 'done');
    assert.equal(c.state.view, 'done', `${c.state.errorCode}: ${c.state.error}`);
    assert.deepEqual(views, ['starting', 'wallet_waiting', 'wallet_checking', 'approved', 'done']);
    assert.equal(done.length, 1);
    assert.match(done[0], /^v18mock-age18-\d{8}\./);
    assert.equal(wallet.answers, 1);
    assert.equal(v18.stats.walletAnswersAccepted, accepted + 1);
    assert.equal((await b.fetch('/adult-content')).status, 200, 'the 18+ page is open');
    c.dispose();
  });

  it('the same flow works with an EU PID instead of a driving licence', async () => {
    const b = browser(origin);
    const wallet = await TestPhoneWallet.create({ issuer, doc: 'pid' });
    const done: string[] = [];
    const c = makeWidget(b, wallet.credentialsFor(origin), done);
    await c.loadServerInfo();
    await c.chooseWallet();
    await until(() => c.state.view === 'done' || c.state.view === 'wallet_failed', 8000, 'done');
    assert.equal(c.state.view, 'done', `${c.state.errorCode}: ${c.state.error}`);
    assert.equal((await b.fetch('/adult-content')).status, 200);
    c.dispose();
  });

  it('an under-18 TEST ID gets UNDER_AGE, no ticket, and the site stays locked', async () => {
    const b = browser(origin);
    const wallet = await TestPhoneWallet.create({ issuer, ageOver18: false });
    const done: string[] = [];
    const c = makeWidget(b, wallet.credentialsFor(origin), done);
    await c.loadServerInfo();
    await c.chooseWallet();
    await until(() => c.state.view === 'wallet_failed' || c.state.view === 'done', 8000, 'failure');
    assert.equal(c.state.view, 'wallet_failed');
    assert.equal(c.state.errorCode, 'UNDER_AGE');
    assert.equal(done.length, 0);
    assert.equal((await b.fetch('/adult-content')).status, 302);
    c.dispose();
  });

  it('an ID from an IACA V18 does not trust is refused (WALLET_UNTRUSTED_ISSUER)', async () => {
    const stranger = await createTestIssuer({ label: 'Some other TEST IACA' });
    const wallet = await TestPhoneWallet.create({ issuer: stranger });
    const b = browser(origin);
    const { sessionId, requests } = await startSession(b);
    const r = await verifyAnswer(b, sessionId, await wallet.answer(requests, origin));
    assert.equal(r.status, 403);
    assert.equal((await r.json()).code, 'WALLET_UNTRUSTED_ISSUER');
  });

  it('an answer made for another site (phishing relay) fails the device signature check', async () => {
    const wallet = await TestPhoneWallet.create({ issuer, pretendOrigin: 'https://evil.test' });
    const b = browser(origin);
    const { sessionId, requests } = await startSession(b);
    const r = await verifyAnswer(b, sessionId, await wallet.answer(requests, origin));
    assert.equal(r.status, 400);
    assert.equal((await r.json()).code, 'WALLET_INVALID');
  });

  it('each request takes one answer; an answer cannot be moved to another session; plain answers are refused', async () => {
    const wallet = await TestPhoneWallet.create({ issuer });
    const b = browser(origin);
    const a = await startSession(b);
    const answer = await wallet.answer(a.requests, origin);
    assert.equal((await verifyAnswer(b, a.sessionId, answer)).status, 200);
    const again = await verifyAnswer(b, a.sessionId, answer);
    assert.ok(again.status === 409, String(again.status));

    const other = await startSession(b);
    const moved = await verifyAnswer(b, other.sessionId, answer);
    assert.equal(moved.status, 400);
    assert.equal((await moved.json()).code, 'WALLET_BAD_RESPONSE', 'encrypted to the first request only');

    const third = await startSession(b);
    const plainReq = [{ protocol: third.requests[0].protocol, data: { ...third.requests[0].data, response_mode: 'dc_api' } }];
    const plain = await verifyAnswer(b, third.sessionId, await wallet.answer(plainReq, origin));
    assert.equal(plain.status, 400, 'V18 asked for an encrypted answer');
    const junk = await startSession(b);
    for (const bad of [null, {}, { protocol: 'openid4vp-v1-unsigned', data: { response: 'not.a.jwe' } }, { protocol: 'org-iso-mdoc', data: {} }]) {
      const s = await startSession(b);
      const r = await verifyAnswer(b, s.sessionId, bad);
      assert.equal(r.status, 400, JSON.stringify(bad));
    }
    void junk;
  });

  it('the wallet endpoints check the Origin header and the session', async () => {
    const b = browser(origin);
    const { sessionId } = await startSession(b);
    const evil = browser(origin, 'https://evil.test');
    const r1 = await evil.fetch(`${v18.url}/v1/wallet/request`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sessionId }) });
    assert.equal(r1.status, 403);
    const r2 = await b.fetch(`${v18.url}/v1/wallet/request`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sessionId: 'pair_nope' }) });
    assert.equal(r2.status, 404);
    await b.fetch(`${v18.url}/v1/pairing/${sessionId}/cancel`, { method: 'POST' });
    const r3 = await b.fetch(`${v18.url}/v1/wallet/request`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sessionId }) });
    assert.equal(r3.status, 409);
  });

  it('the ticket from a wallet answer is a normal one-time ticket: a second use is refused', async () => {
    const b = browser(origin);
    const wallet = await TestPhoneWallet.create({ issuer });
    const done: string[] = [];
    const c = makeWidget(b, wallet.credentialsFor(origin), done);
    await c.loadServerInfo();
    await c.chooseWallet();
    await until(() => done.length === 1, 8000, 'ticket');
    c.dispose();
    const again = await b.post('/v18/verify', { ticket: done[0] });
    assert.equal(again.status, 403);
    assert.equal((await again.json()).code, 'CHALLENGE_MISMATCH');
  });
});
