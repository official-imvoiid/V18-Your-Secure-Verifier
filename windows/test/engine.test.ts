// The app's flows against a mock server that follows the protocol (test/helpers/mock-server.ts).
// Real Windows Hello is not used here: one suite uses the TEST software key, another uses a fake
// Hello addon (RSA keys in memory) so the RS256 path through HelloKeyProvider is exercised.

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { V18Engine, type EngineDeps } from '../src/main/engine.js';
import { HelloKeyProvider, TestSoftwareKeyProvider } from '../src/main/keys.js';
import type { ViewState } from '../src/main/view.js';
import { verifyTicketString } from '../src/shared/ticket.js';
import { FakeHelloAddon } from './helpers/fake-hello.js';
import { startMockServer, type MockServer } from './helpers/mock-server.js';

function memStore(initial: unknown = null) {
  const s = { data: initial as unknown, saved: [] as string[] };
  return {
    s,
    store: {
      load: () => s.data,
      save: (json: string) => {
        s.saved.push(json);
        s.data = JSON.parse(json);
      },
    },
  };
}

function waitFor(get: () => ViewState, pred: (v: ViewState) => boolean, ms = 4000): Promise<ViewState> {
  const end = Date.now() + ms;
  return new Promise((resolve, reject) => {
    const t = () => {
      const v = get();
      if (pred(v)) return resolve(v);
      if (Date.now() > end) return reject(new Error('timed out; last view: ' + JSON.stringify({ screen: v.screen, ask: v.ask, error: v.error, link: v.link && v.link.status })));
      setTimeout(t, 10);
    };
    t();
  });
}

describe('engine flows against a protocol mock server', () => {
  let mock: MockServer;
  before(async () => {
    mock = await startMockServer({ devMode: true });
  });
  after(async () => {
    await mock.close();
  });

  function makeEngine(over: Partial<EngineDeps> & { initial?: unknown } = {}) {
    const { store, s } = memStore('initial' in over ? over.initial : { serverUrl: mock.url, settings: { firstRunDone: true } });
    const asks: unknown[] = [];
    const deps: EngineDeps = {
      debug: true,
      store,
      hello: new HelloKeyProvider(null, 'not used in this test'),
      testKeys: new TestSoftwareKeyProvider(),
      makeQr: async (t) => 'data:text/plain,' + encodeURIComponent(t),
      onChange: () => undefined,
      onAsk: (a) => asks.push(a),
      linkPollMs: 20,
      extraServerOrigins: [mock.origin],
      ...over,
    };
    const engine = new V18Engine(deps);
    return { engine, s, asks, view: () => engine.getView() };
  }

  it('starts on the welcome screen, and first run sets shared-PC mode', async () => {
    const { engine, s } = makeEngine({ initial: null });
    assert.equal(engine.getView().screen, 'welcome');
    engine.firstRun(true);
    assert.equal(engine.getView().screen, 'home');
    assert.equal((s.data as any).settings.sharedPc, true);
  });

  it('sees the TEST MODE server', async () => {
    const { engine, view } = makeEngine();
    await engine.init();
    assert.equal(view().testMode, true);
    assert.equal(view().serverReachable, true);
    assert.equal(view().testKey, true);
  });

  it('makes a test_dev card, then a ticket for a site, which verifies like a website would check it', async () => {
    const { engine, view, s, asks } = makeEngine();
    await engine.init();
    await engine.issueTestDev('adult');
    assert.equal(view().screen, 'card-saved', JSON.stringify(view().error));
    const stored = (s.data as any).card;
    assert.match(stored.cardId, /^card_/);
    assert.match(stored.keyAlias, /^test-software:v18-card-/);
    assert.deepEqual(Object.keys(stored).sort(), ['cardId', 'keyAlias', 'method', 'validUntil']);

    const { sessionId, deepLink } = mock.createSession('https://example-site.test', 'site-challenge-0001');
    await engine.handleDeepLink(deepLink);
    assert.equal(asks.length, 1);
    assert.equal(view().ask?.stage, 'confirm');
    assert.equal(view().ask?.host, 'example-site.test');
    await engine.askApprove();
    assert.equal(view().ask?.stage, 'sent', view().ask?.message);

    const session = mock.sessions.get(sessionId)!;
    assert.equal(session.status, 'approved');
    const v = await verifyTicketString(session.ticket!, mock.issuerJwk as never);
    assert.equal(v.ok, true);
    assert.equal(v.payload?.origin, 'https://example-site.test');
    assert.equal(v.payload?.challenge, 'site-challenge-0001');
    assert.equal(v.payload!.expiresAt - v.payload!.iat, 300);
    // Nothing about the visit was saved.
    assert.ok(!s.saved.some((j) => j.includes('example-site') || j.includes(session.ticket!.slice(0, 30))));
    engine.askClose();
    engine.shutdown();
  });

  it('shows the under-18 screen and keeps nothing', async () => {
    const { engine, view, s } = makeEngine();
    await engine.issueTestDev('under18');
    assert.equal(view().screen, 'err-under18');
    assert.equal((s.data as any)?.card ?? null, null);
  });

  it('refuses TEST cards when the server is not in TEST MODE', async () => {
    const prod = await startMockServer({ devMode: false });
    try {
      const { engine, view } = makeEngine({ initial: { serverUrl: prod.url, settings: { firstRunDone: true } }, extraServerOrigins: [prod.origin] });
      await engine.issueTestDev('adult');
      assert.equal(view().screen, 'err-general');
      assert.equal(view().error?.code, 'METHOD_DISABLED');
      assert.ok(!prod.calls.includes('POST /card/issue'));
    } finally {
      await prod.close();
    }
  });

  it('gets a card from the phone through a device link (3.9)', async () => {
    const { engine, view, s } = makeEngine();
    await engine.startLink();
    const w = await waitFor(view, (v) => v.link?.status === 'waiting');
    assert.match(w.link!.qr!, /v18%3A%2F%2Flink%3Fid%3D/);
    const [linkId] = [...mock.links.keys()].slice(-1);
    mock.approveLink(linkId);
    await waitFor(view, (v) => v.screen === 'card-saved');
    assert.equal((s.data as any).card.method, 'device_link');
    engine.shutdown();
  });

  it('lets the link code run out, then makes a new one', async () => {
    let now = Date.now();
    const { engine, view } = makeEngine({ now: () => now });
    await engine.startLink();
    await waitFor(view, (v) => v.link?.status === 'waiting');
    now += 121_000;
    await waitFor(view, (v) => v.link?.status === 'expired');
    now = Date.now();
    await engine.startLink();
    await waitFor(view, (v) => v.link?.status === 'waiting');
    engine.cancelLink();
    assert.equal(view().link, null);
    engine.shutdown();
  });

  it('in shared-PC mode keeps no card and offers the phone for site requests', async () => {
    const { engine, view, s } = makeEngine({ initial: { serverUrl: mock.url, settings: { firstRunDone: true, sharedPc: true } } });
    await engine.init();
    engine.go('card-methods');
    assert.equal(view().screen, 'home');
    const { deepLink } = mock.createSession('https://example-site.test', 'site-challenge-0002');
    await engine.handleDeepLink(deepLink);
    assert.equal(view().ask?.stage, 'shared');
    await engine.askUsePhone();
    assert.equal(view().ask?.stage, 'phone');
    assert.match(view().ask!.qr!, /v18%3A%2F%2Fverify/);
    assert.equal((s.data as any).card ?? null, null);
  });

  it('turning on shared-PC mode deletes the card here and on the server', async () => {
    const { engine, view, s } = makeEngine();
    await engine.issueTestDev('adult');
    const cardId = (s.data as any).card.cardId;
    await engine.setSettings({ sharedPc: true });
    assert.equal((s.data as any).card, null);
    assert.equal(mock.cards.get(cardId)?.status, 'revoked');
    assert.match(view().notice ?? '', /deleted/);
  });

  it('deletes a card with a signed DELETE', async () => {
    const { engine, view, s } = makeEngine();
    await engine.issueTestDev('adult');
    const cardId = (s.data as any).card.cardId;
    await engine.deleteCard();
    assert.equal(view().screen, 'home');
    assert.equal((s.data as any).card, null);
    assert.equal(mock.cards.get(cardId)?.status, 'revoked');
  });

  it('notices a card revoked elsewhere and removes it', async () => {
    const { engine, view, s } = makeEngine();
    await engine.issueTestDev('adult');
    mock.cards.get((s.data as any).card.cardId)!.status = 'revoked';
    await engine.init();
    assert.equal(view().card, null);
    assert.match(view().notice ?? '', /turned off/);
  });

  it('a card revoked on the server falls back to the no-card dialog when a site asks', async () => {
    const { engine, view, s } = makeEngine();
    await engine.issueTestDev('adult');
    await engine.init(); // let the status check that follows saving a card finish first
    await new Promise((r) => setTimeout(r, 100));
    mock.cards.get((s.data as any).card.cardId)!.status = 'revoked';
    const { sessionId, deepLink } = mock.createSession('https://example-site.test', 'site-challenge-revoked');
    await engine.handleDeepLink(deepLink);
    assert.equal(view().ask?.stage, 'confirm');
    await engine.askApprove();
    assert.equal(view().ask?.stage, 'nocard', view().ask?.message);
    assert.equal(view().card, null);
    assert.equal((s.data as any).card, null);
    assert.equal(mock.sessions.get(sessionId)!.status, 'waiting');
  });

  it('refuses links to other servers, mismatched requests and expired cards', async () => {
    const { engine, view } = makeEngine();
    await engine.issueTestDev('adult');
    await engine.handleDeepLink('v18://verify?session=pair_0123456789abcdef&origin=https%3A%2F%2Fa.test&challenge=cccccccc&minAge=18&server=https%3A%2F%2Fevil.test');
    assert.equal(view().ask?.stage, 'error');
    assert.match(view().ask?.message ?? '', /does not trust/);

    const { sessionId } = mock.createSession('https://real-site.test', 'site-challenge-0003');
    await engine.handleDeepLink(`v18://verify?session=${sessionId}&origin=${encodeURIComponent('https://evil-site.test')}&challenge=site-challenge-0003&minAge=18&server=${encodeURIComponent(mock.url)}`);
    assert.equal(view().ask?.stage, 'error');
    assert.match(view().ask?.message ?? '', /doesn't match/);
  });

  it('shows the expired dialog when the card ran out', async () => {
    const { engine, view } = makeEngine({
      initial: { serverUrl: mock.url, settings: { firstRunDone: true }, card: { cardId: 'card_AAAAAAAAAAAAAAAAAAAAAA', method: 'test_dev', validUntil: '2020-01-01T00:00:00Z', keyAlias: 'test-software:v18-card-abcdefghijkl' } },
    });
    const { deepLink } = mock.createSession('https://example-site.test', 'site-challenge-0004');
    await engine.handleDeepLink(deepLink);
    assert.equal(view().ask?.stage, 'expired');
  });

  it('shows the offline dialog when the server cannot be reached', async () => {
    const { engine, view } = makeEngine({ fetchImpl: async () => Promise.reject(new TypeError('fetch failed')) });
    const { deepLink } = mock.createSession('https://example-site.test', 'site-challenge-0005');
    await engine.handleDeepLink(deepLink);
    assert.equal(view().ask?.stage, 'offline');
  });

  it('refuses tickets on a child account', async () => {
    const { engine, view } = makeEngine({ ageConsent: async () => ({ child: 'included', minor: 'included' }) });
    await engine.init();
    await engine.issueTestDev('adult');
    const { deepLink } = mock.createSession('https://example-site.test', 'site-challenge-0006');
    await engine.handleDeepLink(deepLink);
    assert.equal(view().ask?.stage, 'child');
  });

  describe('with Windows Hello (fake addon, RS256)', () => {
    let addon: FakeHelloAddon;
    beforeEach(() => {
      addon = new FakeHelloAddon();
    });

    it('makes keys in Hello, signs RS256, and gets a ticket', async () => {
      const { engine, view, s } = makeEngine({ hello: new HelloKeyProvider(addon), testKeys: null });
      await engine.init();
      assert.equal(view().hello.ok, true);
      assert.equal(view().testKey, false);
      await engine.issueTestDev('adult');
      assert.equal(view().screen, 'card-saved', JSON.stringify(view().error));
      assert.match((s.data as any).card.keyAlias, /^hello:v18-card-/);
      const { sessionId, deepLink } = mock.createSession('https://example-site.test', 'site-challenge-0007');
      await engine.handleDeepLink(deepLink);
      const before = addon.signCount;
      await engine.askApprove();
      assert.equal(view().ask?.stage, 'sent', view().ask?.message);
      assert.equal(addon.signCount, before + 1, 'exactly one Hello signature per ticket');
      assert.equal(mock.sessions.get(sessionId)!.status, 'approved');
      engine.shutdown();
    });

    it('goes back to the question when Hello is cancelled, and sends nothing', async () => {
      const { engine, view } = makeEngine({ hello: new HelloKeyProvider(addon), testKeys: null });
      await engine.issueTestDev('adult');
      const { sessionId, deepLink } = mock.createSession('https://example-site.test', 'site-challenge-0008');
      await engine.handleDeepLink(deepLink);
      addon.cancelNext = true;
      await engine.askApprove();
      assert.equal(view().ask?.stage, 'confirm');
      assert.match(view().ask?.message ?? '', /cancelled/);
      assert.equal(mock.sessions.get(sessionId)!.status, 'waiting');
    });

    it('shows the PC security error (never a silent software key) when Hello is not set up', async () => {
      addon.supported = false;
      const { engine, view, s } = makeEngine({ hello: new HelloKeyProvider(addon), testKeys: null });
      await engine.init();
      assert.equal(view().hello.ok, false);
      assert.equal(view().hello.code, 'HELLO_NOT_SET_UP');
      await engine.issueTestDev('adult');
      assert.equal(view().screen, 'err-integrity');
      await engine.startLink();
      assert.equal(view().screen, 'err-integrity');
      assert.equal((s.data as any).card ?? null, null);
    });

    it('shows the PC security error when the native helper is missing', async () => {
      const { engine, view } = makeEngine({ hello: new HelloKeyProvider(null, 'v18_hello.node not found'), testKeys: null });
      await engine.init();
      assert.equal(view().hello.code, 'ADDON_MISSING');
    });

    it('removes a card whose Hello key disappeared', async () => {
      const { engine, view, s } = makeEngine({ hello: new HelloKeyProvider(addon), testKeys: null });
      await engine.issueTestDev('adult');
      addon.keys.clear();
      await engine.init();
      assert.equal((s.data as any).card, null);
      assert.match(view().notice ?? '', /key for your card is gone/);
    });
  });
});
