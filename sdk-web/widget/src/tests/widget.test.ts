import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { generateQrSvg } from '../qr.js';
import { PairingClient } from '../pairing-client.js';
import { WidgetController, TestWallet, WidgetState } from '../controller.js';
import { buildVerifyDeepLink, ensureVerifyDeepLink } from '../deeplink.js';
import { detectWalletSupport, readWalletRequests, walletErrorFromBrowser, WALLET_PROTOCOLS } from '../wallet.js';
import { renderView, testModeBanner, announcement } from '../views.js';
import { esc, isUsableChallenge, normalizeServerUrl } from '../util.js';

const SERVER = 'http://localhost:8080';
const ORIGIN = 'http://localhost:3000';
const SITE_CHAL = 'f'.repeat(64);
const SID = 'pair-' + '0123456789abcdef'.repeat(2);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(cond: () => boolean, ms = 3000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error('timed out waiting');
    await sleep(5);
  }
}

/** A fake V18 server + website server behind one fetch function. */
function fakeNet(opts: {
  pollReplies?: Array<{ status?: number; body?: any } | 'throw'>;
  createStatus?: number;
  createBody?: any;
  health?: any;
  siteChallengeStatus?: number;
  verifyStatus?: number;
  verifyBody?: any;
  walletRequestStatus?: number;
  walletRequestBody?: any;
  walletVerifyStatus?: number;
  walletVerifyBody?: any;
} = {}) {
  const calls: Array<{ url: string; method: string; body?: any; credentials?: string }> = [];
  const polls = [...(opts.pollReplies ?? [])];
  const json = (status: number, body: any) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const fetchFn = (async (input: any, init: any = {}) => {
    const url = String(input);
    const method = (init.method ?? 'GET').toUpperCase();
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ url, method, body, credentials: init.credentials });
    if (url === `${SERVER}/v1/health`) return json(200, opts.health ?? { status: 'ok', devMode: true });
    if (url === '/v18/challenge') return json(opts.siteChallengeStatus ?? 200, { challenge: SITE_CHAL });
    if (url === '/v18/verify') return json(opts.verifyStatus ?? 200, opts.verifyBody ?? { ok: true });
    if (url === `${SERVER}/v1/pairing/session`) {
      return json(
        opts.createStatus ?? 201,
        opts.createBody ?? {
          sessionId: SID,
          deepLink: `v18://verify?session=${SID}&origin=${encodeURIComponent(ORIGIN)}&challenge=${SITE_CHAL}&minAge=18`,
          qrData: `v18://verify?session=${SID}&origin=${encodeURIComponent(ORIGIN)}&challenge=${SITE_CHAL}&minAge=18`,
          expiresAt: new Date(Date.now() + 120_000).toISOString(),
          expiresIn: 120,
          pollUrl: `/v1/pairing/${SID}`,
        }
      );
    }
    if (url === `${SERVER}/v1/pairing/${SID}`) {
      const next = polls.length > 1 ? polls.shift()! : polls[0] ?? { body: { status: 'waiting' } };
      if (next === 'throw') throw new TypeError('Failed to fetch');
      return json(next.status ?? 200, next.body ?? {});
    }
    if (url === `${SERVER}/v1/pairing/${SID}/cancel`) return json(200, { ok: true });
    if (url === `${SERVER}/v1/wallet/request`) {
      return json(opts.walletRequestStatus ?? 200, opts.walletRequestBody ?? { sessionId: SID, digital: { requests: [WALLET_REQ] } });
    }
    if (url === `${SERVER}/v1/wallet/verify`) {
      const status = opts.walletVerifyStatus ?? 200;
      // Like V18: an accepted answer puts a ticket on the pairing session.
      if (status === 200) polls.splice(0, polls.length, { body: { status: 'approved', ticket: TICKET } });
      return json(status, opts.walletVerifyBody ?? { status: 'approved' });
    }
    return json(404, { error: 'not found', code: 'NOT_FOUND' });
  }) as typeof fetch;
  return { fetchFn, calls };
}

function makeController(
  net: ReturnType<typeof fakeNet>,
  extra: Partial<ConstructorParameters<typeof WidgetController>[0]> = {},
  tw: TestWallet | null = null,
  moreDeps: Partial<ConstructorParameters<typeof WidgetController>[1]> = {}
) {
  const opened: string[] = [];
  const successes: Array<[string, unknown]> = [];
  const pairing = new PairingClient(SERVER, { fetch: net.fetchFn, pollMs: 5, maxPollFailures: 3 });
  const c = new WidgetController(
    {
      origin: ORIGIN,
      minAge: 18,
      serverUrl: SERVER,
      walletSupport: false,
      verifyUrl: '/v18/verify',
      windowsHelpDelayMs: 30,
      onSuccess: (t, r) => successes.push([t, r]),
      ...extra,
    },
    { fetch: net.fetchFn, pairing, openDeepLink: (l) => opened.push(l), getTestWallet: () => tw, ...moreDeps }
  );
  return { c, opened, successes, pairing };
}

const TICKET = 'v18-age18-20261109.AAAA.BBBB';
const WALLET_REQ = { protocol: 'openid4vp-v1-unsigned', data: { response_type: 'vp_token', nonce: 'n-123', dcql_query: { credentials: [] } } };
const WALLET_ANSWER = { protocol: 'openid4vp-v1-unsigned', data: { response: 'eyJ.jwe.answer' } };

/** A fake navigator.credentials that records what it was asked. */
function fakeCredentials(behaviour: 'answer' | 'cancel' | 'hang' = 'answer') {
  const asked: any[] = [];
  return {
    asked,
    get(options: any) {
      asked.push(options);
      if (behaviour === 'cancel') return Promise.reject(Object.assign(new Error('The user closed the dialog'), { name: 'NotAllowedError' }));
      if (behaviour === 'hang') {
        return new Promise((_res, rej) => options.signal?.addEventListener('abort', () => rej(Object.assign(new Error('aborted'), { name: 'AbortError' }))));
      }
      return Promise.resolve({ protocol: WALLET_ANSWER.protocol, data: WALLET_ANSWER.data, type: 'digital' });
    },
  };
}

/** Text that must never appear in the widget (PROTOCOL.md 4c: nothing half-made is shown). */
const STUB_TEXT = /coming soon|not available|stub|not yet|later/i;

describe('widget: QR codes and helpers', () => {
  it('makes a scalable SVG QR code for a v18:// link', () => {
    const svg = generateQrSvg(buildVerifyDeepLink({ sessionId: SID, origin: ORIGIN, challenge: SITE_CHAL, minAge: 18, serverUrl: SERVER }));
    assert.ok(svg.startsWith('<svg') && svg.includes('</svg>') && svg.includes('viewBox'));
  });

  it('builds the protocol deep link and adds server= when the server left it out', () => {
    const parts = { sessionId: SID, origin: ORIGIN, challenge: SITE_CHAL, minAge: 18, serverUrl: SERVER };
    const link = buildVerifyDeepLink(parts);
    assert.equal(
      link,
      `v18://verify?session=${SID}&origin=http%3A%2F%2Flocalhost%3A3000&challenge=${SITE_CHAL}&minAge=18&server=http%3A%2F%2Flocalhost%3A8080`
    );
    const noServer = `v18://verify?session=${SID}&origin=x&challenge=y&minAge=18`;
    assert.equal(ensureVerifyDeepLink(noServer, parts), `${noServer}&server=http%3A%2F%2Flocalhost%3A8080`);
    assert.equal(ensureVerifyDeepLink(link, parts), link);
    assert.equal(ensureVerifyDeepLink('https://evil.test/?session=' + SID, parts), link, 'non-v18 link is replaced');
    assert.equal(ensureVerifyDeepLink(`v18://verify?session=other&server=x`, parts), link, 'other session is replaced');
  });

  it('detects the Digital Credentials API (class, credentials.get, HTTPS, and a protocol V18 uses)', () => {
    const DC: any = function () {};
    assert.equal(detectWalletSupport(undefined), false);
    assert.equal(detectWalletSupport({ navigator: { credentials: { get() {} } } }), false, 'no DigitalCredential class');
    assert.equal(detectWalletSupport({ DigitalCredential: DC, navigator: {} }), false, 'no credentials.get');
    assert.equal(detectWalletSupport({ DigitalCredential: DC, navigator: { credentials: { get() {} } }, isSecureContext: false }), false, 'not HTTPS');
    assert.equal(detectWalletSupport({ DigitalCredential: DC, navigator: { credentials: { get() {} } }, isSecureContext: true }), true);
    const picky: any = function () {};
    picky.userAgentAllowsProtocol = (p: string) => p === 'some-other-protocol';
    assert.equal(detectWalletSupport({ DigitalCredential: picky, navigator: { credentials: { get() {} } }, isSecureContext: true }), false, 'no protocol V18 uses');
    const iso: any = function () {};
    iso.userAgentAllowsProtocol = (p: string) => p === 'org-iso-mdoc';
    assert.equal(detectWalletSupport({ DigitalCredential: iso, navigator: { credentials: { get() {} } }, isSecureContext: true }), true);
    assert.ok(WALLET_PROTOCOLS.includes('openid4vp-v1-unsigned'));
  });

  it('reads the wallet request in the protocol shape and passes it on untouched', () => {
    const data = { nonce: 'x', nested: { a: [1, 2] } };
    assert.deepEqual(readWalletRequests({ digital: { requests: [{ protocol: 'org-iso-mdoc', data }] } }), [{ protocol: 'org-iso-mdoc', data }]);
    assert.deepEqual(readWalletRequests({ requests: [{ protocol: 'p', data: 'str' }] }), [{ protocol: 'p', data: 'str' }]);
    assert.deepEqual(readWalletRequests({ protocol: 'p', data }), [{ protocol: 'p', data }]);
    for (const bad of [null, {}, { digital: { requests: [] } }, { requests: [{ protocol: 'p' }] }, { requests: [{ data: 1 }] }]) {
      assert.throws(() => readWalletRequests(bad), (e: any) => e.code === 'BAD_REPLY');
    }
    assert.equal(walletErrorFromBrowser({ name: 'NotAllowedError' }).code, 'WALLET_CANCELLED');
    assert.equal(walletErrorFromBrowser({ name: 'TypeError', message: 'x' }).code, 'WALLET_FAILED');
  });

  it('escapes HTML, checks challenges and normalizes server URLs', () => {
    assert.equal(esc('<a href="x">\'&'), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;');
    assert.equal(isUsableChallenge(SITE_CHAL), true);
    assert.equal(isUsableChallenge('short'), false);
    assert.equal(isUsableChallenge('has spaces in it, sixteen+'), false);
    assert.equal(normalizeServerUrl('http://localhost:8080/v1/'), SERVER);
  });
});

describe('widget: pairing client (PROTOCOL.md 3.8)', () => {
  it('sends origin, the site challenge, minAge and ttlSeconds', async () => {
    const net = fakeNet();
    const p = new PairingClient(SERVER, { fetch: net.fetchFn });
    const s = await p.create({ origin: ORIGIN, challenge: SITE_CHAL, minAge: 18 });
    assert.equal(s.sessionId, SID);
    assert.deepEqual(net.calls[0].body, { origin: ORIGIN, challenge: SITE_CHAL, minAge: 18, ttlSeconds: 120 });
  });

  it('reports a server refusal with its error code', async () => {
    const net = fakeNet({ createStatus: 403, createBody: { error: 'Origin header does not match', code: 'ORIGIN_MISMATCH' } });
    const p = new PairingClient(SERVER, { fetch: net.fetchFn });
    await assert.rejects(p.create({ origin: ORIGIN, challenge: SITE_CHAL, minAge: 18 }), (e: any) => e.code === 'ORIGIN_MISMATCH');
  });

  it('refuses a session ID that is too short (protocol: at least 128 random bits)', async () => {
    const net = fakeNet({ createBody: { sessionId: 'pair-1', expiresIn: 120 } });
    const p = new PairingClient(SERVER, { fetch: net.fetchFn });
    await assert.rejects(p.create({ origin: ORIGIN, challenge: SITE_CHAL, minAge: 18 }), (e: any) => e.code === 'BAD_REPLY');
  });

  it('delivers the ticket once and stops polling', async () => {
    const net = fakeNet({ pollReplies: [{ body: { status: 'waiting' } }, { body: { status: 'approved', ticket: TICKET } }, { body: { status: 'approved' } }] });
    const p = new PairingClient(SERVER, { fetch: net.fetchFn, pollMs: 5 });
    const s = await p.create({ origin: ORIGIN, challenge: SITE_CHAL, minAge: 18 });
    const tickets: string[] = [];
    p.watch(s, { onTicket: (t) => tickets.push(t) });
    await until(() => tickets.length > 0);
    const pollsAtDelivery = net.calls.filter((c) => c.url.endsWith(SID)).length;
    await sleep(40);
    assert.deepEqual(tickets, [TICKET]);
    assert.equal(net.calls.filter((c) => c.url.endsWith(SID)).length, pollsAtDelivery, 'no polling after delivery');
    assert.equal(p.isActive(), false);
  });

  it('treats 404 and status "expired" as expired', async () => {
    for (const reply of [{ status: 404, body: { error: 'gone' } }, { body: { status: 'expired' } }]) {
      const net = fakeNet({ pollReplies: [reply] });
      const p = new PairingClient(SERVER, { fetch: net.fetchFn, pollMs: 5 });
      const s = await p.create({ origin: ORIGIN, challenge: SITE_CHAL, minAge: 18 });
      let expired = '';
      p.watch(s, { onExpired: (r) => (expired = r) });
      await until(() => expired !== '');
      assert.ok(expired === 'expired');
    }
  });

  it('reports a lost connection after several failed polls in a row', async () => {
    const net = fakeNet({ pollReplies: ['throw'] });
    const p = new PairingClient(SERVER, { fetch: net.fetchFn, pollMs: 5, maxPollFailures: 3 });
    const s = await p.create({ origin: ORIGIN, challenge: SITE_CHAL, minAge: 18 });
    let lost: Error | null = null;
    p.watch(s, { onConnectionLost: (e) => (lost = e) });
    await until(() => lost !== null);
  });

  it('counts down and expires by itself when time runs out', async () => {
    const net = fakeNet({ createBody: { sessionId: SID, deepLink: '', expiresIn: 1 } });
    let now = 0;
    const p = new PairingClient(SERVER, { fetch: net.fetchFn, pollMs: 5, now: () => now });
    const s = await p.create({ origin: ORIGIN, challenge: SITE_CHAL, minAge: 18 });
    const ticks: number[] = [];
    let expired = '';
    p.watch(s, { onTick: (l) => ticks.push(l), onExpired: (r) => (expired = r) });
    now = 1500;
    await until(() => expired !== '', 2500);
    assert.equal(expired, 'timeout');
    assert.equal(ticks[0], 1);
    assert.equal(ticks[ticks.length - 1], 0);
  });

  it('cancel() tells the server', async () => {
    const net = fakeNet();
    const p = new PairingClient(SERVER, { fetch: net.fetchFn, pollMs: 5 });
    p.watch(await p.create({ origin: ORIGIN, challenge: SITE_CHAL, minAge: 18 }), {});
    await p.cancel();
    assert.ok(net.calls.some((c) => c.url === `${SERVER}/v1/pairing/${SID}/cancel` && c.method === 'POST'));
    assert.equal(p.isActive(), false);
  });
});

describe('widget: flows (state machine)', () => {
  it('phone: challenge from the site -> QR -> connected -> approved -> ticket -> site verify -> done', async () => {
    const net = fakeNet({
      pollReplies: [{ body: { status: 'waiting' } }, { body: { status: 'connected' } }, { body: { status: 'approved' } }, { body: { status: 'approved', ticket: TICKET } }],
    });
    const { c, successes } = makeController(net);
    const views: string[] = [];
    c.subscribe((s, r) => {
      if (r === 'view' && views[views.length - 1] !== s.view) views.push(s.view);
    });
    await c.choosePhone();
    assert.equal(c.state.view, 'qr_waiting');
    assert.ok(c.state.qrData!.includes('server=http%3A%2F%2Flocalhost%3A8080'), 'QR carries server=');
    const chal = net.calls.find((x) => x.url === '/v18/challenge')!;
    assert.equal(chal.method, 'POST');
    assert.equal(chal.credentials, 'same-origin');
    assert.equal(net.calls.find((x) => x.url.endsWith('/pairing/session'))!.body.challenge, SITE_CHAL);
    await until(() => c.state.view === 'done');
    assert.deepEqual(views, ['starting', 'qr_waiting', 'connected', 'approved', 'done']);
    const verify = net.calls.find((x) => x.url === '/v18/verify')!;
    assert.deepEqual(verify.body, { ticket: TICKET });
    assert.equal(successes.length, 1);
    assert.equal(successes[0][0], TICKET);
    c.dispose();
  });

  it('phone: uses a challenge already in the page (data-v18-challenge) without calling the site', async () => {
    const net = fakeNet();
    const { c } = makeController(net, { challenge: 'e'.repeat(64) });
    await c.choosePhone();
    assert.equal(net.calls.some((x) => x.url === '/v18/challenge'), false);
    assert.equal(net.calls.find((x) => x.url.endsWith('/pairing/session'))!.body.challenge, 'e'.repeat(64));
    c.dispose();
  });

  it('phone: expiry -> "Get a new code" makes a NEW challenge and session', async () => {
    const net = fakeNet({ pollReplies: [{ body: { status: 'expired' } }] });
    const { c } = makeController(net);
    await c.choosePhone();
    await until(() => c.state.view === 'expired');
    const before = net.calls.filter((x) => x.url === '/v18/challenge').length;
    await c.retry();
    assert.equal(net.calls.filter((x) => x.url === '/v18/challenge').length, before + 1);
    assert.equal(net.calls.filter((x) => x.url.endsWith('/pairing/session')).length, 2);
    c.dispose();
  });

  it('phone: lost connection -> retry view', async () => {
    const net = fakeNet({ pollReplies: ['throw'] });
    const { c } = makeController(net);
    await c.choosePhone();
    await until(() => c.state.view === 'retry');
    assert.equal(c.state.errorCode, 'CONNECTION_LOST');
    c.dispose();
  });

  it('phone: V18 unreachable or site challenge failing -> retry view with details', async () => {
    const net1 = fakeNet({ createStatus: 503, createBody: { error: 'down', code: 'UNAVAILABLE' } });
    const a = makeController(net1).c;
    await a.choosePhone();
    assert.equal(a.state.view, 'retry');
    assert.equal(a.state.errorCode, 'UNAVAILABLE');
    const net2 = fakeNet({ siteChallengeStatus: 500 });
    const b = makeController(net2).c;
    await b.choosePhone();
    assert.equal(b.state.view, 'retry');
    assert.equal(b.state.errorCode, 'SITE_CHALLENGE_FAILED');
    assert.equal(net2.calls.some((x) => x.url.endsWith('/pairing/session')), false, 'no session without a site challenge');
  });

  it('cancel ("Choose another way") cancels the session on the server', async () => {
    const net = fakeNet();
    const { c } = makeController(net);
    await c.choosePhone();
    c.back();
    await sleep(10);
    assert.equal(c.state.view, 'choose');
    assert.ok(net.calls.some((x) => x.url.endsWith(`/pairing/${SID}/cancel`)));
  });

  it('the website refusing the ticket shows site_refused (not done)', async () => {
    const net = fakeNet({ pollReplies: [{ body: { status: 'approved', ticket: TICKET } }], verifyStatus: 403, verifyBody: { error: 'Ticket was already used', code: 'REPLAY_DETECTED' } });
    const { c, successes } = makeController(net);
    await c.choosePhone();
    await until(() => c.state.view === 'site_refused');
    assert.equal(c.state.errorCode, 'REPLAY_DETECTED');
    assert.equal(successes.length, 0);
    c.dispose();
  });

  it('without verifyUrl the ticket goes to onSuccess and nothing is posted', async () => {
    const net = fakeNet({ pollReplies: [{ body: { status: 'approved', ticket: TICKET } }] });
    const { c, successes } = makeController(net, { verifyUrl: undefined });
    await c.choosePhone();
    await until(() => c.state.view === 'done');
    assert.equal(successes[0][0], TICKET);
    assert.equal(net.calls.some((x) => x.url === '/v18/verify'), false);
    c.dispose();
  });

  it('windows: opens the v18://verify deep link with server=, shows help if nothing happens', async () => {
    const net = fakeNet();
    const { c, opened } = makeController(net);
    await c.chooseWindows();
    assert.equal(c.state.view, 'win_waiting');
    assert.equal(opened.length, 1);
    assert.ok(opened[0].startsWith(`v18://verify?session=${SID}`));
    assert.ok(opened[0].includes('&server=http%3A%2F%2Flocalhost%3A8080'));
    await until(() => c.state.windowsHelpHint);
    c.showWindowsHelp();
    assert.equal(c.state.view, 'win_help');
    c.reopenWindowsApp();
    assert.equal(opened.length, 2);
    assert.equal(c.state.view, 'win_waiting');
    c.dispose();
  });

  it('windows: page blur hides the help hint; the app connecting and submitting finishes the flow', async () => {
    const net = fakeNet({ pollReplies: [{ body: { status: 'waiting' } }, { body: { status: 'waiting' } }, { body: { status: 'connected' } }, { body: { status: 'approved', ticket: TICKET } }] });
    const { c } = makeController(net, { windowsHelpDelayMs: 10_000 });
    await c.chooseWindows();
    c.noteAppMayHaveOpened();
    assert.equal(c.state.windowsAppOpened, true);
    await until(() => c.state.view === 'done');
    c.dispose();
  });

  it('wallet option: shown only when the browser has the API AND V18 says mdoc_wallet is ready', async () => {
    const cases: Array<[boolean, any, boolean]> = [
      [false, { devMode: true, methods: { mdoc_wallet: 'ready' } }, false],
      [true, { devMode: true, methods: { test_dev: 'ready' } }, false],
      [true, { devMode: true, methods: { mdoc_wallet: 'not_configured' } }, false],
      [true, { devMode: false, methods: { mdoc_wallet: 'ready' } }, true],
    ];
    for (const [browser, health, shown] of cases) {
      const net = fakeNet({ health });
      const { c } = makeController(net, { walletSupport: browser }, null, { credentials: fakeCredentials() });
      await c.loadServerInfo();
      const html = renderView(c.state, { canSimulate: false }).body;
      assert.equal(html.includes('Use a phone wallet ID'), shown, JSON.stringify(health));
      assert.equal(c.walletOffered(), shown);
      assert.doesNotMatch(html, STUB_TEXT);
      await c.chooseWallet();
      if (!shown) assert.equal(net.calls.some((x) => x.url.includes('/wallet/') || x.url.endsWith('/pairing/session')), false, 'hidden option does nothing');
      c.dispose();
    }
    // No credentials object (browser without the API) means no option, even if the flag says yes.
    const { c } = makeController(fakeNet({ health: { methods: { mdoc_wallet: 'ready' } } }), { walletSupport: true });
    await c.loadServerInfo();
    assert.equal(c.walletOffered(), false);
  });

  it('wallet: site challenge -> pairing session -> V18 request -> browser wallet -> V18 verify -> poll -> site verify -> done', async () => {
    const net = fakeNet({ health: { devMode: false, methods: { mdoc_wallet: 'ready' } }, pollReplies: [{ body: { status: 'waiting' } }] });
    const creds = fakeCredentials();
    const { c, successes } = makeController(net, { walletSupport: true }, null, { credentials: creds, hasUserActivation: () => true });
    const views: string[] = [];
    c.subscribe((st, r) => {
      if (r === 'view' && views[views.length - 1] !== st.view) views.push(st.view);
    });
    await c.loadServerInfo();
    await c.chooseWallet();
    await until(() => c.state.view === 'done');
    assert.deepEqual(views, ['starting', 'wallet_waiting', 'wallet_checking', 'approved', 'done']);
    const session = net.calls.find((x) => x.url.endsWith('/pairing/session'))!;
    assert.equal(session.body.challenge, SITE_CHAL);
    assert.deepEqual(net.calls.find((x) => x.url.endsWith('/wallet/request'))!.body, { sessionId: SID });
    assert.equal(creds.asked.length, 1);
    assert.equal(creds.asked[0].mediation, 'required');
    assert.deepEqual(creds.asked[0].digital, { requests: [WALLET_REQ] }, 'the request goes to the browser untouched');
    assert.deepEqual(net.calls.find((x) => x.url.endsWith('/wallet/verify'))!.body, { sessionId: SID, response: WALLET_ANSWER }, 'the answer goes to V18 untouched');
    assert.deepEqual(net.calls.find((x) => x.url === '/v18/verify')!.body, { ticket: TICKET });
    assert.equal(successes.length, 1);
    assert.equal(c.state.qrData, null, 'no QR for the wallet');
    const approved = renderView({ ...c.state, view: 'approved', progress: 'getting' }, { canSimulate: false }).body;
    assert.ok(approved.includes('checked the ID') && !approved.includes('without V18 seeing it'), 'honest about who makes the ticket');
    c.dispose();
  });

  it('wallet: no recent click -> "Open my wallet" button, and the wallet opens only on that click', async () => {
    const net = fakeNet({ health: { methods: { mdoc_wallet: 'ready' } } });
    const creds = fakeCredentials();
    const { c } = makeController(net, { walletSupport: true }, null, { credentials: creds, hasUserActivation: () => false });
    await c.loadServerInfo();
    await c.chooseWallet();
    assert.equal(c.state.view, 'wallet_ready');
    assert.equal(creds.asked.length, 0);
    assert.ok(renderView(c.state, { canSimulate: false }).body.includes('data-act="wallet_open"'));
    await c.openWallet();
    await until(() => c.state.view === 'done');
    assert.equal(creds.asked.length, 1);
    c.dispose();
  });

  it('wallet: closing the wallet shares nothing, cancels the session, and offers Try again', async () => {
    const net = fakeNet({ health: { methods: { mdoc_wallet: 'ready' } } });
    const { c, successes } = makeController(net, { walletSupport: true }, null, { credentials: fakeCredentials('cancel') });
    await c.loadServerInfo();
    await c.chooseWallet();
    await until(() => c.state.view === 'wallet_failed');
    assert.equal(c.state.errorCode, 'WALLET_CANCELLED');
    assert.equal(net.calls.some((x) => x.url.endsWith('/wallet/verify')), false);
    await until(() => net.calls.some((x) => x.url.endsWith(`/pairing/${SID}/cancel`)));
    const html = renderView(c.state, { canSimulate: false }).body;
    assert.ok(html.includes('Your wallet shared nothing') && html.includes('data-act="retry"'));
    assert.equal(successes.length, 0);
    await c.retry();
    assert.equal(net.calls.filter((x) => x.url.endsWith('/wallet/request')).length, 2, 'Try again makes a new request');
    c.dispose();
  });

  it('wallet: V18 refusing the answer (under 18, untrusted issuer, bad answer) is shown, never done', async () => {
    const cases: Array<[number, any, string, string]> = [
      [403, { error: 'age_over_18 is false', code: 'UNDER_AGE' }, 'UNDER_AGE', 'did not say 18+'],
      [403, { error: 'IACA not trusted', code: 'WALLET_UNTRUSTED_ISSUER' }, 'WALLET_UNTRUSTED_ISSUER', "can't accept this ID"],
      [400, { error: 'device signature is wrong', code: 'WALLET_INVALID' }, 'WALLET_INVALID', "couldn't use your wallet's answer"],
    ];
    for (const [status, body, code, text] of cases) {
      const net = fakeNet({ health: { methods: { mdoc_wallet: 'ready' } }, walletVerifyStatus: status, walletVerifyBody: body });
      const { c, successes } = makeController(net, { walletSupport: true }, null, { credentials: fakeCredentials() });
      await c.loadServerInfo();
      await c.chooseWallet();
      await until(() => c.state.view === 'wallet_failed');
      assert.equal(c.state.errorCode, code);
      assert.ok(renderView(c.state, { canSimulate: false }).body.includes(text), text);
      assert.equal(successes.length, 0);
      c.dispose();
    }
  });

  it('wallet: V18 unreachable for the request -> retry view; expiry while the wallet is open aborts it', async () => {
    const down = fakeNet({ health: { methods: { mdoc_wallet: 'ready' } }, walletRequestStatus: 503, walletRequestBody: { error: 'down', code: 'UNAVAILABLE' } });
    const a = makeController(down, { walletSupport: true }, null, { credentials: fakeCredentials() }).c;
    await a.loadServerInfo();
    await a.chooseWallet();
    assert.equal(a.state.view, 'retry');
    a.dispose();

    const net = fakeNet({ health: { methods: { mdoc_wallet: 'ready' } }, pollReplies: [{ body: { status: 'waiting' } }, { body: { status: 'expired' } }] });
    const creds = fakeCredentials('hang');
    const { c } = makeController(net, { walletSupport: true }, null, { credentials: creds });
    await c.loadServerInfo();
    await c.chooseWallet();
    await until(() => c.state.view === 'expired');
    assert.equal(creds.asked[0].signal.aborted, true, 'the browser request was stopped');
    assert.ok(renderView(c.state, { canSimulate: false }).body.includes('wallet request'));
    c.dispose();
  });

  it('wallet: closing the widget while the wallet is open aborts the browser request and cancels the session', async () => {
    const net = fakeNet({ health: { methods: { mdoc_wallet: 'ready' } } });
    const creds = fakeCredentials('hang');
    const { c } = makeController(net, { walletSupport: true }, null, { credentials: creds });
    await c.loadServerInfo();
    await c.chooseWallet();
    await until(() => c.state.view === 'wallet_waiting');
    c.dispose();
    assert.equal(creds.asked[0].signal.aborted, true);
    await until(() => net.calls.some((x) => x.url.endsWith(`/pairing/${SID}/cancel`)));
  });

  it('TEST MODE banner appears only when /v1/health says devMode: true', async () => {
    const on = makeController(fakeNet({ health: { status: 'ok', devMode: true } })).c;
    await on.loadServerInfo();
    assert.ok(testModeBanner(on.state).includes('TEST MODE'));
    const off = makeController(fakeNet({ health: { status: 'ok', devMode: false } })).c;
    await off.loadServerInfo();
    assert.equal(testModeBanner(off.state), '');
    const missing = makeController(fakeNet({ health: { status: 'ok' } })).c;
    await missing.loadServerInfo();
    assert.equal(testModeBanner(missing.state), '');
  });

  it('test wallet: button only in dev mode with a registered wallet, and it gets the real session details', async () => {
    const got: any[] = [];
    const tw: TestWallet = { label: 'Browser test wallet', simulatePhone: async (s) => { got.push(s); s.onProgress?.('working'); } };
    const net = fakeNet({ health: { devMode: false } });
    const prod = makeController(net, {}, tw).c;
    await prod.loadServerInfo();
    await prod.choosePhone();
    assert.equal(prod.canSimulate(), false, 'never in production mode');
    await prod.simulateWithTestWallet();
    assert.equal(got.length, 0);
    prod.dispose();

    const dev = makeController(fakeNet(), {}, tw).c;
    await dev.loadServerInfo();
    await dev.choosePhone();
    assert.equal(dev.canSimulate(), true);
    assert.ok(renderView(dev.state, { canSimulate: true }).body.includes('Simulate a phone with the test wallet'));
    await dev.simulateWithTestWallet();
    assert.deepEqual({ ...got[0], onProgress: undefined }, { serverUrl: SERVER, sessionId: SID, origin: ORIGIN, challenge: SITE_CHAL, minAge: 18, onProgress: undefined });
    dev.dispose();

    const none = makeController(fakeNet(), {}, null).c;
    await none.loadServerInfo();
    await none.choosePhone();
    assert.equal(none.canSimulate(), false, 'no wallet registered, no button');
    none.dispose();
  });

  it('test wallet errors are shown, not hidden', async () => {
    const tw: TestWallet = { simulatePhone: async () => { throw new Error('V18 refused: CARD_REQUIRED'); } };
    const { c } = makeController(fakeNet(), {}, tw);
    await c.loadServerInfo();
    await c.choosePhone();
    await c.simulateWithTestWallet();
    assert.equal(c.state.testWallet.failed, true);
    assert.ok(renderView(c.state, { canSimulate: true }).body.includes('CARD_REQUIRED'));
    c.dispose();
  });
});

describe('widget: screens', () => {
  const base = (): WidgetState => makeController(fakeNet()).c.state;

  it('every screen renders a focusable heading and escapes the host', () => {
    const views: WidgetState['view'][] = ['choose', 'starting', 'qr_waiting', 'connected', 'win_waiting', 'win_help', 'wallet_ready', 'wallet_waiting', 'wallet_checking', 'wallet_failed', 'approved', 'done', 'expired', 'retry', 'site_refused', 'how'];
    for (const method of ['phone', 'windows', 'wallet'] as const) {
      for (const view of views) {
        const s: WidgetState = { ...base(), view, method, walletSupport: true, walletServer: true, host: '<b>evil</b>', error: '<img src=x onerror=alert(1)>', errorCode: '<i>x</i>', qrData: 'v18://verify?session=x' };
        const r = renderView(s, { canSimulate: false });
        const html = r.body + r.footer;
        assert.ok(html.includes('id="v18-title" tabindex="-1"'), view);
        assert.equal(html.includes('<b>evil</b>'), false, `${view} escapes host`);
        assert.equal(html.includes('<img src=x'), false, `${view} escapes errors`);
        assert.equal(html.includes('<i>x</i>'), false, `${view} escapes codes`);
        assert.doesNotMatch(html, STUB_TEXT, `${method}/${view} has no stub or "coming soon" text`);
        assert.doesNotMatch(announcement(s), STUB_TEXT);
      }
    }
  });

  it('choose screen matches the design copy', () => {
    const html = renderView(base(), { canSimulate: false }).body;
    for (const text of ['Check your age privately', 'Use my phone (scan a QR)', 'Works on any PC', 'Use V18 for Windows', 'What it never gets', 'Which other sites you visit']) {
      assert.ok(html.includes(text), text);
    }
    assert.equal(html.includes('phone wallet'), false, 'no wallet option without browser and server support');
    const withWallet = renderView({ ...base(), walletSupport: true, walletServer: true }, { canSimulate: false }).body;
    assert.ok(withWallet.includes('Use a phone wallet ID'));
    assert.ok(html.includes('localhost:3000 asks: are you 18 or older?'));
  });

  it('options are real buttons (keyboard reachable)', () => {
    const html = renderView(base(), { canSimulate: false }).body;
    assert.equal((html.match(/<button type="button" class="opt"/g) ?? []).length, 2);
    const all = renderView({ ...base(), walletSupport: true, walletServer: true }, { canSimulate: false }).body;
    assert.equal((all.match(/<button type="button" class="opt"/g) ?? []).length, 3);
  });

  it('announces screen changes for screen readers', () => {
    assert.ok(announcement({ ...base(), view: 'expired' }).includes('Nothing was shared'));
    assert.ok(announcement({ ...base(), view: 'done' }).includes('18+'));
  });
});
