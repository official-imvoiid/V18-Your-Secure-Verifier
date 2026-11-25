// End-to-end: the Windows app's flows (the same engine the Electron app runs) against the REAL
// V18 server from server/. Start it first:   npm run dev --prefix server   (port 8080, dev mode)
// Then:                                      npm run test:e2e   (in windows/)
//
// Windows Hello itself is replaced by FakeHelloAddon (RSA keys in memory, RS256), so the real
// server checks real RS256 device signatures. The "phone" in the device-link test is played by
// this test with its own ES256 key and TEST card, exactly as PROTOCOL.md 3.9 describes.

import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, it } from 'node:test';
import { V18Engine, type EngineDeps } from '../../src/main/engine.js';
import { HelloKeyProvider, TestSoftwareKeyProvider } from '../../src/main/keys.js';
import type { ViewState } from '../../src/main/view.js';
import { ApiError, V18Api } from '../../src/shared/api.js';
import { b64urlEncode } from '../../src/shared/b64url.js';
import { devicePublicKeyBody, jwkThumbprint, spkiToJwk } from '../../src/shared/jwk.js';
import { cardIssueString, linkApproveString } from '../../src/shared/signing.js';
import { verifyTicketString } from '../../src/shared/ticket.js';
import { FakeHelloAddon } from '../helpers/fake-hello.js';

const BASE = 'http://localhost:8080/v1';
const SITE = 'http://localhost:3000';
const api = new V18Api(BASE);

let skip: string | false = false;
try {
  const h = await api.health();
  if (!h.devMode) skip = 'the server on :8080 is not in dev mode (start it with "npm run dev --prefix server")';
} catch {
  skip = 'no V18 server on http://localhost:8080 (start it with "npm run dev --prefix server")';
}

function engine(over: Partial<EngineDeps> = {}) {
  let data: any = { serverUrl: BASE, settings: { firstRunDone: true } };
  const qrTexts: string[] = [];
  const e = new V18Engine({
    debug: true,
    store: { load: () => data, save: (j) => (data = JSON.parse(j)) },
    hello: new HelloKeyProvider(new FakeHelloAddon()),
    testKeys: null,
    makeQr: async (t) => (qrTexts.push(t), 'data:,qr'),
    onChange: () => undefined,
    linkPollMs: 200,
    ...over,
  });
  return { e, stored: () => data, qrTexts, view: () => e.getView() };
}

async function siteSession(challenge: string) {
  const res = await fetch(`${BASE}/pairing/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: SITE },
    body: JSON.stringify({ origin: SITE, challenge, minAge: 18, ttlSeconds: 120 }),
  });
  assert.equal(res.status, 201, await res.clone().text());
  return (await res.json()) as { sessionId: string; deepLink: string };
}

async function pairingPoll(id: string) {
  return (await (await fetch(`${BASE}/pairing/${id}`)).json()) as Record<string, unknown>;
}

function waitFor(get: () => ViewState, pred: (v: ViewState) => boolean, ms = 15000) {
  const end = Date.now() + ms;
  return new Promise<ViewState>((resolve, reject) => {
    const t = () => {
      const v = get();
      if (pred(v)) return resolve(v);
      if (Date.now() > end) return reject(new Error('timed out: ' + JSON.stringify({ screen: v.screen, link: v.link, error: v.error })));
      setTimeout(t, 50);
    };
    t();
  });
}

/** The phone: its own ES256 key and TEST card, then it approves the PC's link (3.9 step 2). */
async function phoneApproves(deepLink: string) {
  const linkId = new URL(deepLink).searchParams.get('id')!;
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = spkiToJwk(publicKey.export({ format: 'der', type: 'spki' }));
  const s = (text: string) => ({ alg: 'ES256' as const, sig: b64urlEncode(sign('sha256', Buffer.from(text), { key: privateKey, dsaEncoding: 'ieee-p1363' })) });
  const c1 = (await api.challenge()).challenge;
  const card = await api.issueCard({
    method: 'test_dev',
    challenge: c1,
    devicePublicKey: devicePublicKeyBody(jwk),
    deviceSignature: s(cardIssueString(c1, jwkThumbprint(jwk))),
    proof: { testSubjectId: 'windows-e2e-phone-' + Date.now() + Math.random(), birthDate: '1990-01-01' },
  });
  const c2 = (await api.challenge()).challenge;
  const res = await fetch(`${BASE}/card/link/${encodeURIComponent(linkId)}/approve`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ cardId: card.cardId, challenge: c2, deviceSignature: s(linkApproveString(card.cardId, c2, linkId)) }),
  });
  assert.ok(res.ok, `approve failed: ${res.status} ${await res.text()}`);
  return card;
}

describe('V18 for Windows against the real server (npm run dev --prefix server)', { skip }, () => {
  it('sees a TEST MODE server', async () => {
    const { e, view } = engine();
    await e.init();
    assert.equal(view().testMode, true);
    assert.equal(view().serverReachable, true);
    assert.equal(view().hello.ok, true);
  });

  it('RS256 (Windows Hello path): TEST card, then a ticket a website can verify, delivered once', async () => {
    const { e, view, stored } = engine();
    await e.issueTestDev('adult');
    assert.equal(view().screen, 'card-saved', JSON.stringify(view().error));
    assert.match(stored().card.keyAlias, /^hello:/);

    const challenge = 'e2e-site-challenge-' + Date.now();
    const { sessionId, deepLink } = await siteSession(challenge);
    await e.handleDeepLink(deepLink);
    assert.equal(view().ask?.stage, 'confirm', view().ask?.message);
    assert.equal(view().ask?.origin, SITE);
    await e.askApprove();
    assert.equal(view().ask?.stage, 'sent', view().ask?.message);

    const first = await pairingPoll(sessionId);
    assert.equal(first.status, 'approved');
    const ticket = first.ticket as string;
    const kid = ticket.split('.')[0];
    const key = (await api.keys()).find((k) => k.kid === kid)!;
    const v = await verifyTicketString(ticket, key);
    assert.equal(v.ok, true);
    assert.equal(v.payload?.origin, SITE);
    assert.equal(v.payload?.challenge, challenge);
    assert.equal(v.payload!.expiresAt - v.payload!.iat, 300);
    const second = await pairingPoll(sessionId);
    assert.equal(second.ticket ?? null, null, 'the ticket is handed out only once');
    e.askClose();
    await e.deleteCard();
  });

  it('ES256 (TEST key path): TEST card and ticket', async () => {
    const { e, view } = engine({ testKeys: new TestSoftwareKeyProvider() });
    await e.issueTestDev('adult');
    assert.equal(view().screen, 'card-saved', JSON.stringify(view().error));
    const { sessionId, deepLink } = await siteSession('e2e-es256-' + Date.now());
    await e.handleDeepLink(deepLink);
    await e.askApprove();
    assert.equal(view().ask?.stage, 'sent', view().ask?.message);
    assert.equal((await pairingPoll(sessionId)).status, 'approved');
    e.askClose();
    await e.deleteCard();
  });

  it('device link (3.9): the PC shows a code, the phone approves, the PC saves its own card and can use it', async () => {
    const { e, view, stored, qrTexts } = engine();
    await e.startLink();
    await waitFor(view, (v) => v.link?.status === 'waiting');
    const deepLink = qrTexts.at(-1)!;
    assert.match(deepLink, /^v18:\/\/link\?id=/);
    const phoneCard = await phoneApproves(deepLink);
    await waitFor(view, (v) => v.screen === 'card-saved');
    const pcCard = stored().card;
    assert.notEqual(pcCard.cardId, phoneCard.cardId);
    assert.ok(Date.parse(pcCard.validUntil) <= Date.parse(phoneCard.validUntil), 'no later than the phone card');
    assert.match(pcCard.keyAlias, /^hello:/);

    const { sessionId, deepLink: verifyLink } = await siteSession('e2e-linked-' + Date.now());
    await e.handleDeepLink(verifyLink);
    await e.askApprove();
    assert.equal(view().ask?.stage, 'sent', view().ask?.message);
    assert.equal((await pairingPoll(sessionId)).status, 'approved');
    e.askClose();
    await e.deleteCard();
    e.shutdown();
  });

  it('under 18: the server refuses and the app shows the under-18 screen, saving nothing', async () => {
    const { e, view, stored } = engine();
    await e.issueTestDev('under18');
    assert.equal(view().screen, 'err-under18');
    assert.equal(stored().card ?? null, null);
  });

  it('delete: a signed DELETE turns the card off on the server', async () => {
    const { e, stored } = engine();
    await e.issueTestDev('adult');
    const cardId = stored().card.cardId;
    assert.equal((await api.cardStatus(cardId)).status, 'active');
    await e.deleteCard();
    assert.equal(stored().card, null);
    assert.equal((await api.cardStatus(cardId)).status, 'revoked');
  });

  it('turning on Shared PC mode revokes the card on the server', async () => {
    const { e, stored, view } = engine();
    await e.issueTestDev('adult');
    const cardId = stored().card.cardId;
    await e.setSettings({ sharedPc: true });
    assert.equal(stored().card, null);
    assert.equal((await api.cardStatus(cardId)).status, 'revoked');
    assert.match(view().notice ?? '', /turned off on the V18 server/);
  });

  it('a revoked card cannot get tickets (401 CARD_REQUIRED), and the app notices', async () => {
    const a = engine();
    await a.e.issueTestDev('adult');
    const snapshot = JSON.parse(JSON.stringify(a.stored()));
    const addon = (a.e as unknown as { deps: { hello: { addon: FakeHelloAddon } } }).deps.hello.addon;
    await a.e.deleteCard(); // revoked on the server
    // A second copy of the app still holding the old card (same Hello key).
    const keyName = snapshot.card.keyAlias.split(':')[1];
    const b = engine({ store: { load: () => snapshot, save: () => undefined }, hello: new HelloKeyProvider(addon) });
    addon.keys.set(keyName, generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey);
    const { deepLink } = await siteSession('e2e-revoked-' + Date.now());
    await b.e.handleDeepLink(deepLink);
    assert.equal(b.view().ask?.stage, 'confirm');
    await b.e.askApprove();
    // The server says CARD_REQUIRED; the app re-checks the card, finds it revoked and drops it.
    assert.equal(b.view().ask?.stage, 'nocard', b.view().ask?.message);
    assert.equal(b.view().card, null);
    await assert.rejects(
      api.blindSign({ cardId: snapshot.card.cardId, challenge: (await api.challenge()).challenge, keyId: 'v18-age18-x', blindedMessage: 'AA', deviceSignature: { alg: 'RS256', sig: 'AA' } }),
      (err: unknown) => err instanceof ApiError && err.code === 'CARD_REQUIRED',
    );
  });

  it('refuses a link whose origin was changed after the site asked', async () => {
    const { e, view } = engine();
    await e.issueTestDev('adult');
    const { deepLink } = await siteSession('e2e-tamper-' + Date.now());
    await e.handleDeepLink(deepLink.replace(encodeURIComponent(SITE), encodeURIComponent('https://evil-site.test')));
    assert.equal(view().ask?.stage, 'error');
    assert.match(view().ask?.message ?? '', /doesn't match/);
    e.askClose();
    await e.deleteCard();
  });
});
