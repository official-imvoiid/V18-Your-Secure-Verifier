/**
 * Phone wallet IDs: mdoc_wallet in the website widget (4c.5) and mdoc_app in
 * the V18 phone app (4d.3). Test mdocs are issued by a TEST IACA made here,
 * with @auth0/mdl; the server verifies them with @auth0/mdl as well.
 */
import 'reflect-metadata';
import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import { androidAppOrigin, PID_DOCTYPE } from '../wallet/mdoc.js';
import { createTestIaca, issueTestMdoc, newHolderKey, TestHolder, TestIaca, testWalletAnswer } from '../wallet/test-wallet.js';
import { api, getJwks, newChallenge, referenceVerifyTicket, ss, startServer, TestDevice, TestServer } from './helpers.js';

const SITE = 'https://shop.example';
const SITE_CHALLENGE = 'site-challenge-0123456789';

let iaca: TestIaca;
let otherIaca: TestIaca;
let holder: TestHolder;

before(async () => {
  iaca = await createTestIaca();
  otherIaca = await createTestIaca({ name: 'Some other IACA' });
  holder = newHolderKey();
});

async function newSession(srv: TestServer, minAge = 18) {
  const r = await api(srv.url, 'POST', '/v1/pairing/session', { origin: SITE, challenge: SITE_CHALLENGE, minAge }, { Origin: SITE });
  assert.equal(r.status, 201);
  return r.body.sessionId as string;
}

async function walletRequest(srv: TestServer, sessionId: string) {
  const r = await api(srv.url, 'POST', '/v1/wallet/request', { sessionId }, { Origin: SITE });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body;
}

describe('mdoc_wallet: the website widget flow', () => {
  let srv: TestServer;
  before(async () => {
    srv = await startServer({ trustedIacas: [iaca.iacaPem] });
  });
  after(async () => srv.close());

  it('health says mdoc_wallet is ready', async () => {
    assert.equal((await api(srv.url, 'GET', '/v1/health')).body.methods.mdoc_wallet, 'ready');
  });

  it('builds an OpenID4VP DC API request asking ONLY for age_over_18 (mDL or EU PID), open to any website', async () => {
    const sessionId = await newSession(srv);
    const r = await api(srv.url, 'POST', '/v1/wallet/request', { sessionId }, { Origin: SITE });
    assert.equal(r.headers.get('access-control-allow-origin'), SITE);
    const req = r.body.digital.requests[0];
    assert.equal(req.protocol, 'openid4vp-v1-unsigned');
    assert.equal(req.data.response_mode, 'dc_api.jwt');
    assert.match(req.data.nonce, /^[A-Za-z0-9_-]{43}$/);
    const claims = req.data.dcql_query.credentials.map((c: any) => c.claims.map((x: any) => x.path.join('/')));
    assert.deepEqual(claims, [['org.iso.18013.5.1/age_over_18'], ['eu.europa.ec.eudi.pid.1/age_over_18']]);
    assert.equal(req.data.client_metadata.jwks.keys[0].kty, 'EC');
    assert.equal(req.data.client_metadata.jwks.keys[0].d, undefined, 'no private key in the request');
  });

  it('a trusted mDL with age_over_18 gives an ordinary ticket on the pairing session (polled once)', async () => {
    const sessionId = await newSession(srv);
    const body = await walletRequest(srv, sessionId);
    const answer = await testWalletAnswer({ mdoc: await issueTestMdoc({ iaca, holder, ageOver18: true }), holder, request: body.digital.requests[0], origin: SITE });
    const v = await api(srv.url, 'POST', '/v1/wallet/verify', { sessionId, response: answer }, { Origin: SITE });
    assert.equal(v.status, 200, JSON.stringify(v.body));
    assert.deepEqual(v.body, { status: 'approved' });
    const poll = await api(srv.url, 'GET', `/v1/pairing/${sessionId}`, undefined, { Origin: SITE });
    assert.equal(poll.body.status, 'approved');
    const check = referenceVerifyTicket(poll.body.ticket, await getJwks(srv.url), { origin: SITE, challenge: SITE_CHALLENGE, minAge: 18 }, Math.floor(srv.clock.now() / 1000), new Set());
    assert.equal(check.ok, true, JSON.stringify(check));
    assert.equal((await api(srv.url, 'GET', `/v1/pairing/${sessionId}`)).body.ticket, undefined, 'delivered once');
  });

  it('an EU PID works too', async () => {
    const sessionId = await newSession(srv);
    const body = await walletRequest(srv, sessionId);
    const mdoc = await issueTestMdoc({ iaca, holder, ageOver18: true, docType: PID_DOCTYPE });
    const answer = await testWalletAnswer({ mdoc, holder, request: body.digital.requests[0], origin: SITE, docType: PID_DOCTYPE });
    assert.equal((await api(srv.url, 'POST', '/v1/wallet/verify', { sessionId, response: answer }, { Origin: SITE })).status, 200);
  });

  async function tryAnswer(build: (req: any) => Promise<unknown>) {
    const sessionId = await newSession(srv);
    const body = await walletRequest(srv, sessionId);
    const response = await build(body.digital.requests[0]);
    return api(srv.url, 'POST', '/v1/wallet/verify', { sessionId, response }, { Origin: SITE });
  }

  it('age_over_18 false gives 403 UNDER_AGE', async () => {
    const r = await tryAnswer(async (req) => testWalletAnswer({ mdoc: await issueTestMdoc({ iaca, holder, ageOver18: false }), holder, request: req, origin: SITE }));
    assert.equal(r.status, 403);
    assert.equal(r.body.code, 'UNDER_AGE');
  });

  it('an untrusted issuer gives WALLET_UNTRUSTED_ISSUER', async () => {
    const r = await tryAnswer(async (req) => testWalletAnswer({ mdoc: await issueTestMdoc({ iaca: otherIaca, holder, ageOver18: true }), holder, request: req, origin: SITE }));
    assert.equal(r.status, 400);
    assert.equal(r.body.code, 'WALLET_UNTRUSTED_ISSUER');
  });

  it('a wrong nonce or another website origin fails device authentication', async () => {
    const mdoc = await issueTestMdoc({ iaca, holder, ageOver18: true });
    const a = await tryAnswer((req) => testWalletAnswer({ mdoc, holder, request: req, origin: SITE, nonceOverride: 'an-old-nonce' }));
    assert.equal(a.body.reason, 'device_auth_failed');
    const b = await tryAnswer((req) => testWalletAnswer({ mdoc, holder, request: req, origin: 'https://evil.example' }));
    assert.equal(b.body.reason, 'device_auth_failed');
  });

  it('a tampered mdoc (changed issuer-signed bytes) is refused', async () => {
    const mdoc = Buffer.from(await issueTestMdoc({ iaca, holder, ageOver18: true }));
    // Flip one byte inside the signed MSO near the end of the issuerAuth.
    const i = mdoc.lastIndexOf(Buffer.from('validityInfo')) + 20;
    mdoc[i] ^= 0x01;
    const r = await tryAnswer((req) => testWalletAnswer({ mdoc, holder, request: req, origin: SITE }).catch(() => ({ protocol: 'openid4vp-v1-unsigned', data: { response: 'x.y.z.w.v' } })));
    assert.equal(r.status, 400);
    assert.ok(['tampered', 'malformed', 'decrypt_failed'].includes(r.body.reason), r.body.reason);
  });

  it('an expired wallet ID is refused', async () => {
    const mdoc = await issueTestMdoc({ iaca, holder, ageOver18: true, validFrom: new Date(Date.now() - 10 * 86_400_000), validUntil: new Date(Date.now() - 86_400_000) });
    const r = await tryAnswer((req) => testWalletAnswer({ mdoc, holder, request: req, origin: SITE }));
    assert.equal(r.body.reason, 'expired');
  });

  it('a request works once; an answer to an old request and a plain (unencrypted) answer are refused', async () => {
    const sessionId = await newSession(srv);
    const body = await walletRequest(srv, sessionId);
    const answer = await testWalletAnswer({ mdoc: await issueTestMdoc({ iaca, holder, ageOver18: false }), holder, request: body.digital.requests[0], origin: SITE });
    await api(srv.url, 'POST', '/v1/wallet/verify', { sessionId, response: answer }, { Origin: SITE });
    const again = await api(srv.url, 'POST', '/v1/wallet/verify', { sessionId, response: answer }, { Origin: SITE });
    assert.equal(again.body.code, 'WALLET_NO_REQUEST');
    const body2 = await walletRequest(srv, sessionId);
    void body2;
    const old = await api(srv.url, 'POST', '/v1/wallet/verify', { sessionId, response: answer }, { Origin: SITE });
    assert.equal(old.body.reason, 'decrypt_failed');
    await walletRequest(srv, sessionId);
    const plain = await api(srv.url, 'POST', '/v1/wallet/verify', { sessionId, response: { protocol: 'openid4vp-v1-unsigned', data: { vp_token: {} } } }, { Origin: SITE });
    assert.equal(plain.body.reason, 'not_encrypted');
  });

  it('the Origin header must be the session origin', async () => {
    const sessionId = await newSession(srv);
    const r = await api(srv.url, 'POST', '/v1/wallet/request', { sessionId }, { Origin: 'https://other.example' });
    assert.equal(r.status, 403);
    assert.equal(r.body.code, 'ORIGIN_MISMATCH');
  });

  it('without trusted IACAs the wallet is "not_configured" (503)', async () => {
    const s2 = await startServer();
    const sessionId = await newSession(s2);
    const r = await api(s2.url, 'POST', '/v1/wallet/request', { sessionId }, { Origin: SITE });
    assert.equal(r.status, 503);
    assert.equal((await api(s2.url, 'GET', '/v1/health')).body.methods.mdoc_wallet, 'not_configured');
    await s2.close();
  });
});

describe('mdoc_app: a wallet on the same phone gives an age card (4d.3)', () => {
  const APP_DIGEST = 'ab'.repeat(32);
  const appOrigin = androidAppOrigin(APP_DIGEST);

  async function appIssue(srv: TestServer, opts: { mdoc?: Uint8Array; origin?: string; proofOrigin?: boolean; dev?: TestDevice } = {}) {
    const challenge = await newChallenge(srv.url);
    const req = await api(srv.url, 'POST', '/v1/wallet/app-request', { challenge });
    assert.equal(req.status, 200, JSON.stringify(req.body));
    assert.equal(req.body.digital.requests[0].data.nonce, challenge, 'the nonce is the server challenge');
    const mdoc = opts.mdoc ?? (await issueTestMdoc({ iaca, holder: newHolderKey(), ageOver18: true }));
    const h = newHolderKey();
    const m = opts.mdoc ? mdoc : await issueTestMdoc({ iaca, holder: h, ageOver18: true });
    const answer = await testWalletAnswer({ mdoc: m, holder: opts.mdoc ? holder : h, request: req.body.digital.requests[0], origin: opts.origin ?? appOrigin });
    const dev = opts.dev ?? (await TestDevice.es256());
    return api(srv.url, 'POST', '/v1/card/issue', {
      method: 'mdoc_app',
      challenge,
      devicePublicKey: dev.jwkWithAlg,
      deviceSignature: dev.sign(ss.cardIssue(challenge, dev.thumbprint)),
      proof: opts.proofOrigin ? { ...answer, origin: appOrigin } : answer,
    });
  }

  it('production with the app signing digest: a "substantial" card, no longer than the credential', async () => {
    const srv = await startServer({ trustedIacas: [iaca.iacaPem], config: { devMode: false, androidCertDigests: [APP_DIGEST], aadhaarNullifierSeed: '1' } });
    const r = await appIssue(srv);
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.equal(r.body.method, 'mdoc_app');
    assert.equal(r.body.assuranceLevel, 'substantial');
    assert.ok(Date.parse(r.body.validUntil) <= srv.clock.now() + 180 * 86_400_000);
    // Shown for another app's origin, the device signature does not match.
    const wrong = await appIssue(srv, { origin: 'android:apk-key-hash:' + 'A'.repeat(43) });
    assert.equal(wrong.body.reason, 'device_auth_failed');
    await srv.close();
  });

  it('one wallet credential gives at most 3 cards (its holder key is the nullifier)', async () => {
    const srv = await startServer({ trustedIacas: [iaca.iacaPem], config: { devMode: false, androidCertDigests: [APP_DIGEST], aadhaarNullifierSeed: '1' } });
    const mdoc = await issueTestMdoc({ iaca, holder, ageOver18: true });
    for (let i = 0; i < 3; i++) assert.equal((await appIssue(srv, { mdoc })).status, 201);
    const fourth = await appIssue(srv, { mdoc });
    assert.equal(fourth.status, 409);
    assert.equal(fourth.body.code, 'NULLIFIER_OVERUSED');
    await srv.close();
  });

  it('dev mode without V18_ANDROID_CERT_DIGESTS lets the TEST app name its origin; production does not', async () => {
    const dev = await startServer({ trustedIacas: [iaca.iacaPem] });
    assert.equal((await appIssue(dev, { proofOrigin: true })).status, 201);
    await dev.close();
    const prod = await startServer({ trustedIacas: [iaca.iacaPem], config: { devMode: false, androidCertDigests: [], aadhaarNullifierSeed: '1' } });
    assert.equal((await api(prod.url, 'GET', '/v1/health')).body.methods.mdoc_app, 'not_configured');
    await prod.close();
  });

  it('needs the app-request made with the same challenge', async () => {
    const srv = await startServer({ trustedIacas: [iaca.iacaPem] });
    const dev = await TestDevice.es256();
    const challenge = await newChallenge(srv.url);
    const r = await api(srv.url, 'POST', '/v1/card/issue', {
      method: 'mdoc_app',
      challenge,
      devicePublicKey: dev.jwkWithAlg,
      deviceSignature: dev.sign(ss.cardIssue(challenge, dev.thumbprint)),
      proof: { protocol: 'openid4vp-v1-unsigned', data: { response: 'x' } },
    });
    assert.equal(r.status, 409);
    assert.equal(r.body.code, 'WALLET_NO_REQUEST');
    assert.equal((await api(srv.url, 'POST', '/v1/wallet/app-request', { challenge: 'f'.repeat(64) })).body.code, 'CHALLENGE_INVALID');
    await srv.close();
  });
});
