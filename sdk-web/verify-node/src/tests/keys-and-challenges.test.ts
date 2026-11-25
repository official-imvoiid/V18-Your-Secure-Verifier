import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import { V18Verifier, JwksKeyStore, ChallengeStore, normalizeServerUrl, verifyTicket } from '../index.js';
import { ORIGIN, NOW, TestKey, makeKey, payload, blindTicket, mockJwksServer } from './helpers.js';

const CHAL = 'a'.repeat(64);

describe('@v18/verify: JWKS fetching from a (mock) V18 server', () => {
  let keyA: TestKey;
  let keyB: TestKey;
  let server: Awaited<ReturnType<typeof mockJwksServer>>;

  before(async () => {
    keyA = await makeKey('v18-age18-20261102');
    keyB = await makeKey('v18-age18-20261109');
    server = await mockJwksServer({ keys: [keyA.jwk] });
  });
  after(async () => server.close());

  it('fetches GET /v1/keys and verifies a ticket (serverUrl may end in /v1)', async () => {
    const v = new V18Verifier({ serverUrl: `${server.url}/v1/`, origin: ORIGIN, clock: () => NOW * 1000 });
    const r = await v.verifyTicket(await blindTicket(keyA, payload()), { expectedChallenge: CHAL });
    assert.equal(r.valid, true);
  });

  it('refetches for a new keyId (rotation), but at most once per 30 s', async () => {
    let ms = NOW * 1000;
    const keyStore = new JwksKeyStore({ serverUrl: server.url, clock: () => ms });
    const v = new V18Verifier({ keyStore, origin: ORIGIN, clock: () => ms });
    server.setJwks({ keys: [keyA.jwk] });
    const before = server.hits;
    assert.equal((await v.verifyTicket(await blindTicket(keyA, payload()), { expectedChallenge: CHAL })).valid, true);
    assert.equal(server.hits, before + 1);

    // The server rotates: keyB appears. Within 30 s, an unknown kid does not cause a refetch.
    server.setJwks({ keys: [keyA.jwk, keyB.jwk] });
    ms += 10_000;
    const r1 = await v.verifyTicket(await blindTicket(keyB, payload()), { expectedChallenge: CHAL });
    assert.equal(!r1.valid && r1.code, 'UNKNOWN_KEY');
    assert.equal(server.hits, before + 1);

    ms += 21_000;
    const r2 = await v.verifyTicket(await blindTicket(keyB, payload()), { expectedChallenge: CHAL });
    assert.equal(r2.valid, true);
    assert.equal(server.hits, before + 2);
  });

  it('drops a key once it is removed from the JWKS (after the cache TTL)', async () => {
    let ms = NOW * 1000;
    const keyStore = new JwksKeyStore({ serverUrl: server.url, cacheTtlSeconds: 60, clock: () => ms });
    const v = new V18Verifier({ keyStore, origin: ORIGIN, clock: () => ms });
    server.setJwks({ keys: [keyA.jwk] });
    assert.equal((await v.verifyTicket(await blindTicket(keyA, payload()), { expectedChallenge: CHAL })).valid, true);
    server.setJwks({ keys: [keyB.jwk] });
    ms += 61_000;
    const r = await v.verifyTicket(await blindTicket(keyA, payload()), { expectedChallenge: CHAL });
    assert.equal(!r.valid && r.code, 'UNKNOWN_KEY');
  });

  it('says KEYS_UNAVAILABLE when the JWKS cannot be fetched and the key is not cached', async () => {
    server.setStatus(503);
    try {
      const v = new V18Verifier({ serverUrl: server.url, origin: ORIGIN, clock: () => NOW * 1000 });
      const r = await v.verifyTicket(await blindTicket(keyA, payload()), { expectedChallenge: CHAL });
      assert.equal(!r.valid && r.code, 'KEYS_UNAVAILABLE');
    } finally {
      server.setStatus(200);
    }
  });

  it('keeps using a cached key when a later refresh fails (V18 down does not break sites)', async () => {
    let ms = NOW * 1000;
    server.setJwks({ keys: [keyA.jwk] });
    const keyStore = new JwksKeyStore({ serverUrl: server.url, cacheTtlSeconds: 60, clock: () => ms });
    const v = new V18Verifier({ keyStore, origin: ORIGIN, clock: () => ms });
    assert.equal((await v.verifyTicket(await blindTicket(keyA, payload()), { expectedChallenge: CHAL })).valid, true);
    server.setStatus(500);
    try {
      ms += 120_000; // past the TTL, so it tries to refresh and fails
      const r = await v.verifyTicket(await blindTicket(keyA, payload({ iat: NOW + 120, expiresAt: NOW + 420 })), { expectedChallenge: CHAL });
      assert.equal(r.valid, true);
    } finally {
      server.setStatus(200);
    }
  });

  it('verifyTicket() helper works with a serverUrl', async () => {
    // This helper uses the real clock, so use a key that is valid today.
    const now = Math.floor(Date.now() / 1000);
    const live = await makeKey('v18-age18-live', { nbf: now - 100, exp: now + 86_400 });
    server.setJwks({ keys: [keyA.jwk, live.jwk] });
    const r = await verifyTicket(await blindTicket(live, payload({ iat: now, expiresAt: now + 300 })), {
      serverUrl: server.url,
      expectedOrigin: ORIGIN,
      expectedChallenge: CHAL,
    });
    assert.equal(r.valid, true);
  });

  it('normalizeServerUrl strips trailing slashes and /v1', () => {
    assert.equal(normalizeServerUrl('http://localhost:8080/v1/'), 'http://localhost:8080');
    assert.equal(normalizeServerUrl('http://localhost:8080/'), 'http://localhost:8080');
    assert.equal(normalizeServerUrl('https://v18.example'), 'https://v18.example');
  });
});

describe('@v18/verify: ChallengeStore', () => {
  it('makes 64-hex-character challenges that differ every time', () => {
    const s = new ChallengeStore();
    const a = s.create('v').challenge;
    const b = s.create('v').challenge;
    assert.match(a, /^[0-9a-f]{64}$/);
    assert.notEqual(a, b);
  });

  it('take() works once', () => {
    const s = new ChallengeStore();
    const { challenge } = s.create('v');
    assert.equal(s.take('v', challenge), true);
    assert.equal(s.take('v', challenge), false);
  });

  it('a challenge stops working after its TTL (default 5 minutes)', () => {
    let ms = NOW * 1000;
    const s = new ChallengeStore({ clock: () => ms });
    const { challenge, expiresAt } = s.create('v');
    assert.equal(Date.parse(expiresAt), ms + 300_000);
    ms += 300_001;
    assert.equal(s.take('v', challenge), false);
  });

  it('keeps at most maxPerVisit open challenges (oldest dropped)', () => {
    const s = new ChallengeStore({ maxPerVisit: 2 });
    const c1 = s.create('v').challenge;
    const c2 = s.create('v').challenge;
    const c3 = s.create('v').challenge;
    assert.equal(s.openCount('v'), 2);
    assert.equal(s.take('v', c1), false);
    assert.equal(s.take('v', c2), true);
    assert.equal(s.take('v', c3), true);
  });

  it('keeps visits apart and needs a visit ID', () => {
    const s = new ChallengeStore();
    const { challenge } = s.create('a');
    assert.equal(s.take('b', challenge), false);
    assert.equal(s.take('a', challenge), true);
    assert.throws(() => s.create(''));
    assert.match(ChallengeStore.newVisitId(), /^[A-Za-z0-9_-]{43}$/);
  });
});
