import { describe, it, before } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { V18Verifier, JwksKeyStore, ChallengeStore, MemoryReplayCache, VerifyResult } from '../index.js';
import { ORIGIN, NOW, TestKey, makeKey, payload, blindTicket, directTicket, b64u } from './helpers.js';

const CHAL = 'a'.repeat(64);

function code(r: VerifyResult): string {
  return r.valid ? 'VALID' : r.code;
}

describe('@v18/verify: PROTOCOL.md 3.7 rules', () => {
  let key18: TestKey;
  let key21: TestKey;
  let attacker: TestKey;
  let clockSec = NOW;

  /** A fresh verifier with key18 and key21 pinned, a fresh replay cache, and a fake clock. */
  function verifier(): V18Verifier {
    const keyStore = new JwksKeyStore();
    keyStore.setJwks({ keys: [key18.jwk, key21.jwk] });
    return new V18Verifier({ keyStore, origin: ORIGIN, clock: () => clockSec * 1000 });
  }

  before(async () => {
    key18 = await makeKey('v18-age18-20261109');
    key21 = await makeKey('v18-age21-20261109', { minAge: 21 });
    attacker = await makeKey('v18-age18-20261109'); // same kid, different private key
  });

  // ---------- positive ----------

  it('accepts a real blind-signed ticket and reports the KEY threshold', async () => {
    clockSec = NOW;
    const r = await verifier().verifyTicket(await blindTicket(key18, payload()), { expectedChallenge: CHAL });
    assert.equal(code(r), 'VALID');
    assert.ok(r.valid);
    assert.equal(r.ticket.minAge, 18);
    assert.equal(r.ticket.keyId, 'v18-age18-20261109');
    assert.equal(r.ticket.origin, ORIGIN);
  });

  it('accepts expectedOrigin passed per call (overrides the default)', async () => {
    clockSec = NOW;
    const t = await blindTicket(key18, payload({ origin: 'http://localhost:3000' }));
    const r = await verifier().verifyTicket(t, { expectedOrigin: 'http://localhost:3000', expectedChallenge: CHAL });
    assert.equal(code(r), 'VALID');
  });

  // ---------- rule 1: key in JWKS, now <= exp + 600 ----------

  it('rule 1: rejects an unknown keyId', async () => {
    clockSec = NOW;
    const t = directTicket(key18, payload(), { kid: 'v18-age18-19990101' });
    assert.equal(code(await verifier().verifyTicket(t, { expectedChallenge: CHAL })), 'UNKNOWN_KEY');
  });

  it('rule 1: accepts a key that expired less than 600 s ago (grace period)', async () => {
    const k = await makeKey('v18-age18-grace', { exp: NOW - 599, nbf: NOW - 7 * 86_400 });
    const keyStore = new JwksKeyStore();
    keyStore.addJwk(k.jwk);
    const v = new V18Verifier({ keyStore, origin: ORIGIN, clock: () => NOW * 1000 });
    assert.equal(code(await v.verifyTicket(directTicket(k, payload()), { expectedChallenge: CHAL })), 'VALID');
  });

  it('rule 1: rejects a key that expired more than 600 s ago', async () => {
    const k = await makeKey('v18-age18-old', { exp: NOW - 601, nbf: NOW - 7 * 86_400 });
    const keyStore = new JwksKeyStore();
    keyStore.addJwk(k.jwk);
    const v = new V18Verifier({ keyStore, origin: ORIGIN, clock: () => NOW * 1000 });
    assert.equal(code(await v.verifyTicket(directTicket(k, payload()), { expectedChallenge: CHAL })), 'KEY_EXPIRED');
  });

  it('rule 1: rejects a key whose nbf is still in the future (the "next" key)', async () => {
    const k = await makeKey('v18-age18-next', { nbf: NOW + 3600, exp: NOW + 8 * 86_400 });
    const keyStore = new JwksKeyStore();
    keyStore.addJwk(k.jwk);
    const v = new V18Verifier({ keyStore, origin: ORIGIN, clock: () => NOW * 1000 });
    assert.equal(code(await v.verifyTicket(directTicket(k, payload()), { expectedChallenge: CHAL })), 'KEY_NOT_YET_VALID');
  });

  it('rule 1: ignores JWKS keys without v18_min_age, nbf or exp, or with the wrong alg', async () => {
    for (const bad of [{ omit: ['v18_min_age'] }, { omit: ['nbf'] }, { omit: ['exp'] }, { alg: 'PS384' }]) {
      const k = await makeKey('v18-age18-bad', bad);
      const keyStore = new JwksKeyStore();
      assert.equal(keyStore.setJwks({ keys: [k.jwk] }), 0, JSON.stringify(bad));
      assert.throws(() => keyStore.addJwk(k.jwk));
      const v = new V18Verifier({ keyStore, origin: ORIGIN, clock: () => NOW * 1000 });
      assert.equal(code(await v.verifyTicket(directTicket(k, payload()), { expectedChallenge: CHAL })), 'UNKNOWN_KEY');
    }
  });

  // ---------- rule 2: RSA-PSS SHA-384, MGF1-SHA-384, salt 48 ----------

  it('rule 2: rejects a changed signature byte', async () => {
    clockSec = NOW;
    const [kid, p, s] = (await blindTicket(key18, payload())).split('.');
    const sig = Buffer.from(s, 'base64url');
    sig[10] ^= 0x01;
    const r = await verifier().verifyTicket(`${kid}.${p}.${b64u(sig)}`, { expectedChallenge: CHAL });
    assert.equal(code(r), 'INVALID_SIGNATURE');
  });

  it('rule 2: rejects a changed message (e.g. someone edits the origin)', async () => {
    clockSec = NOW;
    const [kid, p, s] = (await blindTicket(key18, payload({ origin: 'https://evil.test' }))).split('.');
    const prepared = Buffer.from(p, 'base64url');
    const json = prepared.subarray(32).toString('utf8').replace('https://evil.test', 'https://good.test');
    const edited = Buffer.concat([prepared.subarray(0, 32), Buffer.from(json, 'utf8')]);
    const r = await verifier().verifyTicket(`${kid}.${b64u(edited)}.${s}`, { expectedChallenge: CHAL });
    assert.equal(code(r), 'INVALID_SIGNATURE');
  });

  it('rule 2: rejects a ticket sealed by a different private key under the same keyId', async () => {
    clockSec = NOW;
    const r = await verifier().verifyTicket(await blindTicket(attacker, payload()), { expectedChallenge: CHAL });
    assert.equal(code(r), 'INVALID_SIGNATURE');
  });

  it('rule 2: rejects PSS with the wrong salt length or hash', async () => {
    clockSec = NOW;
    const v = verifier();
    assert.equal(code(await v.verifyTicket(directTicket(key18, payload(), { saltLength: 32 }), { expectedChallenge: CHAL })), 'INVALID_SIGNATURE');
    assert.equal(code(await v.verifyTicket(directTicket(key18, payload(), { hash: 'sha256', saltLength: 32 }), { expectedChallenge: CHAL })), 'INVALID_SIGNATURE');
  });

  // ---------- rule 3: payload.v == 1 ----------

  it('rule 3: rejects v missing, v = 2 and v = "1"', async () => {
    clockSec = NOW;
    const v = verifier();
    const noV = payload();
    delete noV.v;
    for (const p of [noV, payload({ v: 2 }), payload({ v: '1' })]) {
      assert.equal(code(await v.verifyTicket(directTicket(key18, p), { expectedChallenge: CHAL })), 'UNSUPPORTED_VERSION');
    }
  });

  // ---------- rule 4: origin ----------

  it('rule 4: rejects a ticket made for another site', async () => {
    clockSec = NOW;
    const t = await blindTicket(key18, payload({ origin: 'https://evil.test' }));
    assert.equal(code(await verifier().verifyTicket(t, { expectedChallenge: CHAL })), 'ORIGIN_MISMATCH');
  });

  it('rule 4: origin must match exactly (no host-only, no trailing slash, no other port)', async () => {
    clockSec = NOW;
    const v = verifier();
    for (const o of ['example-site.test', `${ORIGIN}/`, `${ORIGIN}:8443`, 'http://example-site.test']) {
      assert.equal(code(await v.verifyTicket(directTicket(key18, payload({ origin: o })), { expectedChallenge: CHAL })), 'ORIGIN_MISMATCH', o);
    }
  });

  it('rule 4: a badly configured expectedOrigin is a CONFIG_ERROR, not a pass', async () => {
    clockSec = NOW;
    const t = directTicket(key18, payload({ origin: 'localhost:3000' }));
    const r = await verifier().verifyTicket(t, { expectedOrigin: 'localhost:3000', expectedChallenge: CHAL });
    assert.equal(code(r), 'CONFIG_ERROR');
    assert.throws(() => new V18Verifier({ origin: 'https://example.com/' }));
  });

  // ---------- rule 5: challenge ----------

  it('rule 5: rejects a ticket with a different challenge', async () => {
    clockSec = NOW;
    const t = await blindTicket(key18, payload({ challenge: 'b'.repeat(64) }));
    assert.equal(code(await verifier().verifyTicket(t, { expectedChallenge: CHAL })), 'CHALLENGE_MISMATCH');
  });

  it('rule 5: refuses to verify when the site gives no challenge', async () => {
    clockSec = NOW;
    const t = await blindTicket(key18, payload());
    assert.equal(code(await verifier().verifyTicket(t)), 'CHALLENGE_REQUIRED');
    assert.equal(code(await verifier().verifyTicket(t, { expectedChallenge: '' })), 'CHALLENGE_REQUIRED');
  });

  it('rule 5: works with ChallengeStore, and each challenge works only once', async () => {
    clockSec = NOW;
    const store = new ChallengeStore({ clock: () => clockSec * 1000 });
    const { challenge } = store.create('visit-1');
    const v = verifier();
    const t1 = await blindTicket(key18, payload({ challenge }));
    const t2 = await blindTicket(key18, payload({ challenge })); // a second ticket, same challenge
    assert.equal(code(await v.verifyTicket(t1, { expectedChallenge: store.checker('visit-1') })), 'VALID');
    assert.equal(code(await v.verifyTicket(t2, { expectedChallenge: store.checker('visit-1') })), 'CHALLENGE_MISMATCH');
  });

  it('rule 5: a challenge from one visit does not work for another visit', async () => {
    clockSec = NOW;
    const store = new ChallengeStore({ clock: () => clockSec * 1000 });
    const { challenge } = store.create('visit-A');
    store.create('visit-B');
    const t = await blindTicket(key18, payload({ challenge }));
    assert.equal(code(await verifier().verifyTicket(t, { expectedChallenge: store.checker('visit-B') })), 'CHALLENGE_MISMATCH');
  });

  // ---------- rule 6: the key's v18_min_age, never payload.minAge ----------

  it('rule 6: an 18+ key fails a 21+ site even if the payload claims minAge 21', async () => {
    clockSec = NOW;
    const t = await blindTicket(key18, payload({ minAge: 21 }));
    assert.equal(code(await verifier().verifyTicket(t, { expectedChallenge: CHAL, minAge: 21 })), 'AGE_INSUFFICIENT');
  });

  it('rule 6: a 21+ key passes an 18+ site and a 21+ site, whatever the payload says', async () => {
    clockSec = NOW;
    const v = verifier();
    const r1 = await v.verifyTicket(directTicket(key21, payload({ minAge: 0 })), { expectedChallenge: CHAL, minAge: 18 });
    assert.equal(code(r1), 'VALID');
    assert.ok(r1.valid && r1.ticket.minAge === 21);
    const r2 = await v.verifyTicket(directTicket(key21, payload()), { expectedChallenge: CHAL, minAge: 21 });
    assert.equal(code(r2), 'VALID');
  });

  // ---------- rule 7: iat - 60 <= now <= expiresAt + 60, expiresAt - iat <= 300 ----------

  it('rule 7: accepts the edges of the window', async () => {
    const v = verifier();
    clockSec = NOW - 60; // iat - 60
    assert.equal(code(await v.verifyTicket(directTicket(key18, payload()), { expectedChallenge: CHAL })), 'VALID');
    clockSec = NOW + 300 + 60; // expiresAt + 60
    assert.equal(code(await v.verifyTicket(directTicket(key18, payload()), { expectedChallenge: CHAL })), 'VALID');
    clockSec = NOW;
    assert.equal(code(await v.verifyTicket(directTicket(key18, payload({ expiresAt: NOW + 300 })), { expectedChallenge: CHAL })), 'VALID');
  });

  it('rule 7: rejects a ticket from more than 60 s in the future', async () => {
    clockSec = NOW - 61;
    assert.equal(code(await verifier().verifyTicket(directTicket(key18, payload()), { expectedChallenge: CHAL })), 'TICKET_NOT_YET_VALID');
  });

  it('rule 7: rejects a ticket more than 60 s past expiresAt', async () => {
    clockSec = NOW + 300 + 61;
    assert.equal(code(await verifier().verifyTicket(directTicket(key18, payload()), { expectedChallenge: CHAL })), 'TICKET_EXPIRED');
  });

  it('rule 7: rejects a lifetime over 300 s, or a negative lifetime', async () => {
    clockSec = NOW;
    const v = verifier();
    assert.equal(code(await v.verifyTicket(directTicket(key18, payload({ expiresAt: NOW + 301 })), { expectedChallenge: CHAL })), 'TICKET_LIFETIME_INVALID');
    assert.equal(code(await v.verifyTicket(directTicket(key18, payload({ expiresAt: NOW - 1 })), { expectedChallenge: CHAL })), 'TICKET_LIFETIME_INVALID');
  });

  // ---------- rule 8: replay cache ----------

  it('rule 8: the same ticket is accepted once, then refused', async () => {
    clockSec = NOW;
    const v = verifier();
    const t = await blindTicket(key18, payload());
    assert.equal(code(await v.verifyTicket(t, { expectedChallenge: CHAL })), 'VALID');
    assert.equal(code(await v.verifyTicket(t, { expectedChallenge: CHAL })), 'REPLAY_DETECTED');
  });

  it('rule 8: a new ticket with a reused ticketId is refused too', async () => {
    clockSec = NOW;
    const v = verifier();
    const p = payload();
    assert.equal(code(await v.verifyTicket(directTicket(key18, p), { expectedChallenge: CHAL })), 'VALID');
    assert.equal(code(await v.verifyTicket(directTicket(key18, p), { expectedChallenge: CHAL })), 'REPLAY_DETECTED');
  });

  it('rule 8: a refused ticket does not use up its ticketId', async () => {
    clockSec = NOW;
    const v = verifier();
    const p = payload();
    assert.equal(code(await v.verifyTicket(directTicket(key18, p), { expectedChallenge: 'c'.repeat(64) })), 'CHALLENGE_MISMATCH');
    assert.equal(code(await v.verifyTicket(directTicket(key18, p), { expectedChallenge: CHAL })), 'VALID');
  });

  it('rule 8: MemoryReplayCache remembers until the given time, then forgets', () => {
    let ms = NOW * 1000;
    const c = new MemoryReplayCache({ clock: () => ms });
    assert.equal(c.checkAndRemember('t1', NOW + 10), true);
    assert.equal(c.checkAndRemember('t1', NOW + 10), false);
    ms = (NOW + 11) * 1000;
    assert.equal(c.checkAndRemember('t1', NOW + 20), true);
  });

  // ---------- ticket format ----------

  it('format: rejects wrong part counts, bad base64url and padding', async () => {
    clockSec = NOW;
    const v = verifier();
    const t = await blindTicket(key18, payload());
    const [kid, p, s] = t.split('.');
    for (const bad of ['', 'abc', `${kid}.${p}`, `${t}.x`, `${kid}.${p}=.${s}`, `${kid}.${p}.${s}+/`, `${kid}.${p}.${s}!`, 'x'.repeat(9000)]) {
      assert.equal(code(await v.verifyTicket(bad, { expectedChallenge: CHAL })), 'INVALID_FORMAT', bad.slice(0, 40));
    }
    assert.equal(code(await v.verifyTicket(12345 as any, { expectedChallenge: CHAL })), 'INVALID_FORMAT');
  });

  it('format: rejects signed messages that are not the protocol JSON', async () => {
    clockSec = NOW;
    const v = verifier();
    const cases: Array<Record<string, unknown> | Uint8Array> = [
      new TextEncoder().encode('not json'),
      new Uint8Array([0xff, 0xfe, 0x7b, 0x7d]), // not UTF-8
      new TextEncoder().encode('[1,2,3]'),
      payload({ ticketId: 'short' }),
      payload({ ticketId: b64u(crypto.randomBytes(8)) }),
      payload({ iat: '1762700000' }),
      payload({ expiresAt: NOW + 0.5 }),
      payload({ origin: 42 }),
      payload({ challenge: null }),
    ];
    for (const body of cases) {
      assert.equal(code(await v.verifyTicket(directTicket(key18, body), { expectedChallenge: CHAL })), 'MALFORMED_PAYLOAD');
    }
  });
});
