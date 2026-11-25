import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import { api, DAY, issueTestCard, newChallenge, ss, startServer, TestDevice, TestServer, columnsOf, dumpTables } from './helpers.js';

const CARD_ID = /^card_[A-Za-z0-9_-]{22}$/;

async function deleteCard(base: string, cardId: string, device: TestDevice) {
  const challenge = await newChallenge(base);
  return api(base, 'DELETE', `/v1/card/${cardId}`, {
    challenge,
    deviceSignature: device.sign(ss.cardDelete(cardId, challenge)),
  });
}

describe('Age cards (protocol 3.5)', () => {
  let srv: TestServer;
  before(async () => {
    srv = await startServer();
  });
  after(async () => {
    await srv.close();
  });

  it('issues a test_dev card bound to an ES256 device key', async () => {
    const dev = await TestDevice.es256();
    const r = await issueTestCard(srv.url, dev);
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.match(r.body.cardId, CARD_ID);
    assert.equal(r.body.method, 'test_dev');
    assert.equal(r.body.assuranceLevel, 'test');
    assert.equal(r.body.minAgeCertified, 18);
    assert.equal(Date.parse(r.body.validUntil) - srv.clock.now(), 30 * DAY);
    assert.deepEqual(Object.keys(r.body).sort(), ['assuranceLevel', 'cardId', 'method', 'minAgeCertified', 'validUntil']);
  });

  it('issues a card bound to an RS256 (Windows Hello style) key', async () => {
    const dev = await TestDevice.rs256();
    const r = await issueTestCard(srv.url, dev);
    assert.equal(r.status, 201, JSON.stringify(r.body));
  });

  it('stores no personal data: no subject ID and no birth date anywhere in the database', async () => {
    const dev = await TestDevice.es256();
    const subject = 'PERSONAL-subject-xyz-123';
    const r = await issueTestCard(srv.url, dev, { testSubjectId: subject, birthDate: '1987-06-05' });
    assert.equal(r.status, 201);
    const db = srv.services.db;
    for (const [name, rows] of Object.entries(await dumpTables(db))) {
      const dump = JSON.stringify(rows);
      assert.ok(!dump.includes(subject), `table ${name} holds the subject ID`);
      assert.ok(!dump.includes('1987-06-05'), `table ${name} holds the birth date`);
    }
    const cols = await columnsOf(db, 'cards');
    assert.deepEqual(cols, [
      'assurance_level',
      'card_id',
      'device_key_alg',
      'device_key_jwk',
      'device_key_thumbprint',
      'issued_at',
      'method',
      'min_age_certified',
      'nullifier_hash',
      'revoked_at',
      'status',
      'valid_until',
    ]);
  });

  it('refuses a reused challenge (401 CHALLENGE_INVALID)', async () => {
    const dev = await TestDevice.es256();
    const challenge = await newChallenge(srv.url);
    const body = {
      method: 'test_dev',
      challenge,
      devicePublicKey: dev.jwkWithAlg,
      deviceSignature: dev.sign(ss.cardIssue(challenge, dev.thumbprint)),
      proof: { testSubjectId: 'reuse-test', birthDate: '1990-01-01' },
    };
    assert.equal((await api(srv.url, 'POST', '/v1/card/issue', body)).status, 201);
    const again = await api(srv.url, 'POST', '/v1/card/issue', body);
    assert.equal(again.status, 401);
    assert.equal(again.body.code, 'CHALLENGE_INVALID');
  });

  it('refuses an expired challenge', async () => {
    const dev = await TestDevice.es256();
    const challenge = await newChallenge(srv.url);
    srv.clock.advance(5 * 60_000 + 1000);
    const r = await api(srv.url, 'POST', '/v1/card/issue', {
      method: 'test_dev',
      challenge,
      devicePublicKey: dev.jwkWithAlg,
      deviceSignature: dev.sign(ss.cardIssue(challenge, dev.thumbprint)),
      proof: { testSubjectId: 'late', birthDate: '1990-01-01' },
    });
    assert.equal(r.status, 401);
    assert.equal(r.body.code, 'CHALLENGE_INVALID');
  });

  it('refuses a wrong proof-of-possession signature (401 BAD_DEVICE_SIGNATURE)', async () => {
    const dev = await TestDevice.es256();
    const other = await TestDevice.es256();
    const challenge = await newChallenge(srv.url);
    const r = await api(srv.url, 'POST', '/v1/card/issue', {
      method: 'test_dev',
      challenge,
      devicePublicKey: dev.jwkWithAlg,
      // signed by a different key
      deviceSignature: other.sign(ss.cardIssue(challenge, dev.thumbprint)),
      proof: { testSubjectId: 'pop', birthDate: '1990-01-01' },
    });
    assert.equal(r.status, 401);
    assert.equal(r.body.code, 'BAD_DEVICE_SIGNATURE');

    const c2 = await newChallenge(srv.url);
    const r2 = await api(srv.url, 'POST', '/v1/card/issue', {
      method: 'test_dev',
      challenge: c2,
      devicePublicKey: dev.jwkWithAlg,
      // right key, but over another device's thumbprint
      deviceSignature: dev.sign(ss.cardIssue(c2, other.thumbprint)),
      proof: { testSubjectId: 'pop', birthDate: '1990-01-01' },
    });
    assert.equal(r2.status, 401);
  });

  it('refuses under-18 test subjects (403 UNDER_AGE)', async () => {
    const dev = await TestDevice.es256();
    const r = await issueTestCard(srv.url, dev, { testSubjectId: 'kid', birthDate: '2012-01-01' });
    assert.equal(r.status, 403);
    assert.equal(r.body.code, 'UNDER_AGE');
  });

  it('caps active cards per ID at V18_MAX_CARDS_PER_ID (3), and a delete frees a slot', async () => {
    const subject = { testSubjectId: 'cap-subject', birthDate: '1990-01-01' };
    const devices = await Promise.all([1, 2, 3, 4].map(() => TestDevice.es256()));
    const cards: string[] = [];
    for (const d of devices.slice(0, 3)) {
      const r = await issueTestCard(srv.url, d, subject);
      assert.equal(r.status, 201);
      cards.push(r.body.cardId);
    }
    const fourth = await issueTestCard(srv.url, devices[3], subject);
    assert.equal(fourth.status, 409);
    assert.equal(fourth.body.code, 'NULLIFIER_OVERUSED');

    const del = await deleteCard(srv.url, cards[0], devices[0]);
    assert.equal(del.status, 200);
    assert.deepEqual(del.body, { cardId: cards[0], status: 'revoked' });
    assert.equal((await issueTestCard(srv.url, devices[3], subject)).status, 201);
  });

  it('refuses a second active card on the same device key (409 DEVICE_KEY_IN_USE)', async () => {
    const dev = await TestDevice.es256();
    assert.equal((await issueTestCard(srv.url, dev)).status, 201);
    const again = await issueTestCard(srv.url, dev);
    assert.equal(again.status, 409);
    assert.equal(again.body.code, 'DEVICE_KEY_IN_USE');
  });

  it('refuses passport_zk (501 METHOD_NOT_READY) and unknown methods (400)', async () => {
    const dev = await TestDevice.es256();
    const challenge = await newChallenge(srv.url);
    const r = await api(srv.url, 'POST', '/v1/card/issue', {
      method: 'passport_zk',
      challenge,
      devicePublicKey: dev.jwkWithAlg,
      deviceSignature: dev.sign(ss.cardIssue(challenge, dev.thumbprint)),
      proof: { circuit: 'x', proof: {}, publicSignals: [] },
    });
    assert.equal(r.status, 501);
    assert.equal(r.body.code, 'METHOD_NOT_READY');
    const u = await api(srv.url, 'POST', '/v1/card/issue', { method: 'selfie' });
    assert.equal(u.status, 400);
    assert.equal(u.body.code, 'METHOD_UNKNOWN');
  });

  it('refuses a JWK that carries the private key', async () => {
    const dev = await TestDevice.es256();
    const challenge = await newChallenge(srv.url);
    const r = await api(srv.url, 'POST', '/v1/card/issue', {
      method: 'test_dev',
      challenge,
      devicePublicKey: { ...dev.jwkWithAlg, d: 'c2VjcmV0' },
      deviceSignature: dev.sign(ss.cardIssue(challenge, dev.thumbprint)),
      proof: { testSubjectId: 'x', birthDate: '1990-01-01' },
    });
    assert.equal(r.status, 400);
    assert.equal(r.body.code, 'BAD_DEVICE_KEY');
  });

  it('GET /v1/card/:id/status shows active, revoked and expired, and nothing else', async () => {
    const dev = await TestDevice.es256();
    const card = (await issueTestCard(srv.url, dev)).body;
    const s1 = await api(srv.url, 'GET', `/v1/card/${card.cardId}/status`);
    assert.deepEqual(s1.body, { status: 'active', validUntil: card.validUntil });

    const dev2 = await TestDevice.es256();
    const card2 = (await issueTestCard(srv.url, dev2)).body;
    await deleteCard(srv.url, card2.cardId, dev2);
    assert.equal((await api(srv.url, 'GET', `/v1/card/${card2.cardId}/status`)).body.status, 'revoked');

    const unknown = await api(srv.url, 'GET', '/v1/card/card_AAAAAAAAAAAAAAAAAAAAAA/status');
    assert.equal(unknown.status, 404);
    assert.equal(unknown.body.code, 'CARD_NOT_FOUND');
  });

  it('DELETE refuses a bad device signature and an unknown card', async () => {
    const dev = await TestDevice.es256();
    const other = await TestDevice.es256();
    const card = (await issueTestCard(srv.url, dev)).body;
    const bad = await deleteCard(srv.url, card.cardId, other);
    assert.equal(bad.status, 401);
    assert.equal(bad.body.code, 'BAD_DEVICE_SIGNATURE');
    assert.equal((await api(srv.url, 'GET', `/v1/card/${card.cardId}/status`)).body.status, 'active');
    const none = await deleteCard(srv.url, 'card_AAAAAAAAAAAAAAAAAAAAAA', dev);
    assert.equal(none.status, 404);
  });

  it('an ID validity date caps the card (never beyond the ID)', async () => {
    const dev = await TestDevice.es256();
    const r = await issueTestCard(srv.url, dev, { testSubjectId: 'short-id', birthDate: '1990-01-01', idValidUntil: '2026-11-20' });
    assert.equal(r.status, 201);
    assert.equal(r.body.validUntil, '2026-11-21T00:00:00.000Z');
  });
});

describe('Card expiry', () => {
  it('a card is "expired" after 30 days and frees its nullifier slot', async () => {
    const srv = await startServer({ config: { maxCardsPerId: 1 } });
    try {
      const dev = await TestDevice.es256();
      const subject = { testSubjectId: 'expiry', birthDate: '1990-01-01' };
      const card = (await issueTestCard(srv.url, dev, subject)).body;
      assert.equal((await issueTestCard(srv.url, await TestDevice.es256(), subject)).status, 409);
      srv.clock.advance(30 * DAY + 1000);
      assert.equal((await api(srv.url, 'GET', `/v1/card/${card.cardId}/status`)).body.status, 'expired');
      assert.equal((await issueTestCard(srv.url, await TestDevice.es256(), subject)).status, 201);
    } finally {
      await srv.close();
    }
  });
});

describe('Production mode', () => {
  it('refuses test_dev with 501 METHOD_DISABLED', async () => {
    const srv = await startServer({ config: { devMode: false } });
    try {
      const health = await api(srv.url, 'GET', '/v1/health');
      assert.equal(health.body.devMode, false);
      assert.equal(health.body.methods.test_dev, 'disabled');
      const r = await issueTestCard(srv.url, await TestDevice.es256());
      assert.equal(r.status, 501);
      assert.equal(r.body.code, 'METHOD_DISABLED');
    } finally {
      await srv.close();
    }
  });
});
