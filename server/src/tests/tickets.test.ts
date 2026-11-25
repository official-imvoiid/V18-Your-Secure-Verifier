import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import {
  api,
  blindTicket,
  currentKey,
  DAY,
  getJwks,
  HOUR,
  issueTestCard,
  makeTicket,
  newChallenge,
  referenceVerifyTicket,
  requestBlindSignature,
  ss,
  startServer,
  TestDevice,
  TestServer,
  ticketPayload,
} from './helpers.js';

const SITE = { origin: 'https://example-site.test', challenge: 'site-challenge-123' };

describe('Blind-signed tickets (protocol 3.6)', () => {
  let srv: TestServer;
  let dev: TestDevice;
  let cardId: string;

  before(async () => {
    srv = await startServer({ config: { ageThresholds: [16, 18, 21] } });
    dev = await TestDevice.es256();
    cardId = (await issueTestCard(srv.url, dev)).body.cardId;
  });
  after(async () => {
    await srv.close();
  });

  const nowSec = () => Math.floor(srv.clock.now() / 1000);
  const blinded = async (minAge = 18) => {
    const jwk = currentKey(await getJwks(srv.url), minAge, nowSec());
    return { jwk, b: await blindTicket(jwk, ticketPayload(SITE.origin, SITE.challenge, nowSec(), minAge)) };
  };

  it('signs for an active card, and the ticket passes all 8 website checks (3.7)', async () => {
    const ticket = await makeTicket(srv, cardId, dev, SITE);
    const [kid] = ticket.split('.');
    assert.equal(kid, 'v18-age18-20261109');
    const seen = new Set<string>();
    const jwks = await getJwks(srv.url);
    const v = referenceVerifyTicket(ticket, jwks, { ...SITE, minAge: 18 }, nowSec(), seen);
    assert.equal(v.ok, true, JSON.stringify(v));
    // replay is caught by the website's replay cache
    assert.deepEqual(referenceVerifyTicket(ticket, jwks, { ...SITE, minAge: 18 }, nowSec(), seen), {
      ok: false,
      rule: 8,
      why: 'replay',
    });
    // the wrong site or the wrong visit challenge fail
    assert.equal((referenceVerifyTicket(ticket, jwks, { ...SITE, origin: 'https://evil.test', minAge: 18 }, nowSec(), new Set()) as any).rule, 4);
    assert.equal((referenceVerifyTicket(ticket, jwks, { ...SITE, challenge: 'other', minAge: 18 }, nowSec(), new Set()) as any).rule, 5);
  });

  it('returns {blindSignature, keyId, algorithm}', async () => {
    const { jwk, b } = await blinded();
    const r = await requestBlindSignature(srv.url, cardId, dev, jwk.kid, b.blindedMessage);
    assert.equal(r.status, 200);
    assert.deepEqual(Object.keys(r.body).sort(), ['algorithm', 'blindSignature', 'keyId']);
    assert.equal(r.body.algorithm, 'RSABSSA-SHA384-PSS-Randomized');
    assert.equal(Buffer.from(r.body.blindSignature, 'base64url').length, 256);
  });

  it('accepts ES256 raw r||s and RS256 device signatures too', async () => {
    assert.ok(await makeTicket(srv, cardId, dev, SITE, { raw: true }));
    const rsa = await TestDevice.rs256();
    const rsaCard = (await issueTestCard(srv.url, rsa)).body.cardId;
    assert.ok(await makeTicket(srv, rsaCard, rsa, SITE));
  });

  it('a request with no card gets 401 CARD_REQUIRED (the old open signer is gone)', async () => {
    const { b } = await blinded();
    const old = await api(srv.url, 'POST', '/v1/ticket/blind-sign', { blindedMessage: b.blindedMessage });
    assert.equal(old.status, 401);
    assert.equal(old.body.code, 'CARD_REQUIRED');

    const noSig = await api(srv.url, 'POST', '/v1/ticket/blind-sign', {
      cardId,
      challenge: await newChallenge(srv.url),
      keyId: 'v18-age18-20261109',
      blindedMessage: b.blindedMessage,
    });
    assert.equal(noSig.status, 401);
    assert.equal(noSig.body.code, 'CARD_REQUIRED');
  });

  it('an unknown card gets 401 CARD_REQUIRED', async () => {
    const { jwk, b } = await blinded();
    const r = await requestBlindSignature(srv.url, 'card_AAAAAAAAAAAAAAAAAAAAAA', dev, jwk.kid, b.blindedMessage);
    assert.equal(r.status, 401);
    assert.equal(r.body.code, 'CARD_REQUIRED');
    assert.equal(r.body.reason, 'unknown_card');
  });

  it('a wrong device signature gets 401 CARD_REQUIRED', async () => {
    const { jwk, b } = await blinded();
    // another device signs for this card
    const thief = await TestDevice.es256();
    const r1 = await requestBlindSignature(srv.url, cardId, thief, jwk.kid, b.blindedMessage);
    assert.equal(r1.status, 401);
    assert.equal(r1.body.reason, 'bad_signature');

    // the right device, but the signature covers a different blinded message
    const other = await blinded();
    const challenge = await newChallenge(srv.url);
    const r2 = await api(srv.url, 'POST', '/v1/ticket/blind-sign', {
      cardId,
      challenge,
      keyId: jwk.kid,
      blindedMessage: b.blindedMessage,
      deviceSignature: dev.sign(ss.ticket(cardId, challenge, jwk.kid, other.b.blindedMessage)),
    });
    assert.equal(r2.status, 401);
    assert.equal(r2.body.code, 'CARD_REQUIRED');
  });

  it('a reused challenge gets 401 CHALLENGE_INVALID', async () => {
    const { jwk, b } = await blinded();
    const challenge = await newChallenge(srv.url);
    const first = await requestBlindSignature(srv.url, cardId, dev, jwk.kid, b.blindedMessage, { challenge });
    assert.equal(first.status, 200);
    const again = await requestBlindSignature(srv.url, cardId, dev, jwk.kid, b.blindedMessage, { challenge });
    assert.equal(again.status, 401);
    assert.equal(again.body.code, 'CHALLENGE_INVALID');
  });

  it('a key above the card\'s certified age gets 403 MIN_AGE_NOT_CERTIFIED; a lower one is fine', async () => {
    const high = await blinded(21);
    const r = await requestBlindSignature(srv.url, cardId, dev, high.jwk.kid, high.b.blindedMessage);
    assert.equal(r.status, 403);
    assert.equal(r.body.code, 'MIN_AGE_NOT_CERTIFIED');
    const low = await blinded(16);
    assert.equal((await requestBlindSignature(srv.url, cardId, dev, low.jwk.kid, low.b.blindedMessage)).status, 200);
  });

  it('the NEXT (not yet valid) key and unknown keys get 400 KEY_NOT_CURRENT', async () => {
    const keys = await getJwks(srv.url);
    const cur = currentKey(keys, 18, nowSec());
    const next = keys.find((k) => k.v18_min_age === 18 && k.nbf === cur.exp)!;
    const b = await blindTicket(next, ticketPayload(SITE.origin, SITE.challenge, nowSec()));
    const r = await requestBlindSignature(srv.url, cardId, dev, next.kid, b.blindedMessage);
    assert.equal(r.status, 400);
    assert.equal(r.body.code, 'KEY_NOT_CURRENT');
    const u = await requestBlindSignature(srv.url, cardId, dev, 'v18-age18-19990101', b.blindedMessage);
    assert.equal(u.body.code, 'KEY_NOT_CURRENT');
  });

  it('a blinded message of the wrong size gets 400 BAD_BLINDED_MESSAGE', async () => {
    const { jwk } = await blinded();
    const r = await requestBlindSignature(srv.url, cardId, dev, jwk.kid, Buffer.alloc(100, 1).toString('base64url'));
    assert.equal(r.status, 400);
    assert.equal(r.body.code, 'BAD_BLINDED_MESSAGE');
  });

  it('a revoked card gets 401 CARD_REQUIRED', async () => {
    const d = await TestDevice.es256();
    const id = (await issueTestCard(srv.url, d)).body.cardId;
    const challenge = await newChallenge(srv.url);
    await api(srv.url, 'DELETE', `/v1/card/${id}`, { challenge, deviceSignature: d.sign(ss.cardDelete(id, challenge)) });
    const { jwk, b } = await blinded();
    const r = await requestBlindSignature(srv.url, id, d, jwk.kid, b.blindedMessage);
    assert.equal(r.status, 401);
    assert.equal(r.body.reason, 'card_revoked');
  });
});

describe('Ticket rules that need time to pass', () => {
  it('an EXPIRED key (after rotation) gets 400 KEY_NOT_CURRENT; the new key works', async () => {
    const srv = await startServer();
    try {
      const dev = await TestDevice.es256();
      const cardId = (await issueTestCard(srv.url, dev)).body.cardId;
      const oldKey = currentKey(await getJwks(srv.url), 18, Math.floor(srv.clock.now() / 1000));
      const b = await blindTicket(oldKey, ticketPayload(SITE.origin, SITE.challenge, Math.floor(srv.clock.now() / 1000)));

      srv.clock.advance(8 * DAY);
      const keys = await getJwks(srv.url);
      assert.ok(keys.find((k) => k.kid === oldKey.kid), 'old key is still listed as "previous" for verifiers');
      const r = await requestBlindSignature(srv.url, cardId, dev, oldKey.kid, b.blindedMessage);
      assert.equal(r.status, 400);
      assert.equal(r.body.code, 'KEY_NOT_CURRENT');
      assert.ok(await makeTicket(srv, cardId, dev, SITE));
    } finally {
      await srv.close();
    }
  });

  it('an EXPIRED card gets 401 CARD_REQUIRED', async () => {
    const srv = await startServer();
    try {
      const dev = await TestDevice.es256();
      const cardId = (await issueTestCard(srv.url, dev)).body.cardId;
      srv.clock.advance(31 * DAY);
      const jwk = currentKey(await getJwks(srv.url), 18, Math.floor(srv.clock.now() / 1000));
      const b = await blindTicket(jwk, ticketPayload(SITE.origin, SITE.challenge, Math.floor(srv.clock.now() / 1000)));
      const r = await requestBlindSignature(srv.url, cardId, dev, jwk.kid, b.blindedMessage);
      assert.equal(r.status, 401);
      assert.equal(r.body.code, 'CARD_REQUIRED');
      assert.equal(r.body.reason, 'card_expired');
    } finally {
      await srv.close();
    }
  });

  it('rate limit: V18_TICKETS_PER_HOUR per card, then 429 with Retry-After', async () => {
    const srv = await startServer({ config: { ticketsPerHour: 3 } });
    try {
      const dev = await TestDevice.es256();
      const cardId = (await issueTestCard(srv.url, dev)).body.cardId;
      for (let i = 0; i < 3; i++) await makeTicket(srv, cardId, dev, SITE);
      const jwk = currentKey(await getJwks(srv.url), 18, Math.floor(srv.clock.now() / 1000));
      const b = await blindTicket(jwk, ticketPayload(SITE.origin, SITE.challenge, Math.floor(srv.clock.now() / 1000)));
      const r = await requestBlindSignature(srv.url, cardId, dev, jwk.kid, b.blindedMessage);
      assert.equal(r.status, 429);
      assert.equal(r.body.code, 'RATE_LIMITED');
      assert.equal(r.headers.get('retry-after'), '3600');

      // another card is not affected
      const dev2 = await TestDevice.es256();
      const card2 = (await issueTestCard(srv.url, dev2)).body.cardId;
      assert.ok(await makeTicket(srv, card2, dev2, SITE));

      srv.clock.advance(HOUR + 1000);
      assert.ok(await makeTicket(srv, cardId, dev, SITE));
    } finally {
      await srv.close();
    }
  });
});
