import { RSABSSA } from '@cloudflare/blindrsa-ts';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { before, describe, it } from 'node:test';
import type { IssuerJwk } from '../src/shared/api.js';
import { b64urlDecode, b64urlEncode } from '../src/shared/b64url.js';
import { blindTicket, buildTicketPayload, finalizeTicket, pickTicketKey, ticketMessageBytes, verifyTicketString } from '../src/shared/ticket.js';

const ALG = 'RSABSSA-SHA384-PSS-Randomized';

describe('ticket message (PROTOCOL 3.6)', () => {
  it('has exactly the protocol fields, in order, with no spaces', () => {
    const p = buildTicketPayload({ origin: 'https://example-site.test', challenge: 'abc', minAge: 18, nowMs: 1762700000_000, ticketId: 'AAAAAAAAAAAAAAAAAAAAAA' });
    const json = new TextDecoder().decode(ticketMessageBytes(p));
    assert.equal(
      json,
      '{"v":1,"ticketId":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example-site.test","challenge":"abc","minAge":18,"iat":1762700000,"expiresAt":1762700300}',
    );
    assert.deepEqual(Object.keys(JSON.parse(json)), ['v', 'ticketId', 'origin', 'challenge', 'minAge', 'iat', 'expiresAt']);
  });
  it('uses a fresh 16-byte random ticketId', () => {
    const a = buildTicketPayload({ origin: 'https://a.test', challenge: 'c', minAge: 18 });
    const b = buildTicketPayload({ origin: 'https://a.test', challenge: 'c', minAge: 18 });
    assert.equal(b64urlDecode(a.ticketId).length, 16);
    assert.notEqual(a.ticketId, b.ticketId);
  });
  it('never lives longer than 300 seconds', () => {
    const p = buildTicketPayload({ origin: 'https://a.test', challenge: 'c', minAge: 18, lifetime: 7200 });
    assert.equal(p.expiresAt - p.iat, 300);
  });
  it('escapes origin and challenge as JSON strings', () => {
    const p = buildTicketPayload({ origin: 'https://a.test', challenge: 'x"y\\z', minAge: 18 });
    assert.equal(JSON.parse(new TextDecoder().decode(ticketMessageBytes(p))).challenge, 'x"y\\z');
  });
});

describe('ticket key choice', () => {
  const now = 1_800_000_000;
  const k = (kid: string, extra: Partial<IssuerJwk>): IssuerJwk => ({ kid, kty: 'RSA', n: 'n', e: 'AQAB', alg: ALG, v18_min_age: 18, nbf: now - 100, exp: now + 100, ...extra });
  it('takes the current key, not the previous or the next one', () => {
    const keys = [k('prev', { nbf: now - 1000, exp: now - 10 }), k('cur', {}), k('next', { nbf: now + 50, exp: now + 1000 })];
    assert.equal(pickTicketKey(keys, 18, now)?.kid, 'cur');
  });
  it('prefers the newest key during an overlap', () => {
    const keys = [k('old', { nbf: now - 1000 }), k('new', { nbf: now - 10 })];
    assert.equal(pickTicketKey(keys, 18, now)?.kid, 'new');
  });
  it('skips keys with the wrong algorithm or a lower age', () => {
    assert.equal(pickTicketKey([k('a', { alg: 'PS384' }), k('b', { v18_min_age: 16 })], 18, now), null);
  });
});

describe('blind ticket round trip with @cloudflare/blindrsa-ts', () => {
  let issuer: IssuerJwk;
  let privateKey: CryptoKey;
  const suite = RSABSSA.SHA384.PSS.Randomized();

  before(async () => {
    const kp = await suite.generateKey({ modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) });
    privateKey = kp.privateKey;
    const jwk = (await webcrypto.subtle.exportKey('jwk', kp.publicKey as webcrypto.CryptoKey)) as { n: string; e: string };
    issuer = { kid: 'v18-age18-20261109', kty: 'RSA', n: jwk.n, e: jwk.e, alg: ALG, v18_min_age: 18 };
  });

  it('blinds, gets signed blind, unblinds, and the ticket verifies like a website would check it', async () => {
    const payload = buildTicketPayload({ origin: 'https://example-site.test', challenge: 'site-challenge-123', minAge: 18 });
    const b = await blindTicket(issuer, payload);
    // prepared = 32 random bytes + message
    assert.equal(b.prepared.length, 32 + ticketMessageBytes(payload).length);
    assert.deepEqual([...b.prepared.slice(32)], [...ticketMessageBytes(payload)]);
    // The server only ever sees the blinded message, which does not contain the payload.
    assert.ok(!Buffer.from(b64urlDecode(b.blindedMessage)).includes(Buffer.from('example-site')));
    const blindSig = await suite.blindSign(privateKey, b64urlDecode(b.blindedMessage));
    const ticket = await finalizeTicket(b, b64urlEncode(blindSig));
    const [kid, prep, sig] = ticket.split('.');
    assert.equal(kid, 'v18-age18-20261109');
    assert.equal(prep, b64urlEncode(b.prepared));
    assert.equal(b64urlDecode(sig).length, 256);
    const v = await verifyTicketString(ticket, issuer);
    assert.equal(v.ok, true);
    assert.deepEqual(v.payload, payload);
  });

  it('refuses a blind signature that does not match', async () => {
    const b = await blindTicket(issuer, buildTicketPayload({ origin: 'https://a.test', challenge: 'cccccccc', minAge: 18 }));
    const other = await blindTicket(issuer, buildTicketPayload({ origin: 'https://a.test', challenge: 'dddddddd', minAge: 18 }));
    const wrong = await suite.blindSign(privateKey, b64urlDecode(other.blindedMessage));
    await assert.rejects(finalizeTicket(b, b64urlEncode(wrong)));
  });

  it('makes tickets that look different every time (unlinkable)', async () => {
    const p = buildTicketPayload({ origin: 'https://a.test', challenge: 'cccccccc', minAge: 18, ticketId: 'AAAAAAAAAAAAAAAAAAAAAA', nowMs: 0 });
    const b1 = await blindTicket(issuer, p);
    const b2 = await blindTicket(issuer, p);
    assert.notEqual(b1.blindedMessage, b2.blindedMessage);
    assert.notEqual(b64urlEncode(b1.prepared), b64urlEncode(b2.prepared));
  });
});
