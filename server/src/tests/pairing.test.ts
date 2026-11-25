import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import { api, startServer, TestServer } from './helpers.js';

const ORIGIN = 'http://localhost:3000';
const CHAL = 'site-challenge-0002'; // 16 to 256 URL-safe characters (PROTOCOL.md 4b item 15)
const FAKE_TICKET = 'v18-age18-20261109.cHJlcGFyZWQ.c2lnbmF0dXJl'; // shape only; the relay does not check signatures

describe('QR hand-off relay (protocol 3.8)', () => {
  let srv: TestServer;
  before(async () => {
    srv = await startServer();
  });
  after(async () => {
    await srv.close();
  });

  const create = (body: Record<string, unknown>, headers: Record<string, string> = {}) =>
    api(srv.url, 'POST', '/v1/pairing/session', body, headers);
  const newSession = async () =>
    (await create({ origin: ORIGIN, challenge: 'site-challenge-0001', minAge: 18, ttlSeconds: 120 })).body.sessionId as string;

  it('creates a session with a 128-bit ID and the full deep link (with server=)', async () => {
    const r = await create({ origin: ORIGIN, challenge: 'abc.123_XYZ~def-456', minAge: 18, ttlSeconds: 120 }, { Origin: ORIGIN });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.match(r.body.sessionId, /^pair_[A-Za-z0-9_-]{22}$/);
    assert.equal(Buffer.from(r.body.sessionId.slice(5), 'base64url').length, 16); // 128 bits
    assert.equal(
      r.body.deepLink,
      `v18://verify?session=${r.body.sessionId}&origin=http%3A%2F%2Flocalhost%3A3000&challenge=abc.123_XYZ~def-456&minAge=18&server=http%3A%2F%2Flocalhost%3A8080`
    );
    assert.equal(r.body.qrData, r.body.deepLink);
    assert.equal(r.body.expiresIn, 120);
    assert.equal(r.body.pollUrl, `/v1/pairing/${r.body.sessionId}`);
    assert.ok(Date.parse(r.body.expiresAt) > srv.clock.now());
  });

  it('session IDs do not repeat', async () => {
    const ids = new Set<string>();
    for (let i = 0; i < 50; i++) ids.add(await newSession());
    assert.equal(ids.size, 50);
  });

  it('refuses a request whose Origin header differs from origin (403 ORIGIN_MISMATCH)', async () => {
    const r = await create({ origin: ORIGIN, challenge: CHAL }, { Origin: 'https://evil.example' });
    assert.equal(r.status, 403);
    assert.equal(r.body.code, 'ORIGIN_MISMATCH');
  });

  it('refuses a bad origin, a missing challenge and an unsupported minAge', async () => {
    assert.equal((await create({ origin: 'localhost:3000', challenge: CHAL })).body.code, 'BAD_ORIGIN');
    assert.equal((await create({ origin: 'http://localhost:3000/path', challenge: CHAL })).body.code, 'BAD_ORIGIN');
    assert.equal((await create({ origin: ORIGIN })).status, 400);
    assert.equal((await create({ origin: ORIGIN, challenge: CHAL, minAge: 21 })).body.code, 'MIN_AGE_UNSUPPORTED');
  });

  it('website challenge must be 16 to 256 URL-safe characters (PROTOCOL.md 4b item 15)', async () => {
    assert.equal((await create({ origin: ORIGIN, challenge: 'a'.repeat(15) })).status, 400);
    assert.equal((await create({ origin: ORIGIN, challenge: 'a'.repeat(257) })).status, 400);
    assert.equal((await create({ origin: ORIGIN, challenge: 'abc/def+ghij=klmnop' })).status, 400);
    assert.equal((await create({ origin: ORIGIN, challenge: 'has space in it 1234' })).status, 400);
    assert.equal((await create({ origin: ORIGIN, challenge: 'a'.repeat(16) })).status, 201);
    assert.equal((await create({ origin: ORIGIN, challenge: 'f'.repeat(64) })).status, 201); // 32 bytes as hex
    assert.equal((await create({ origin: ORIGIN, challenge: 'a'.repeat(256) })).status, 201);
  });

  it('runs waiting -> connected -> approved, and the poll returns the ticket ONCE', async () => {
    const id = await newSession();
    assert.equal((await api(srv.url, 'GET', `/v1/pairing/${id}`)).body.status, 'waiting');
    assert.equal((await api(srv.url, 'POST', `/v1/pairing/${id}/connect`)).status, 200);
    assert.equal((await api(srv.url, 'GET', `/v1/pairing/${id}`)).body.status, 'connected');
    const submit = await api(srv.url, 'POST', `/v1/pairing/${id}/submit`, { ticket: FAKE_TICKET });
    assert.equal(submit.status, 200);

    const first = await api(srv.url, 'GET', `/v1/pairing/${id}`);
    assert.equal(first.body.status, 'approved');
    assert.equal(first.body.ticket, FAKE_TICKET);

    const second = await api(srv.url, 'GET', `/v1/pairing/${id}`);
    assert.equal(second.body.status, 'approved');
    assert.equal(second.body.ticket, undefined, 'ticket is cleared after the first poll');
    assert.equal(second.body.ticketDelivered, true);
  });

  it('accepts a ticket only once (409 ALREADY_SUBMITTED)', async () => {
    const id = await newSession();
    await api(srv.url, 'POST', `/v1/pairing/${id}/connect`);
    assert.equal((await api(srv.url, 'POST', `/v1/pairing/${id}/submit`, { ticket: FAKE_TICKET })).status, 200);
    const again = await api(srv.url, 'POST', `/v1/pairing/${id}/submit`, { ticket: FAKE_TICKET.replace('c2ln', 'eHh4') });
    assert.equal(again.status, 409);
    assert.equal(again.body.code, 'ALREADY_SUBMITTED');
    assert.equal((await api(srv.url, 'GET', `/v1/pairing/${id}`)).body.ticket, FAKE_TICKET, 'the first ticket stays');
  });

  it('refuses a malformed ticket and a second connect', async () => {
    const id = await newSession();
    assert.equal((await api(srv.url, 'POST', `/v1/pairing/${id}/submit`, { ticket: 'not a ticket' })).body.code, 'BAD_TICKET');
    await api(srv.url, 'POST', `/v1/pairing/${id}/connect`);
    const again = await api(srv.url, 'POST', `/v1/pairing/${id}/connect`);
    assert.equal(again.status, 409);
    assert.equal(again.body.code, 'WRONG_STATE');
  });

  it('cancel stops the session', async () => {
    const id = await newSession();
    assert.equal((await api(srv.url, 'POST', `/v1/pairing/${id}/cancel`)).status, 200);
    assert.equal((await api(srv.url, 'GET', `/v1/pairing/${id}`)).body.status, 'cancelled');
    assert.equal((await api(srv.url, 'POST', `/v1/pairing/${id}/submit`, { ticket: FAKE_TICKET })).status, 409);
  });

  it('unknown sessions answer 404 SESSION_NOT_FOUND', async () => {
    for (const path of ['/v1/pairing/pair_AAAAAAAAAAAAAAAAAAAAAA', '/v1/pairing/non-existent-id']) {
      const r = await api(srv.url, 'GET', path);
      assert.equal(r.status, 404);
      assert.equal(r.body.code, 'SESSION_NOT_FOUND');
      assert.equal(r.body.status, 'expired');
    }
    const s = await api(srv.url, 'POST', '/v1/pairing/non-existent-id/submit', { ticket: FAKE_TICKET });
    assert.equal(s.status, 404);
  });

  it('expires after ttlSeconds: poll says "expired", connect and submit get 410', async () => {
    const id = await newSession();
    srv.clock.advance(121_000);
    assert.equal((await api(srv.url, 'GET', `/v1/pairing/${id}`)).body.status, 'expired');
    assert.equal((await api(srv.url, 'POST', `/v1/pairing/${id}/connect`)).status, 410);
    const s = await api(srv.url, 'POST', `/v1/pairing/${id}/submit`, { ticket: FAKE_TICKET });
    assert.equal(s.status, 410);
    assert.equal(s.body.code, 'SESSION_EXPIRED');
  });
});

describe('Per-IP limit on pairing session creation (PROTOCOL.md 4b item 5)', () => {
  it('allows V18_PAIRING_SESSIONS_PER_MINUTE per IP, then 429 with Retry-After, then allows again', async () => {
    const srv = await startServer({ config: { pairingSessionsPerMinute: 3 } });
    try {
      const body = { origin: 'https://any-shop.example', challenge: CHAL };
      const headers = { Origin: 'https://any-shop.example' };
      const ids: string[] = [];
      for (let i = 0; i < 3; i++) {
        const r = await api(srv.url, 'POST', '/v1/pairing/session', body, headers);
        assert.equal(r.status, 201);
        ids.push(r.body.sessionId);
      }
      const over = await api(srv.url, 'POST', '/v1/pairing/session', body, headers);
      assert.equal(over.status, 429);
      assert.equal(over.body.code, 'RATE_LIMITED');
      assert.equal(over.headers.get('retry-after'), '60');
      assert.equal(over.body.retryAfterSeconds, 60);
      // The widget can still read the 429 from any website.
      assert.equal(over.headers.get('access-control-allow-origin'), 'https://any-shop.example');

      // Only creation is limited: polling and cancelling still work.
      for (let i = 0; i < 5; i++) {
        assert.equal((await api(srv.url, 'GET', `/v1/pairing/${ids[0]}`, undefined, headers)).status, 200);
      }
      assert.equal((await api(srv.url, 'POST', `/v1/pairing/${ids[1]}/cancel`, undefined, headers)).status, 200);

      srv.clock.advance(60_001);
      assert.equal((await api(srv.url, 'POST', '/v1/pairing/session', body, headers)).status, 201);
    } finally {
      await srv.close();
    }
  });

  it('bad requests count too, so the limit cannot be dodged with junk', async () => {
    const srv = await startServer({ config: { pairingSessionsPerMinute: 2 } });
    try {
      await api(srv.url, 'POST', '/v1/pairing/session', { origin: 'nope' });
      await api(srv.url, 'POST', '/v1/pairing/session', { origin: 'nope' });
      const r = await api(srv.url, 'POST', '/v1/pairing/session', { origin: ORIGIN, challenge: CHAL });
      assert.equal(r.status, 429);
    } finally {
      await srv.close();
    }
  });

  it('defaults to 30 per minute', async () => {
    const { loadConfig } = await import('../config.js');
    assert.equal(loadConfig({}).pairingSessionsPerMinute, 30);
    assert.equal(loadConfig({ V18_PAIRING_SESSIONS_PER_MINUTE: '5' }).pairingSessionsPerMinute, 5);
    assert.equal(loadConfig({}).trustProxy, false);
    assert.equal(loadConfig({ V18_TRUST_PROXY: '1' }).trustProxy, 1);
    assert.equal(loadConfig({ V18_TRUST_PROXY: 'true' }).trustProxy, true);
    assert.equal(loadConfig({ V18_TRUST_PROXY: 'loopback' }).trustProxy, 'loopback');
  });
});
