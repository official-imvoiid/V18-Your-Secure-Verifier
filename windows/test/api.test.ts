import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ApiError, OfflineError, V18Api } from '../src/shared/api.js';

type Call = { url: string; method: string; body: unknown };

function fakeFetch(answer: (c: Call) => { status: number; body: unknown }) {
  const calls: Call[] = [];
  const f = async (url: string, init?: RequestInit) => {
    const c = { url, method: init?.method ?? 'GET', body: init?.body ? JSON.parse(String(init.body)) : undefined };
    calls.push(c);
    const a = answer(c);
    return new Response(JSON.stringify(a.body), { status: a.status, headers: { 'content-type': 'application/json' } });
  };
  return { f, calls };
}

const sig = { alg: 'RS256' as const, sig: 'c2ln' };
const jwk = { kty: 'RSA' as const, n: 'bg', e: 'AQAB', alg: 'RS256' as const };

describe('protocol client', () => {
  it('calls each endpoint with the right method, path and body', async () => {
    const { f, calls } = fakeFetch((c) => {
      if (c.url.endsWith('/challenge')) return { status: 200, body: { challenge: 'a'.repeat(64), expiresAt: 'x' } };
      if (c.url.endsWith('/card/issue')) return { status: 201, body: { cardId: 'card_x', method: 'test_dev', minAgeCertified: 18, validUntil: '2027-01-01T00:00:00Z' } };
      if (c.url.endsWith('/status')) return { status: 200, body: { status: 'active', validUntil: '2027-01-01T00:00:00Z' } };
      if (c.url.endsWith('/card/link/start')) return { status: 201, body: { linkId: 'lnk_1', deepLink: 'v18://link?id=lnk_1', expiresIn: 120 } };
      if (c.url.includes('/card/link/')) return { status: 200, body: { status: 'waiting' } };
      if (c.url.endsWith('/blind-sign')) return { status: 200, body: { blindSignature: 'YQ', keyId: 'k', algorithm: 'RSABSSA-SHA384-PSS-Randomized' } };
      if (c.url.includes('/pairing/') && c.method === 'GET') return { status: 200, body: { sessionId: 's', status: 'waiting', origin: 'https://a.test', challenge: 'c', minAge: 18 } };
      return { status: 200, body: {} };
    });
    const api = new V18Api('http://localhost:8080/v1/', f);
    await api.challenge();
    await api.issueCard({ method: 'test_dev', challenge: 'c', devicePublicKey: jwk, deviceSignature: sig, proof: { testSubjectId: 't', birthDate: '1990-01-01' } });
    await api.deleteCard('card_x/../admin', { challenge: 'c', deviceSignature: sig });
    await api.cardStatus('card_x');
    await api.linkStart({ devicePublicKey: jwk, challenge: 'c', deviceSignature: sig });
    await api.linkPoll('lnk_1');
    await api.blindSign({ cardId: 'card_x', challenge: 'c', keyId: 'k', blindedMessage: 'b', deviceSignature: sig });
    await api.pairingGet('s');
    await api.pairingConnect('s');
    await api.pairingSubmit('s', 'ticket');
    await api.pairingCancel('s');
    assert.deepEqual(
      calls.map((c) => `${c.method} ${c.url.replace('http://localhost:8080/v1', '')}`),
      [
        'POST /challenge',
        'POST /card/issue',
        'DELETE /card/card_x%2F..%2Fadmin',
        'GET /card/card_x/status',
        'POST /card/link/start',
        'GET /card/link/lnk_1',
        'POST /ticket/blind-sign',
        'GET /pairing/s',
        'POST /pairing/s/connect',
        'POST /pairing/s/submit',
        'POST /pairing/s/cancel',
      ],
    );
    assert.deepEqual(calls[2].body, { challenge: 'c', deviceSignature: sig });
    assert.deepEqual(calls[9].body, { ticket: 'ticket' });
  });

  it('turns {"error","code"} answers into ApiError', async () => {
    const { f } = fakeFetch(() => ({ status: 401, body: { error: 'no card', code: 'CARD_REQUIRED' } }));
    await assert.rejects(new V18Api('http://x/v1', f).blindSign({ cardId: 'c', challenge: 'c', keyId: 'k', blindedMessage: 'b', deviceSignature: sig }), (e: unknown) => {
      assert.ok(e instanceof ApiError);
      assert.equal(e.status, 401);
      assert.equal(e.code, 'CARD_REQUIRED');
      return true;
    });
  });

  it('turns network failures into OfflineError', async () => {
    const api = new V18Api('http://x/v1', async () => {
      throw new TypeError('fetch failed');
    });
    await assert.rejects(api.health(), OfflineError);
  });

  it('times out slow servers as offline', async () => {
    const api = new V18Api(
      'http://x/v1',
      (_u, init) =>
        new Promise((_res, rej) => {
          init?.signal?.addEventListener('abort', () => rej(new Error('aborted')));
        }),
      30,
    );
    await assert.rejects(api.health(), /too long/);
  });

  it('checks answers before trusting them', async () => {
    const bad = (body: unknown) => new V18Api('http://x/v1', fakeFetch(() => ({ status: 200, body })).f);
    await assert.rejects(bad({ challenge: 'short' }).challenge(), /bad challenge/);
    await assert.rejects(bad({ status: 'maybe' }).linkPoll('l'), /bad link status/);
    await assert.rejects(bad({ status: 'approved', card: { cardId: 'c', method: 'm', validUntil: 'never' } }).linkPoll('l'), /validUntil/);
    assert.deepEqual(await bad({ keys: [{ kid: 'k', kty: 'RSA', n: 'n', e: 'e' }, { kid: 'x', kty: 'EC' }] }).keys(), [{ kid: 'k', kty: 'RSA', n: 'n', e: 'e' }]);
  });
});
