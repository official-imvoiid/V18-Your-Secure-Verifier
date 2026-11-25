import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { api, issueTestCard, startServer, TestDevice, TestServer } from './helpers.js';

describe('HTTP basics', () => {
  let srv: TestServer;
  before(async () => {
    srv = await startServer();
  });
  after(async () => {
    await srv.close();
  });

  it('GET /v1/health reports devMode and the method status', async () => {
    const r = await api(srv.url, 'GET', '/v1/health');
    assert.equal(r.status, 200);
    assert.equal(r.body.status, 'ok');
    assert.equal(r.body.service, 'v18-server');
    assert.equal(r.body.protocolVersion, 1);
    assert.equal(r.body.devMode, true);
    assert.deepEqual(r.body.methods, {
      test_dev: 'ready',
      anon_aadhaar: 'not_configured',
      emrtd_attested: 'ready',
      passport_attested: 'ready',
      philsys_qr_attested: 'ready',
      mynumber_attested: 'disabled',
      face_estimate: 'disabled',
      mdoc_wallet: 'not_configured',
      mdoc_app: 'not_configured',
      passport_zk: 'not_ready',
    });
    assert.deepEqual(r.body.connectors, []);
    assert.equal(r.body.nullifierKeyId, 'v18-nullifier-1');
    assert.equal(r.body.storage, process.env.V18_TEST_DB === 'postgres' ? 'postgres' : 'sqlite');
  });

  it('serves the API under /v1 only, with JSON 404s', async () => {
    const old = await api(srv.url, 'GET', '/health');
    assert.equal(old.status, 404);
    assert.equal(old.body.code, 'NOT_FOUND');
  });

  it('answers bad JSON with 400 BAD_JSON and never echoes the body', async () => {
    const res = await fetch(`${srv.url}/v1/card/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"proof": "SECRET-MARKER-1990-01-01" ',
    });
    const text = await res.text();
    assert.equal(res.status, 400);
    assert.equal(JSON.parse(text).code, 'BAD_JSON');
    assert.ok(!text.includes('SECRET-MARKER'));
  });

  it('refuses bodies over 64 KB with 413 (256 KB only where proofs, chains and wallet answers go)', async () => {
    const r = await api(srv.url, 'POST', '/v1/pairing/session', { pad: 'x'.repeat(70_000) });
    assert.equal(r.status, 413);
    assert.equal(r.body.code, 'BODY_TOO_LARGE');
    const ok = await api(srv.url, 'POST', '/v1/card/issue', { pad: 'x'.repeat(70_000) });
    assert.notEqual(ok.status, 413, 'card issue takes up to 256 KB');
    const big = await api(srv.url, 'POST', '/v1/card/issue', { pad: 'x'.repeat(270_000) });
    assert.equal(big.status, 413);
  });

  it('sends security headers (helmet): no framing, no sniffing, no referrer, CSP default-src none', async () => {
    const r = await api(srv.url, 'GET', '/v1/health');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-frame-options'), 'SAMEORIGIN');
    assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
    assert.match(r.headers.get('content-security-policy') ?? '', /default-src 'none'/);
    assert.match(r.headers.get('content-security-policy') ?? '', /frame-ancestors 'none'/);
    assert.equal(r.headers.get('cross-origin-resource-policy'), 'cross-origin');
    assert.equal(r.headers.get('x-powered-by'), null);
  });

  it('serves /metrics in Prometheus format with route patterns only (no IDs)', async () => {
    await api(srv.url, 'GET', '/v1/card/card_AAAAAAAAAAAAAAAAAAAAAA/status');
    const res = await fetch(`${srv.url}/metrics`);
    const text = await res.text();
    assert.equal(res.status, 200);
    assert.ok(text.includes('v18_http_requests_total{method="GET",route="/v1/card/:cardId/status",status="404"} 1'), text.slice(0, 400));
    assert.ok(!text.includes('card_AAAA'), 'no real IDs in metrics');
    assert.match(text, /v18_cards_active /);
  });

  it('does not log request bodies (console is watched during requests)', async () => {
    const marker = 'PRIVATE-MARKER-' + Date.now();
    const seen: string[] = [];
    const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
    const originals = methods.map((m) => console[m]);
    methods.forEach((m) => {
      console[m] = (...a: unknown[]) => {
        seen.push(a.map(String).join(' '));
      };
    });
    try {
      await issueTestCard(srv.url, await TestDevice.es256(), { testSubjectId: marker, birthDate: '1990-01-01' });
      await issueTestCard(srv.url, await TestDevice.es256(), { testSubjectId: marker, birthDate: '2015-01-01' });
      await fetch(`${srv.url}/v1/pairing/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: `{"origin":"${marker}`,
      });
      await api(srv.url, 'POST', '/v1/ticket/blind-sign', { cardId: marker, blindedMessage: marker });
    } finally {
      methods.forEach((m, i) => (console[m] = originals[i]));
    }
    assert.ok(!seen.join('\n').includes(marker), 'a request body reached the console');
  });

  it('no console call in the server code mentions a request body (source scan)', () => {
    const root = path.resolve(__dirname, '..');
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory() && e.name !== 'tests') walk(p);
        else if (e.isFile() && p.endsWith('.js')) files.push(p);
      }
    };
    walk(root);
    assert.ok(files.length > 10);
    for (const f of files) {
      for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
        if (line.includes('console.')) {
          assert.ok(!/body/i.test(line), `${path.basename(f)}: ${line.trim()}`);
        }
      }
    }
  });
});

const ACAO = 'access-control-allow-origin';
const SHOP = 'https://any-shop.example'; // a website on no list

/** Preflight request as a browser would send it. */
const preflight = (base: string, path: string, origin: string, method: string) =>
  fetch(`${base}${path}`, {
    method: 'OPTIONS',
    headers: { Origin: origin, 'Access-Control-Request-Method': method, 'Access-Control-Request-Headers': 'content-type' },
  });

describe('CORS: app endpoints use the allowlist', () => {
  it('dev mode allows the demo origin on app endpoints (with DELETE)', async () => {
    const srv = await startServer();
    try {
      const ok = await api(srv.url, 'POST', '/v1/challenge', undefined, { Origin: 'http://localhost:3000' });
      assert.equal(ok.headers.get(ACAO), 'http://localhost:3000');

      const pre = await preflight(srv.url, '/v1/card/card_x', 'http://localhost:3000', 'DELETE');
      assert.equal(pre.status, 204);
      assert.match(pre.headers.get('access-control-allow-methods') ?? '', /DELETE/);
    } finally {
      await srv.close();
    }
  });

  it('an unlisted website gets NO CORS headers on any app endpoint', async () => {
    const srv = await startServer();
    try {
      const card = await api(srv.url, 'POST', '/v1/card/issue', { method: 'test_dev' }, { Origin: SHOP });
      assert.equal(card.headers.get(ACAO), null);
      assert.equal((await preflight(srv.url, '/v1/card/issue', SHOP, 'POST')).headers.get(ACAO), null);

      const appCalls: [string, string][] = [
        ['POST', '/v1/challenge'],
        ['POST', '/v1/ticket/blind-sign'],
        ['GET', '/v1/card/card_AAAAAAAAAAAAAAAAAAAAAA/status'],
        ['DELETE', '/v1/card/card_AAAAAAAAAAAAAAAAAAAAAA'],
        ['POST', '/v1/card/link/start'],
        ['POST', '/v1/card/link/link_AAAAAAAAAAAAAAAAAAAAAA/approve'],
        ['GET', '/v1/card/link/link_AAAAAAAAAAAAAAAAAAAAAA'],
        ['POST', '/v1/pairing/pair_AAAAAAAAAAAAAAAAAAAAAA/connect'],
        ['POST', '/v1/pairing/pair_AAAAAAAAAAAAAAAAAAAAAA/submit'],
      ];
      for (const [method, path] of appCalls) {
        const r = await api(srv.url, method, path, method === 'GET' ? undefined : {}, { Origin: SHOP });
        assert.equal(r.headers.get(ACAO), null, `${method} ${path}`);
        const pre = await preflight(srv.url, path, SHOP, method);
        assert.equal(pre.headers.get(ACAO), null, `preflight ${method} ${path}`);
      }
    } finally {
      await srv.close();
    }
  });

  it('production allows only V18_CORS_ORIGINS on app endpoints (the demo origin is not added)', async () => {
    const srv = await startServer({ config: { devMode: false, corsOrigins: ['https://shop.example'] } });
    try {
      const shop = await api(srv.url, 'POST', '/v1/challenge', undefined, { Origin: 'https://shop.example' });
      assert.equal(shop.headers.get(ACAO), 'https://shop.example');
      const demo = await api(srv.url, 'POST', '/v1/challenge', undefined, { Origin: 'http://localhost:3000' });
      assert.equal(demo.headers.get(ACAO), null);
    } finally {
      await srv.close();
    }
  });
});

describe('CORS: widget endpoints are open to any website (PROTOCOL.md 4b item 5)', () => {
  for (const devMode of [true, false]) {
    it(`${devMode ? 'dev' : 'production'}: an unlisted website can read health and keys, create, poll and cancel a pairing session`, async () => {
      const srv = await startServer({ config: { devMode } });
      try {
        const check = (r: { headers: Headers }, label: string) => {
          assert.equal(r.headers.get(ACAO), SHOP, label);
          assert.match(r.headers.get('vary') ?? '', /Origin/, `${label}: Vary`);
          assert.equal(r.headers.get('access-control-allow-credentials'), null, `${label}: no credentials`);
        };
        check(await api(srv.url, 'GET', '/v1/health', undefined, { Origin: SHOP }), 'health');
        check(await api(srv.url, 'GET', '/v1/keys', undefined, { Origin: SHOP }), 'keys');
        check(await api(srv.url, 'GET', '/v1/keys/pem', undefined, { Origin: SHOP }), 'pem');

        const pre = await preflight(srv.url, '/v1/pairing/session', SHOP, 'POST');
        assert.equal(pre.status, 204);
        check(pre, 'preflight session');
        assert.match(pre.headers.get('access-control-allow-methods') ?? '', /POST/);
        assert.match(pre.headers.get('access-control-allow-headers') ?? '', /Content-Type/i);

        const created = await api(
          srv.url,
          'POST',
          '/v1/pairing/session',
          { origin: SHOP, challenge: 'any-shop-visit-challenge-01' },
          { Origin: SHOP }
        );
        assert.equal(created.status, 201, JSON.stringify(created.body));
        check(created, 'create session');
        const id = created.body.sessionId;

        check(await api(srv.url, 'GET', `/v1/pairing/${id}`, undefined, { Origin: SHOP }), 'poll');
        check(await preflight(srv.url, `/v1/pairing/${id}/cancel`, SHOP, 'POST'), 'preflight cancel');
        const cancel = await api(srv.url, 'POST', `/v1/pairing/${id}/cancel`, undefined, { Origin: SHOP });
        assert.equal(cancel.status, 200);
        check(cancel, 'cancel');
      } finally {
        await srv.close();
      }
    });
  }

  it('still refuses a session whose Origin header differs from origin, but the widget can read the error', async () => {
    const srv = await startServer();
    try {
      const r = await api(
        srv.url,
        'POST',
        '/v1/pairing/session',
        { origin: 'https://victim.example', challenge: 'any-shop-visit-challenge-01' },
        { Origin: SHOP }
      );
      assert.equal(r.status, 403);
      assert.equal(r.body.code, 'ORIGIN_MISMATCH');
      assert.equal(r.headers.get(ACAO), SHOP);
    } finally {
      await srv.close();
    }
  });

  it('does not echo "null" or malformed origins', async () => {
    const srv = await startServer();
    try {
      for (const bad of ['null', 'https://shop.example/path', 'file://']) {
        const r = await api(srv.url, 'GET', '/v1/health', undefined, { Origin: bad });
        assert.equal(r.headers.get(ACAO), null, bad);
      }
    } finally {
      await srv.close();
    }
  });
});
