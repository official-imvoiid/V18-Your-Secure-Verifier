import { describe, it, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { FileKeyStore, MemoryKeyStore } from '../keys/keystore.js';
import { TicketKeyService } from '../keys/ticket-keys.js';
import { api, DAY, FakeClock, startServer } from './helpers.js';

const KID = /^v18-age\d{1,2}-\d{8}$/;

describe('Ticket keys (protocol 3.2)', () => {
  const tmpDirs: string[] = [];
  after(() => {
    for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true });
  });

  it('GET /v1/keys lists current and next keys per threshold with every required field', async () => {
    const srv = await startServer({ config: { ageThresholds: [18, 21] } });
    try {
      const r = await api(srv.url, 'GET', '/v1/keys');
      assert.equal(r.status, 200);
      assert.match(r.headers.get('cache-control') ?? '', /max-age=300/);
      const keys = r.body.keys;
      assert.equal(keys.length, 4); // no previous key yet on a fresh server
      const now = Math.floor(srv.clock.now() / 1000);
      for (const k of keys) {
        assert.match(k.kid, KID);
        assert.equal(k.kty, 'RSA');
        assert.equal(k.use, 'sig');
        assert.equal(k.alg, 'RSABSSA-SHA384-PSS-Randomized');
        assert.equal(typeof k.n, 'string');
        assert.equal(k.e, 'AQAB');
        assert.ok(Number.isInteger(k.v18_min_age));
        assert.ok(Number.isInteger(k.nbf) && Number.isInteger(k.exp));
        assert.equal(k.exp - k.nbf, 7 * 86400);
        assert.equal(Buffer.from(k.n, 'base64url').length, 256); // RSA-2048
        assert.ok(!('d' in k), 'no private parts');
      }
      const current18 = keys.find((k: any) => k.v18_min_age === 18 && k.nbf <= now && now < k.exp);
      assert.equal(current18.kid, 'v18-age18-20261109'); // starts today (UTC)
      assert.ok(keys.find((k: any) => k.v18_min_age === 18 && k.nbf === current18.exp), 'next key is published');
      assert.ok(keys.find((k: any) => k.kid === 'v18-age21-20261109'));
    } finally {
      await srv.close();
    }
  });

  it('rotates every V18_KEY_ROTATION_DAYS and lists previous, current and next', async () => {
    const clock = new FakeClock();
    const store = new MemoryKeyStore();
    const svc = new TicketKeyService(store, { thresholds: [18], rotationDays: 7, modulusBits: 2048 }, clock.now);
    await svc.refresh();
    assert.deepEqual(svc.published().map((k) => k.kid), ['v18-age18-20261109', 'v18-age18-20261116']);

    clock.advance(7 * DAY);
    await svc.refresh();
    assert.deepEqual(svc.published().map((k) => k.kid), ['v18-age18-20261109', 'v18-age18-20261116', 'v18-age18-20261123']);
    assert.equal(svc.currentKey(18).kid, 'v18-age18-20261116');

    clock.advance(7 * DAY);
    await svc.refresh();
    assert.deepEqual(svc.published().map((k) => k.kid), ['v18-age18-20261116', 'v18-age18-20261123', 'v18-age18-20261130']);
    // Keys older than "previous" are deleted from the store.
    assert.equal((await store.list()).length, 3);
    svc.close();
  });

  it('keeps keys across restarts (dev file store)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-keys-'));
    tmpDirs.push(dir);
    const clock = new FakeClock();
    const a = new TicketKeyService(await FileKeyStore.open(dir), { thresholds: [18], rotationDays: 7, modulusBits: 2048 }, clock.now);
    await a.refresh();
    const before = a.jwks().keys;
    a.close();

    const files = fs.readdirSync(dir).sort();
    assert.deepEqual(files, ['v18-age18-20261109.json', 'v18-age18-20261116.json']);

    // "Restart": a new service on the same folder must reuse the same keys.
    const b = new TicketKeyService(await FileKeyStore.open(dir), { thresholds: [18], rotationDays: 7, modulusBits: 2048 }, clock.now);
    await b.refresh();
    assert.deepEqual(b.jwks().keys, before);

    // And the reloaded private key still signs for the same public key.
    const key = b.currentKey(18);
    const m = new Uint8Array(256);
    m[255] = 7;
    const sig = await b.blindSign(key, m);
    const pub = crypto.createPublicKey({ key: key.publicJwk, format: 'jwk' });
    const back = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_NO_PADDING }, Buffer.from(sig));
    assert.deepEqual(new Uint8Array(back), m); // s^e mod n == m
    b.close();
  });

  it('a whole server restart on the same data folder publishes the same JWKS', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-data-'));
    tmpDirs.push(dir);
    const clock = new FakeClock();
    const cfg = { dataDir: dir, keyDir: path.join(dir, 'keys'), dbPath: path.join(dir, 'v18.sqlite') };
    const s1 = await startServer({ clock, keyStore: await FileKeyStore.open(cfg.keyDir), config: cfg });
    const k1 = (await api(s1.url, 'GET', '/v1/keys')).body;
    await s1.close();
    const s2 = await startServer({ clock, keyStore: await FileKeyStore.open(cfg.keyDir), config: cfg });
    const k2 = (await api(s2.url, 'GET', '/v1/keys')).body;
    await s2.close();
    assert.deepEqual(k2, k1);
  });

  it('GET /v1/keys/pem returns the current key, or the key named by ?kid=', async () => {
    const srv = await startServer();
    try {
      const keys = (await api(srv.url, 'GET', '/v1/keys')).body.keys;
      const current = await api(srv.url, 'GET', '/v1/keys/pem');
      assert.equal(current.status, 200);
      assert.match(current.body, /^-----BEGIN PUBLIC KEY-----/);
      const fromPem = crypto.createPublicKey(current.body).export({ format: 'jwk' });
      assert.equal(fromPem.n, keys[0].n);

      const next = await api(srv.url, 'GET', `/v1/keys/pem?kid=${keys[1].kid}`);
      assert.equal(crypto.createPublicKey(next.body).export({ format: 'jwk' }).n, keys[1].n);

      const missing = await api(srv.url, 'GET', '/v1/keys/pem?kid=v18-age18-19990101');
      assert.equal(missing.status, 404);
      assert.equal(missing.body.code, 'KEY_NOT_FOUND');
    } finally {
      await srv.close();
    }
  });
});
