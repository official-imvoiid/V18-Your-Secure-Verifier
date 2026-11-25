/**
 * Production storage (4c.7): the encrypted key store (V18_KEK and the KMS
 * adapter), and several server copies sharing ONE database (all state:
 * challenges, rate limits, pairing sessions, links, cards and keys).
 * Runs on SQLite (a shared file) and on PostgreSQL (npm run test:pg).
 */
import 'reflect-metadata';
import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { KmsClient, KmsKeyWrapper, LocalKekWrapper } from '../keys/wrap.js';
import { api, FakeClock, freshDatabase, TEST_DB, issueTestCard, makeTicket, newChallenge, ss, startServer, TestDevice, TestServer } from './helpers.js';

/** One database that several test servers share. */
async function sharedDb(): Promise<{ config: Record<string, unknown>; drop(): Promise<void> }> {
  const pg = await freshDatabase();
  if (pg) return { config: { databaseUrl: pg.url }, drop: pg.drop };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-shared-'));
  return {
    config: { databaseUrl: null, dbPath: path.join(dir, 'v18.sqlite') },
    drop: async () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

const KEK = crypto.randomBytes(32);

describe('Encrypted key store (V18_KEK)', () => {
  let db: Awaited<ReturnType<typeof sharedDb>>;
  before(async () => {
    db = await sharedDb();
  });
  after(async () => db.drop());

  it('keeps every private key sealed with AES-256-GCM; the same KEK reopens them; another KEK cannot', async () => {
    const clock = new FakeClock();
    const a = await startServer({ clock, keyStore: undefined as never, config: { keyStore: 'db', kek: KEK, ...db.config } });
    const jwksA = (await api(a.url, 'GET', '/v1/keys')).body;
    const nkA = (await api(a.url, 'GET', '/v1/keys/nullifier')).body;
    const rows = await a.services.db.all<{ kid: string; wrapped_private: string }>('SELECT kid, wrapped_private FROM signing_keys');
    assert.equal(rows.length, 3, 'current and next ticket keys plus the nullifier key');
    for (const r of rows) {
      assert.match(r.wrapped_private, /^kek1\.[0-9a-f]{8}\./);
      assert.ok(!r.wrapped_private.includes('"d"'), 'no plain private key in the database');
    }
    // A card and ticket work with the sealed keys.
    const dev = await TestDevice.es256();
    const card = await issueTestCard(a.url, dev);
    assert.ok(await makeTicket(a, card.body.cardId, dev, { origin: 'https://site.test', challenge: 'k'.repeat(20) }));
    await a.close();

    const b = await startServer({ clock, keyStore: undefined as never, config: { keyStore: 'db', kek: KEK, ...db.config } });
    assert.deepEqual((await api(b.url, 'GET', '/v1/keys')).body, jwksA, 'same keys after a restart');
    assert.deepEqual((await api(b.url, 'GET', '/v1/keys/nullifier')).body, nkA, 'the nullifier key never changes');
    await b.close();

    await assert.rejects(
      startServer({ clock, keyStore: undefined as never, config: { keyStore: 'db', kek: crypto.randomBytes(32), ...db.config } }),
      /sealed with another V18_KEK/
    );
  });

  it('production refuses the plain file key store and a missing KEK', async () => {
    await assert.rejects(startServer({ keyStore: undefined as never, config: { devMode: false, keyStore: 'file', aadhaarNullifierSeed: '1' } }), /V18_KEK/);
    await assert.rejects(startServer({ keyStore: undefined as never, config: { devMode: false, keyStore: 'db', kek: null, aadhaarNullifierSeed: '1' } }), /V18_KEK/);
  });

  it('a sealed key cannot be moved to another key ID (AES-GCM additional data)', async () => {
    const w = new LocalKekWrapper(KEK);
    const sealed = await w.wrap(Buffer.from('secret'), 'v18-age18-20261109');
    assert.equal((await w.unwrap(sealed, 'v18-age18-20261109')).toString(), 'secret');
    await assert.rejects(w.unwrap(sealed, 'v18-age18-20261116'), /could not be decrypted/);
  });
});

describe('KMS key wrapper (envelope encryption)', () => {
  /** TEST stand-in for a cloud KMS: AES-GCM under a key that never leaves this object. */
  class FakeKms implements KmsClient {
    readonly name = 'test-kms';
    calls = 0;
    private readonly key = crypto.randomBytes(32);
    async encrypt(plain: Buffer, context: string) {
      this.calls++;
      const iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv('aes-256-gcm', this.key, iv).setAAD(Buffer.from(context));
      const body = Buffer.concat([c.update(plain), c.final()]);
      return Buffer.concat([iv, c.getAuthTag(), body]);
    }
    async decrypt(blob: Buffer, context: string) {
      this.calls++;
      const d = crypto.createDecipheriv('aes-256-gcm', this.key, blob.subarray(0, 12)).setAAD(Buffer.from(context));
      d.setAuthTag(blob.subarray(12, 28));
      return Buffer.concat([d.update(blob.subarray(28)), d.final()]);
    }
  }

  it('seals each key with a fresh data key that only the KMS can open', async () => {
    const kms = new FakeKms();
    const db = await sharedDb();
    const srv = await startServer({ keyStore: undefined as never, keyWrapper: new KmsKeyWrapper(kms), config: { keyStore: 'db', ...db.config } });
    const rows = await srv.services.db.all<{ wrapped_private: string }>('SELECT wrapped_private FROM signing_keys');
    assert.ok(rows.every((r) => r.wrapped_private.startsWith('kms1.')));
    assert.ok(kms.calls >= 3);
    const dev = await TestDevice.es256();
    const card = await issueTestCard(srv.url, dev);
    assert.ok(await makeTicket(srv, card.body.cardId, dev, { origin: 'https://site.test', challenge: 'm'.repeat(20) }));
    await srv.close();
    await db.drop();
  });
});

describe('Several server copies on one database', () => {
  let db: Awaited<ReturnType<typeof sharedDb>>;
  let a: TestServer;
  let b: TestServer;
  before(async () => {
    db = await sharedDb();
    const clock = new FakeClock();
    const common = { keyStore: 'db' as const, kek: KEK, pairingSessionsPerMinute: 3, ...db.config };
    a = await startServer({ clock, keyStore: undefined as never, config: common });
    b = await startServer({ clock, keyStore: undefined as never, config: common });
  });
  after(async () => {
    await a.close();
    await b.close();
    await db.drop();
  });

  it('publish the same JWKS and nullifier key', async () => {
    assert.deepEqual((await api(a.url, 'GET', '/v1/keys')).body, (await api(b.url, 'GET', '/v1/keys')).body);
    assert.deepEqual((await api(a.url, 'GET', '/v1/keys/nullifier')).body, (await api(b.url, 'GET', '/v1/keys/nullifier')).body);
  });

  it('a challenge from copy A is used up on copy B, once', async () => {
    const dev = await TestDevice.es256();
    const challenge = await newChallenge(a.url);
    const body = { method: 'test_dev', challenge, devicePublicKey: dev.jwkWithAlg, deviceSignature: dev.sign(ss.cardIssue(challenge, dev.thumbprint)), proof: { testSubjectId: 'multi-1', birthDate: '1990-01-01' } };
    assert.equal((await api(b.url, 'POST', '/v1/card/issue', body)).status, 201);
    assert.equal((await api(a.url, 'POST', '/v1/card/issue', body)).body.code, 'CHALLENGE_INVALID');
  });

  it('a card made on A gets tickets on B; a QR session made on A is filled on B and delivered once on A', async () => {
    const dev = await TestDevice.es256();
    const card = await issueTestCard(a.url, dev);
    const s = await api(a.url, 'POST', '/v1/pairing/session', { origin: 'https://site.test', challenge: 'multi-instance-challenge' });
    const ticket = await makeTicket(b, card.body.cardId, dev, { origin: 'https://site.test', challenge: 'multi-instance-challenge' });
    assert.equal((await api(b.url, 'POST', `/v1/pairing/${s.body.sessionId}/connect`)).status, 200);
    assert.equal((await api(b.url, 'POST', `/v1/pairing/${s.body.sessionId}/submit`, { ticket })).status, 200);
    assert.equal((await api(a.url, 'POST', `/v1/pairing/${s.body.sessionId}/submit`, { ticket })).body.code, 'ALREADY_SUBMITTED');
    assert.equal((await api(a.url, 'GET', `/v1/pairing/${s.body.sessionId}`)).body.ticket, ticket);
    assert.equal((await api(b.url, 'GET', `/v1/pairing/${s.body.sessionId}`)).body.ticket, undefined, 'once, across copies');
  });

  it('a device link started on A is approved on B and collected on A', async () => {
    const phone = await TestDevice.es256();
    const phoneCard = await issueTestCard(a.url, phone);
    const pc = await TestDevice.rs256();
    const c1 = await newChallenge(a.url);
    const start = await api(a.url, 'POST', '/v1/card/link/start', { devicePublicKey: pc.jwkWithAlg, challenge: c1, deviceSignature: pc.sign(ss.cardIssue(c1, pc.thumbprint)) });
    const c2 = await newChallenge(b.url);
    const ok = await api(b.url, 'POST', `/v1/card/link/${start.body.linkId}/approve`, {
      cardId: phoneCard.body.cardId,
      challenge: c2,
      deviceSignature: phone.sign(ss.linkApprove(phoneCard.body.cardId, c2, start.body.linkId)),
    });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal((await api(a.url, 'GET', `/v1/card/link/${start.body.linkId}`)).body.card.method, 'test_dev');
  });

  it('share rate limits (3 QR sessions per minute per IP across both copies)', async () => {
    const make = (srv: TestServer) => api(srv.url, 'POST', '/v1/pairing/session', { origin: 'https://site.test', challenge: 'rate-limit-shared-x' });
    // One session was made in the test above, on A.
    assert.equal((await make(b)).status, 201);
    assert.equal((await make(a)).status, 201);
    const fourth = await make(b);
    assert.equal(fourth.status, 429);
    assert.equal(fourth.body.code, 'RATE_LIMITED');
  });

  // Two SQLite connections in ONE process would block each other (SQLite locks
  // synchronously); SQLite deployments run one server copy. PostgreSQL runs this.
  it('the nullifier cap holds when two copies issue at the same time', { skip: TEST_DB === 'sqlite' ? 'SQLite: one server copy only (tested on PostgreSQL)' : false }, async () => {
    const devs = await Promise.all(Array.from({ length: 6 }, () => TestDevice.es256()));
    const results = await Promise.all(devs.map((d, i) => issueTestCard(i % 2 ? a.url : b.url, d, { testSubjectId: 'race-subject', birthDate: '1990-01-01' })));
    const created = results.filter((r) => r.status === 201).length;
    assert.equal(created, 3, results.map((r) => `${r.status} ${r.body.code ?? ''}`).join(', '));
    assert.ok(results.filter((r) => r.status !== 201).every((r) => r.body.code === 'NULLIFIER_OVERUSED'));
  });
});
