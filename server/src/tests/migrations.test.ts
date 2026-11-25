/**
 * Migrations: the dev-database bug and the guard against it.
 *
 * What happened: server/data/v18.sqlite applied 003 on 2026-11-19 while its
 * cards table still listed only five methods; 003 was edited later, but a
 * database never re-runs an applied migration, so cards for emrtd_attested,
 * mdoc_app and connectors failed with 500. Migration 004 fixes such databases,
 * and a checksum per applied migration now stops the server if an applied file
 * is ever edited again.
 *
 * Runs on SQLite (npm test) and PostgreSQL (npm run test:pg).
 */
import 'reflect-metadata';
import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { ConnectorLike, RegistryLike } from '../connect/service.js';
import { MIGRATIONS_DIR, migrationChecksum, openPostgres, openSqlite, SqlDb } from '../db/sql.js';
import { PinnedVkeyVerifier, stopSnarkjsCurve } from '../issuers/anon-aadhaar.js';
import { serverRoot } from '../config.js';
import { createTestIaca, issueTestMdoc, newHolderKey, testWalletAnswer } from '../wallet/test-wallet.js';
import { api, freshDatabase, issueTestCard, makeTicket, newChallenge, ss, startServer, TEST_DB, TestDevice, TestServer } from './helpers.js';

const OLD_003 = TEST_DB === 'postgres' ? '003_phase2.sql' : '003_phase2_sqlite.sql';

/** A database (file or PostgreSQL) that this test controls. */
async function scratchDb() {
  const pg = await freshDatabase();
  if (pg) {
    return {
      config: { databaseUrl: pg.url },
      open: (o: { upTo?: string; migrationsDir?: string } = {}) => openPostgres(pg.url, o),
      drop: pg.drop,
    };
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-mig-'));
  const file = path.join(dir, 'v18.sqlite');
  return {
    config: { databaseUrl: null, dbPath: file },
    open: async (o: { upTo?: string; migrationsDir?: string } = {}) => openSqlite(file, o),
    drop: async () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

async function insertOldCard(db: SqlDb, cardId: string, method: string, nullifier: string): Promise<void> {
  await db.run('INSERT INTO nullifiers (nullifier_hash, issuer_id, created_at) VALUES (?, ?, ?) ON CONFLICT (nullifier_hash) DO NOTHING', [
    nullifier,
    method,
    '2026-11-01T00:00:00.000Z',
  ]);
  const dev = await TestDevice.es256();
  await db.run(
    `INSERT INTO cards (card_id, method, assurance_level, min_age_certified, device_key_alg, device_key_jwk,
       device_key_thumbprint, nullifier_hash, status, issued_at, valid_until, revoked_at)
     VALUES (?, ?, 'test', 18, 'ES256', ?, ?, ?, 'active', '2026-11-01T00:00:00.000Z', '2027-01-01T00:00:00.000Z', NULL)`,
    [cardId, method, JSON.stringify(dev.publicJwk), dev.thumbprint, nullifier]
  );
}

describe('Migration 004 repairs a database that ran the first version of 003', () => {
  let db: Awaited<ReturnType<typeof scratchDb>>;
  let srv: TestServer;
  const oldCards = ['card_AAAAAAAAAAAAAAAAAAAAAA', 'card_BBBBBBBBBBBBBBBBBBBBBB'];

  before(async () => {
    db = await scratchDb();
    // 1. The dev database as it was: migrations up to the OLD 003, with cards in it.
    const old = await db.open({ upTo: OLD_003 });
    await insertOldCard(old, oldCards[0], 'test_dev', 'a'.repeat(64));
    await insertOldCard(old, oldCards[1], 'anon_aadhaar', 'b'.repeat(64));
    await assert.rejects(insertOldCard(old, 'card_CCCCCCCCCCCCCCCCCCCCCC', 'emrtd_attested', 'c'.repeat(64)), /check|constraint/i, 'the old 003 refuses new methods');
    // 2. And from before the checksum guard: no checksums recorded.
    await old.run('UPDATE schema_migrations SET checksum = NULL');
    await old.close();
  });

  after(async () => {
    await srv?.close();
    await db.drop();
    await stopSnarkjsCurve();
  });

  it('the new server applies 004, keeps every old card and records checksums for all migrations', async () => {
    const iaca = await createTestIaca();
    const loaded = await PinnedVkeyVerifier.load();
    const scripted: ConnectorLike = {
      id: 'bankid_se',
      countries: ['SE'],
      assurance: 'high',
      label: 'BankID',
      callbackMethod: 'GET',
      async buildAuthUrl() {
        return { authUrl: 'https://app.bankid.com/' };
      },
      async handleCallback() {
        return { over18: true, subject: 'migration-test-person' };
      },
    };
    const registry: RegistryLike = { list: () => [scripted], get: (id) => (id === 'bankid_se' ? scripted : undefined) };
    srv = await startServer({
      aadhaarVerifier: loaded.verifier,
      trustedIacas: [iaca.iacaPem],
      connectorRegistry: registry,
      config: { faceModels: ['v18-test-face'], enableMyNumber: true, ...db.config },
    });
    (srv as any).iaca = iaca;
    for (const id of oldCards) {
      assert.equal((await api(srv.url, 'GET', `/v1/card/${id}/status`)).body.status, 'active', id);
    }
    const rows = await srv.services.db.all<{ name: string; checksum: string | null }>('SELECT name, checksum FROM schema_migrations ORDER BY name');
    assert.ok(rows.some((r) => r.name.startsWith('004_')), 'migration 004 applied');
    for (const r of rows) {
      const file = fs.readFileSync(path.join(MIGRATIONS_DIR, r.name), 'utf8');
      assert.equal(r.checksum, migrationChecksum(file), `${r.name} checksum`);
    }
  });

  it('every card method can now be stored, and the cards work for tickets', async () => {
    const methods: Record<string, number> = {};
    const record = (m: string, status: number) => (methods[m] = status);
    const attested = async (method: string, proof: Record<string, unknown>) => {
      const dev = await TestDevice.es256();
      const c = await newChallenge(srv.url);
      const r = await api(srv.url, 'POST', '/v1/card/issue', { method, challenge: c, devicePublicKey: dev.jwkWithAlg, deviceSignature: dev.sign(ss.cardIssue(c, dev.thumbprint)), proof });
      record(method, r.status);
      return { r, dev };
    };
    const n = () => crypto.randomBytes(32).toString('base64url');
    const nk = 'v18-nullifier-1';

    const td = await issueTestCard(srv.url, await TestDevice.es256());
    record('test_dev', td.status);

    // anon_aadhaar with the REAL fixture proof (bound to its own challenge and key).
    const fx = JSON.parse(fs.readFileSync(path.join(serverRoot, 'test-fixtures', 'anon-aadhaar', 'proofs.json'), 'utf8'));
    await srv.services.db.run('INSERT INTO challenges (challenge, expires_at) VALUES (?, ?)', [fx.challenge, srv.clock.now() + 300_000]);
    const fkey = crypto.createPrivateKey({ key: fx.devicePrivateJwk, format: 'jwk' });
    const aa = await api(srv.url, 'POST', '/v1/card/issue', {
      method: 'anon_aadhaar',
      challenge: fx.challenge,
      devicePublicKey: { ...fx.devicePublicJwk, alg: 'ES256' },
      deviceSignature: { alg: 'ES256', sig: crypto.sign('sha256', Buffer.from(ss.cardIssue(fx.challenge, fx.thumbprint)), fkey).toString('base64url') },
      proof: fx.proofs.over18_reveal_age_only,
    });
    record('anon_aadhaar', aa.status);

    const em = await attested('emrtd_attested', { over18: true, docExpiry: '2031-01-01', issuingState: 'FRA', docType: 'I', passiveAuth: 'ok', chipAuth: 'chip_auth', nullifier: n(), nullifierKeyId: nk });
    await attested('passport_attested', { over18: true, docExpiry: '2031-01-01', issuingState: 'IND', passiveAuth: 'ok', chipAuth: 'none', nullifier: n(), nullifierKeyId: nk });
    await attested('philsys_qr_attested', { over18: true, qrSignature: 'ok', nullifier: n(), nullifierKeyId: nk });
    await attested('mynumber_attested', { over18: true, jpkiChain: 'ok', certExpiry: '2030-06-30', nullifier: n(), nullifierKeyId: nk });
    await attested('face_estimate', { estimator: 'v18-test-face', challengeAge: 25, passed: true, liveness: 'passed' });

    // mdoc_app (dev mode: the TEST app names its origin).
    const holder = newHolderKey();
    const origin = 'android:apk-key-hash:' + Buffer.alloc(32, 7).toString('base64url');
    const ch = await newChallenge(srv.url);
    const req = await api(srv.url, 'POST', '/v1/wallet/app-request', { challenge: ch });
    const answer = await testWalletAnswer({ mdoc: await issueTestMdoc({ iaca: (srv as any).iaca, holder, ageOver18: true }), holder, request: req.body.digital.requests[0], origin });
    const wdev = await TestDevice.es256();
    const md = await api(srv.url, 'POST', '/v1/card/issue', {
      method: 'mdoc_app',
      challenge: ch,
      devicePublicKey: wdev.jwkWithAlg,
      deviceSignature: wdev.sign(ss.cardIssue(ch, wdev.thumbprint)),
      proof: { ...answer, origin },
    });
    record('mdoc_app', md.status);

    // connector:<id>
    const cdev = await TestDevice.es256();
    const cc = await newChallenge(srv.url);
    const start = await api(srv.url, 'POST', '/v1/connect/bankid_se/start', { challenge: cc, devicePublicKey: cdev.jwkWithAlg, deviceSignature: cdev.sign(ss.cardIssue(cc, cdev.thumbprint)) });
    const cb = await fetch(`${srv.url}/v1/connect/bankid_se/callback?state=${start.body.state}`, { redirect: 'manual' });
    const link = new URL((cb.headers.get('location') ?? '').replace('v18://', 'v18://x/'));
    record('connector:bankid_se', link.searchParams.get('status') === 'ok' ? 201 : 500);

    assert.deepEqual(methods, {
      test_dev: 201,
      anon_aadhaar: 201,
      emrtd_attested: 201,
      passport_attested: 201,
      philsys_qr_attested: 201,
      mynumber_attested: 201,
      face_estimate: 201,
      mdoc_app: 201,
      'connector:bankid_se': 201,
    });
    const stored = (await srv.services.db.all<{ method: string }>('SELECT DISTINCT method FROM cards')).map((r) => r.method).sort();
    assert.deepEqual(stored, [
      'anon_aadhaar',
      'connector:bankid_se',
      'emrtd_attested',
      'face_estimate',
      'mdoc_app',
      'mynumber_attested',
      'philsys_qr_attested',
      'test_dev',
    ]);
    assert.ok(await makeTicket(srv, em.r.body.cardId, em.dev, { origin: 'https://site.test', challenge: 'm'.repeat(20) }));
  });

  it('the store still refuses a method name the server does not know', async () => {
    const dev = await TestDevice.es256();
    await assert.rejects(
      srv.services.cards.createCard({
        method: 'made_up' as never,
        deviceKey: { alg: 'ES256', jwk: dev.publicJwk as never, thumbprint: dev.thumbprint },
        nullifierHash: 'd'.repeat(64),
        assuranceLevel: 'test',
        minAgeCertified: 18,
        validUntilMs: srv.clock.now() + 1000,
      }),
      /unknown method/
    );
  });
});

describe('Migration checksum guard', () => {
  it('refuses to start when an applied migration file was edited; line endings alone do not count', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-migdir-'));
    for (const f of fs.readdirSync(MIGRATIONS_DIR)) fs.copyFileSync(path.join(MIGRATIONS_DIR, f), path.join(dir, f));
    const db = await scratchDb();
    await (await db.open({ migrationsDir: dir })).close();

    const target = path.join(dir, TEST_DB === 'postgres' ? '002_cards.sql' : '002_cards_sqlite.sql');
    const original = fs.readFileSync(target, 'utf8');
    // Same text with Windows line endings (what a git checkout may give): still fine.
    fs.writeFileSync(target, original.replace(/\r?\n/g, '\r\n'));
    await (await db.open({ migrationsDir: dir })).close();
    // A real edit: refused, with a message that says what to do.
    fs.writeFileSync(target, original + '\n-- an edit after the fact\n');
    await assert.rejects(db.open({ migrationsDir: dir }), /was changed after it was applied[\s\S]*new numbered migration/);
    await db.drop();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('the server itself refuses to start on a database that applied a different version of a repository migration', async () => {
    const db = await scratchDb();
    const conn = await db.open();
    const name = TEST_DB === 'postgres' ? '003_phase2.sql' : '003_phase2_sqlite.sql';
    await conn.run('UPDATE schema_migrations SET checksum = ? WHERE name = ?', ['0'.repeat(64), name]);
    await conn.close();
    await assert.rejects(startServer({ config: db.config }), new RegExp(`${name.replace('.', '\\.')} was changed after it was applied`));
    await db.drop();
  });

  it('the repository migrations all match: 003 is back to the text databases applied', () => {
    const s3 = fs.readFileSync(path.join(MIGRATIONS_DIR, '003_phase2_sqlite.sql'), 'utf8');
    assert.match(s3, /CHECK \(method IN \('test_dev', 'anon_aadhaar', 'passport_zk', 'passport_attested', 'face_estimate'\)\)/);
    assert.ok(fs.existsSync(path.join(MIGRATIONS_DIR, '004_cards_any_method_sqlite.sql')));
    assert.ok(fs.existsSync(path.join(MIGRATIONS_DIR, '004_cards_any_method.sql')));
  });
});
