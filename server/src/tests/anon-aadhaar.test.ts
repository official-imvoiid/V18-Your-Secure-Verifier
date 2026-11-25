/**
 * Anon Aadhaar card issuing with REAL proofs (no mock).
 *
 * test-fixtures/anon-aadhaar/proofs.json holds real Groth16 proofs made by
 * `npm run make-aadhaar-fixtures` with the official v2 circuit files and the
 * Node prover, from UIDAI's public SAMPLE QR re-signed with the Anon Aadhaar
 * TEST key (test data only). The server checks them with snarkjs and the
 * PINNED vkey.json from server/assets/artifacts.
 */
import 'reflect-metadata';
import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { serverRoot } from '../config.js';
import {
  anonAadhaarLib,
  anonAadhaarSignal,
  loadUidaiKeys,
  PinnedVkeyVerifier,
  stopSnarkjsCurve,
} from '../issuers/anon-aadhaar.js';
import { api, ss, startServer, TestServer } from './helpers.js';

const FIX = path.join(serverRoot, 'test-fixtures', 'anon-aadhaar', 'proofs.json');
const fixture = JSON.parse(fs.readFileSync(FIX, 'utf8')) as {
  challenge: string;
  nullifierSeed: string;
  thumbprint: string;
  devicePublicJwk: Record<string, string>;
  devicePrivateJwk: crypto.JsonWebKey;
  proofs: Record<'over18_reveal_age_only' | 'over18_reveals_gender_too' | 'under18_reveal_age_only', any>;
};
const deviceKey = crypto.createPrivateKey({ key: fixture.devicePrivateJwk, format: 'jwk' });
const sign = (text: string) => ({ alg: 'ES256', sig: crypto.sign('sha256', Buffer.from(text), { key: deviceKey, dsaEncoding: 'der' }).toString('base64url') });
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

let verifier: PinnedVkeyVerifier;

/** Puts a challenge into the server's store, as if POST /v1/challenge had made it. */
async function plantChallenge(srv: TestServer, challenge: string): Promise<void> {
  await srv.services.db.run('INSERT INTO challenges (challenge, expires_at) VALUES (?, ?)', [challenge, srv.clock.now() + 300_000]);
}

async function issue(srv: TestServer, proof: unknown, opts: { challenge?: string; device?: { jwk: Record<string, string>; sign: typeof sign; thumbprint: string } } = {}) {
  const challenge = opts.challenge ?? fixture.challenge;
  await plantChallenge(srv, challenge);
  const dev = opts.device ?? { jwk: fixture.devicePublicJwk, sign, thumbprint: fixture.thumbprint };
  return api(srv.url, 'POST', '/v1/card/issue', {
    method: 'anon_aadhaar',
    challenge,
    devicePublicKey: { ...dev.jwk, alg: 'ES256' },
    deviceSignature: dev.sign(ss.cardIssue(challenge, dev.thumbprint)),
    proof,
  });
}

before(async () => {
  const loaded = await PinnedVkeyVerifier.load();
  assert.ok(loaded.verifier, `pinned vkey.json must be present: ${loaded.reason}`);
  verifier = loaded.verifier!;
});

after(async () => {
  await stopSnarkjsCurve();
});

describe('Anon Aadhaar keys and the pinned verification key', () => {
  it('the bundled UIDAI certificate hashes to @anon-aadhaar/core productionPublicKeyHash; the TEST cert to testPublicKeyHash', async () => {
    const keys = await loadUidaiKeys();
    const prod = keys.filter((k) => !k.test).map((k) => k.pubkeyHash);
    const test = keys.filter((k) => k.test).map((k) => k.pubkeyHash);
    assert.deepEqual(prod, [anonAadhaarLib().productionPublicKeyHash]);
    assert.deepEqual(test, [anonAadhaarLib().testPublicKeyHash]);
  });

  it('refuses a vkey.json that does not match its pinned SHA-256', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-vkey-'));
    const vk = JSON.parse(fs.readFileSync(path.join(serverRoot, 'assets', 'artifacts', 'vkey.json'), 'utf8'));
    vk.vk_alpha_1[0] = '1';
    fs.writeFileSync(path.join(dir, 'vkey.json'), JSON.stringify(vk));
    await assert.rejects(PinnedVkeyVerifier.load(dir), /does not match its pinned SHA-256/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('signal rule (4b item 1): "0x" + hex(SHA-256(challenge|thumbprint)), and the fixture is bound that way', () => {
    const { signal, signalHash } = anonAadhaarSignal(fixture.challenge, fixture.thumbprint);
    assert.match(signal, /^0x[0-9a-f]{64}$/);
    assert.equal(signalHash, anonAadhaarLib().hash(signal));
    assert.equal(BigInt(fixture.proofs.over18_reveal_age_only.proof.signalHash), BigInt(signalHash));
  });
});

describe('Anon Aadhaar card issue with real proofs (dev mode)', () => {
  let srv: TestServer;
  before(async () => {
    srv = await startServer({ aadhaarVerifier: verifier });
  });
  after(async () => srv.close());

  it('a real TEST-key proof gives a card with assuranceLevel "test" (never "substantial")', async () => {
    const r = await issue(srv, fixture.proofs.over18_reveal_age_only);
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.equal(r.body.method, 'anon_aadhaar');
    assert.equal(r.body.assuranceLevel, 'test');
    assert.equal(r.body.minAgeCertified, 18);
    assert.equal(Date.parse(r.body.validUntil) - srv.clock.now(), 180 * 86_400_000);
  });

  it('health says anon_aadhaar is ready', async () => {
    assert.equal((await api(srv.url, 'GET', '/v1/health')).body.methods.anon_aadhaar, 'ready');
  });

  it('a tampered Groth16 proof fails the real pairing check (bad_proof)', async () => {
    const p = clone(fixture.proofs.over18_reveal_age_only);
    p.proof.groth16Proof.pi_a[0] = (BigInt(p.proof.groth16Proof.pi_a[0]) + 1n).toString();
    const r = await issue(srv, p);
    assert.equal(r.status, 400);
    assert.equal(r.body.reason, 'bad_proof');
  });

  it('a changed public signal (nullifier or timestamp) fails the proof', async () => {
    for (const field of ['nullifier', 'timestamp']) {
      const p = clone(fixture.proofs.over18_reveal_age_only);
      p.proof[field] = (BigInt(p.proof[field]) + 1n).toString();
      const r = await issue(srv, p);
      assert.equal(r.body.reason, 'bad_proof', field);
    }
  });

  it('the proof is tied to its challenge and device key (signal_mismatch otherwise)', async () => {
    const other = crypto.randomBytes(32).toString('hex');
    const r1 = await issue(srv, fixture.proofs.over18_reveal_age_only, { challenge: other });
    assert.equal(r1.body.reason, 'signal_mismatch');
    const k = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = k.publicKey.export({ format: 'jwk' }) as Record<string, string>;
    const pub = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
    const { calculateJwkThumbprint } = await import('jose');
    const thumb = await calculateJwkThumbprint(pub as never, 'sha256');
    const otherSign = (text: string) => ({ alg: 'ES256', sig: crypto.sign('sha256', Buffer.from(text), k.privateKey).toString('base64url') });
    const r2 = await issue(srv, fixture.proofs.over18_reveal_age_only, { device: { jwk: pub, sign: otherSign, thumbprint: thumb } });
    assert.equal(r2.body.reason, 'signal_mismatch');
  });

  it('a real proof that also reveals gender is refused (reveals_too_much)', async () => {
    const r = await issue(srv, fixture.proofs.over18_reveals_gender_too);
    assert.equal(r.status, 400);
    assert.equal(r.body.reason, 'reveals_too_much');
  });

  it('a real proof of an under-18 TEST person gives 403 UNDER_AGE', async () => {
    const r = await issue(srv, fixture.proofs.under18_reveal_age_only);
    assert.equal(r.status, 403);
    assert.equal(r.body.code, 'UNDER_AGE');
  });

  it('accepts the serialized PCD form {type, pcd: "<json>"}', async () => {
    const s2 = await startServer({ aadhaarVerifier: verifier });
    const r = await issue(s2, { type: 'anon-aadhaar', pcd: JSON.stringify(fixture.proofs.over18_reveal_age_only) });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    await s2.close();
  });

  it('an unknown UIDAI key and a malformed proof are refused', async () => {
    const p = clone(fixture.proofs.over18_reveal_age_only);
    p.proof.pubkeyHash = '123';
    assert.equal((await issue(srv, p)).body.reason, 'unknown_issuer_key');
    assert.equal((await issue(srv, { proof: { nullifier: 'x' } })).body.reason, 'malformed');
  });
});

describe('Anon Aadhaar: production rules and configuration', () => {
  it('production refuses a TEST-key proof (test_key_rejected)', async () => {
    const srv = await startServer({ aadhaarVerifier: verifier, config: { devMode: false, aadhaarNullifierSeed: fixture.nullifierSeed } });
    const r = await issue(srv, fixture.proofs.over18_reveal_age_only);
    assert.equal(r.status, 400);
    assert.equal(r.body.reason, 'test_key_rejected');
    await srv.close();
  });

  it('a proof made for another nullifier seed is refused', async () => {
    const srv = await startServer({ aadhaarVerifier: verifier, config: { aadhaarNullifierSeed: '424242' } });
    const r = await issue(srv, fixture.proofs.over18_reveal_age_only);
    assert.equal(r.body.reason, 'wrong_nullifier_seed');
    await srv.close();
  });

  it('without the verification key the method is "not_configured" and answers 503', async () => {
    const srv = await startServer({ aadhaarVerifier: null });
    assert.equal((await api(srv.url, 'GET', '/v1/health')).body.methods.anon_aadhaar, 'not_configured');
    const r = await issue(srv, fixture.proofs.over18_reveal_age_only);
    assert.equal(r.status, 503);
    assert.equal(r.body.code, 'METHOD_NOT_CONFIGURED');
    await srv.close();
  });
});
