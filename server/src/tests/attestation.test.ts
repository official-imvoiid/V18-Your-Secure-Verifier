/**
 * Android key attestation (PROTOCOL.md 4c.3).
 *
 * Part 1 uses REAL attestation chains from real phones (Pixel and Sony),
 * published by Google in github.com/android/keyattestation (testdata,
 * Apache-2.0, copied to server/test-fixtures/android-attestation/). They are
 * checked against the real bundled Google roots. Those phones have unlocked
 * bootloaders (test devices), so production correctly refuses them.
 *
 * Part 2 uses chains generated here and signed by a TEST root, which the
 * test adds to the trusted roots, to cover the cases a real chain cannot
 * (a locked, verified phone running com.v18.app).
 */
import 'reflect-metadata';
import { describe, it, before } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as x509 from '@peculiar/x509';
import {
  AttestationPolicy,
  GoogleRevocationList,
  loadGoogleRoots,
  normalizeDigest,
  serialKey,
  StaticRevocationList,
  verifyKeyAttestation,
} from '../attestation/android.js';
import { TEST_SIGNING_CERT_DIGEST, TestAttestationRoot } from '../attestation/test-chain.js';
import { serverRoot } from '../config.js';

const FIXTURES = path.join(serverRoot, 'test-fixtures', 'android-attestation');

interface RealChain {
  name: string;
  chain: string[];
  leafKey: crypto.KeyObject;
  challenge: Buffer;
  packageName: string;
  digest: string;
  nowMs: number;
  meta: any;
}

function loadReal(name: string): RealChain {
  const ders = x509.PemConverter.decode(fs.readFileSync(path.join(FIXTURES, `${name}.pem`), 'utf8'));
  const text = fs.readFileSync(path.join(FIXTURES, `${name}.json`), 'utf8');
  const meta = JSON.parse(text.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n'));
  const leaf = new x509.X509Certificate(ders[0]);
  return {
    name,
    chain: ders.map((d) => Buffer.from(d).toString('base64')),
    leafKey: crypto.createPublicKey({ key: Buffer.from(leaf.publicKey.rawData), format: 'der', type: 'spki' }),
    // Most are UTF-8 text; the Sony one is 32 random bytes.
    challenge: Buffer.from(meta.attestationChallenge, 'base64'),
    packageName: meta.softwareEnforced.attestationApplicationId.packages[0].name,
    digest: Buffer.from(meta.softwareEnforced.attestationApplicationId.signatures[0], 'base64').toString('hex'),
    // RKP intermediates live for weeks, so check at the time the key was made.
    nowMs: Number(meta.softwareEnforced.creationDateTime) + 60_000,
    meta,
  };
}

const REAL_GOOGLE_ROOTED = [
  'akita_sdk34_TEE_EC_NONE',
  'akita_sdk34_SB_RSA_NONE',
  'blueline_sdk28_TEE_RSA_NONE',
  'caiman_sdk36_TEE_EC_RKP',
  'caiman_sdk36_SB_EC_RKP',
  'frankel_sdk37_TEE_EC_2026',
  'tegu_sdk36_TEE_EC_2026_ROOT',
  'tegu_sdk36_SB_EC_2026_ROOT',
  'walleye_sdk27_TEE_EC_NONE',
  'sony-xperia10-iii_sdk33_TEE_EC',
];

function policyFor(c: RealChain, over: Partial<AttestationPolicy> = {}): AttestationPolicy {
  return {
    devMode: false,
    packageName: c.packageName,
    certDigests: [c.digest],
    trustedRoots: loadGoogleRoots(),
    revocation: new StaticRevocationList(),
    ...over,
  };
}

async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err: any) {
    return err.extra?.reason ?? err.code ?? String(err);
  }
  return 'passed';
}

describe('Android attestation: real chains from real phones', () => {
  it('the bundled Google roots are the two currently published roots (RSA-4096 and EC P-384 "Key Attestation CA1")', () => {
    const roots = loadGoogleRoots();
    assert.equal(roots.length, 2);
    const kinds = roots.map((r) => r.publicKey.algorithm.name).sort();
    assert.deepEqual(kinds, ['ECDSA', 'RSASSA-PKCS1-v1_5']);
    assert.ok(roots.some((r) => r.subject.includes('Key Attestation CA1')));
  });

  for (const name of REAL_GOOGLE_ROOTED) {
    it(`${name}: chain verifies to a Google root and parses; production refuses it if the bootloader is unlocked`, async () => {
      const c = loadReal(name);
      const input = { chain: c.chain, allowedChallenges: [c.challenge], devicePublicKey: c.leafKey, nowMs: c.nowMs };
      // Dev mode: everything about the chain is real and valid; only the boot state is let through.
      const r = await verifyKeyAttestation(input, policyFor(c, { devMode: true }));
      assert.equal(r.chainTrusted, true);
      assert.equal(r.packageName, c.packageName);
      const expectedLevel = c.meta.keyMintSecurityLevel === 'STRONG_BOX' ? 'StrongBox' : 'TrustedEnvironment';
      assert.equal(r.securityLevel, expectedLevel);
      assert.equal(r.attestationVersion, Number(c.meta.attestationVersion));
      const rot = c.meta.hardwareEnforced.rootOfTrust;
      assert.equal(r.deviceLocked, rot.deviceLocked);
      assert.equal(r.verifiedBootState?.toUpperCase(), rot.verifiedBootState.replace('_', ''));
      if (rot.verifiedBootState === 'VERIFIED' && rot.deviceLocked) {
        assert.deepEqual(r.devModeExceptions, []);
        assert.equal(r.hardwareVerified, true);
      } else {
        assert.deepEqual(r.devModeExceptions, ['boot_not_verified']);
        // Production: verified boot with a locked bootloader is required.
        assert.equal(await reason(verifyKeyAttestation(input, policyFor(c))), 'boot_not_verified');
      }
    });
  }

  it('wrong challenge, wrong package, wrong signing certificate and wrong key are refused', async () => {
    const c = loadReal('caiman_sdk36_TEE_EC_RKP');
    const base = { chain: c.chain, allowedChallenges: [c.challenge], devicePublicKey: c.leafKey, nowMs: c.nowMs };
    const dev = policyFor(c, { devMode: true });
    assert.equal(await reason(verifyKeyAttestation({ ...base, allowedChallenges: ['another challenge'] }, dev)), 'challenge_mismatch');
    assert.equal(await reason(verifyKeyAttestation(base, { ...dev, packageName: 'com.v18.app' })), 'wrong_package');
    assert.equal(await reason(verifyKeyAttestation(base, { ...dev, certDigests: ['00'.repeat(32)] })), 'wrong_signing_certificate');
    const other = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey;
    assert.equal(await reason(verifyKeyAttestation({ ...base, devicePublicKey: other }, dev)), 'key_mismatch');
  });

  it('a certificate on the revocation list is refused (leaf, intermediate or root)', async () => {
    const c = loadReal('tegu_sdk36_TEE_EC_2026_ROOT');
    const base = { chain: c.chain, allowedChallenges: [c.challenge], devicePublicKey: c.leafKey, nowMs: c.nowMs };
    for (const i of [0, 1, c.chain.length - 1]) {
      const serial = serialKey(new x509.X509Certificate(Buffer.from(c.chain[i], 'base64')));
      const p = policyFor(c, { devMode: true, revocation: new StaticRevocationList([serial.toUpperCase()]) });
      assert.equal(await reason(verifyKeyAttestation(base, p)), 'revoked', `cert ${i}`);
    }
  });

  it('an expired intermediate is refused, but the expired 2016 Google root certificate still anchors older phones', async () => {
    const c = loadReal('caiman_sdk36_TEE_EC_RKP');
    const later = c.nowMs + 400 * 86_400_000;
    const r = await reason(
      verifyKeyAttestation({ chain: c.chain, allowedChallenges: [c.challenge], devicePublicKey: c.leafKey, nowMs: later }, policyFor(c, { devMode: true }))
    );
    assert.equal(r, 'certificate_expired');
    // blueline's chain ends in the 2016 root certificate (expired 2026-05-24); checked today it still passes.
    const b = loadReal('blueline_sdk28_TEE_RSA_NONE');
    const rootCert = new x509.X509Certificate(Buffer.from(b.chain[b.chain.length - 1], 'base64'));
    assert.ok(rootCert.notAfter.getTime() < Date.UTC(2026, 10, 19));
    const ok = await verifyKeyAttestation(
      { chain: b.chain, allowedChallenges: [b.challenge], devicePublicKey: b.leafKey, nowMs: Date.UTC(2026, 10, 19) },
      policyFor(b, { devMode: true })
    );
    assert.equal(ok.chainTrusted, true);
  });

  it('a chain with a re-encoded (tampered) leaf fails the signature check', async () => {
    const ders = x509.PemConverter.decode(fs.readFileSync(path.join(FIXTURES, 'invalid_tags_not_in_ascending_order.pem'), 'utf8'));
    const leaf = new x509.X509Certificate(ders[0]);
    const key = crypto.createPublicKey({ key: Buffer.from(leaf.publicKey.rawData), format: 'der', type: 'spki' });
    const r = await reason(
      verifyKeyAttestation(
        { chain: ders.map((d) => Buffer.from(d).toString('base64')), allowedChallenges: ['challenge'], devicePublicKey: key, nowMs: Date.UTC(2025, 0, 1) },
        { devMode: true, packageName: 'x', certDigests: [], trustedRoots: loadGoogleRoots(), revocation: new StaticRevocationList() }
      )
    );
    assert.equal(r, 'bad_chain_signature');
  });

  it('a Pixel 1 (marlin) chain with software attestation and no Google hardware root: production refuses, dev mode says why', async () => {
    const c = loadReal('marlin_sdk29_TEE_EC_NONE');
    const input = { chain: c.chain, allowedChallenges: [c.challenge], devicePublicKey: c.leafKey, nowMs: c.nowMs };
    assert.equal(await reason(verifyKeyAttestation(input, policyFor(c))), 'untrusted_root');
    const r = await verifyKeyAttestation(input, policyFor(c, { devMode: true }));
    assert.equal(r.chainTrusted, false);
    assert.equal(r.securityLevel, 'Software');
    assert.ok(r.devModeExceptions.includes('untrusted_root'));
    assert.ok(r.devModeExceptions.includes('software_security_level'));
  });

  it('malformed input is refused', async () => {
    const p: AttestationPolicy = { devMode: true, packageName: 'x', certDigests: [], trustedRoots: [], revocation: new StaticRevocationList() };
    const key = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey;
    for (const chain of [undefined, [], ['abc'], 'x', [1, 2], ['!!!', '???']]) {
      assert.equal(await reason(verifyKeyAttestation({ chain, allowedChallenges: ['c'], devicePublicKey: key, nowMs: Date.now() }, p)), 'malformed');
    }
  });
});

describe('Android attestation: generated TEST chains (locked, verified phone)', () => {
  let root: TestAttestationRoot;
  let policy: AttestationPolicy;
  const challenge = 'a'.repeat(64);
  const device = () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey;

  before(async () => {
    root = await TestAttestationRoot.create();
    policy = {
      devMode: false,
      packageName: 'com.v18.app',
      certDigests: [TEST_SIGNING_CERT_DIGEST.toString('hex')],
      trustedRoots: [...loadGoogleRoots(), root.rootCert],
      revocation: new StaticRevocationList(),
    };
  });

  it('a TEE key on a locked, verified phone passes every production check', async () => {
    const key = device();
    const r = await verifyKeyAttestation(
      { chain: await root.chainFor(key, { challenge }), allowedChallenges: [challenge], devicePublicKey: key, nowMs: Date.now() },
      policy
    );
    assert.equal(r.hardwareVerified, true);
    assert.equal(r.securityLevel, 'TrustedEnvironment');
    assert.equal(r.verifiedBootState, 'Verified');
    assert.equal(r.deviceLocked, true);
    assert.deepEqual(r.devModeExceptions, []);
  });

  it('StrongBox and RSA device keys pass too', async () => {
    const key = device();
    const r = await verifyKeyAttestation(
      { chain: await root.chainFor(key, { challenge, securityLevel: 2 }), allowedChallenges: [challenge], devicePublicKey: key, nowMs: Date.now() },
      policy
    );
    assert.equal(r.securityLevel, 'StrongBox');
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey;
    const r2 = await verifyKeyAttestation(
      { chain: await root.chainFor(rsa, { challenge }), allowedChallenges: [challenge], devicePublicKey: rsa, nowMs: Date.now() },
      policy
    );
    assert.equal(r2.hardwareVerified, true);
  });

  it('production refuses software keys, imported keys, unlocked or unverified phones, and a missing extension', async () => {
    const cases: [Parameters<TestAttestationRoot['chainFor']>[1], string][] = [
      [{ challenge, securityLevel: 0 }, 'software_security_level'],
      [{ challenge, origin: 2 }, 'key_not_generated'],
      [{ challenge, deviceLocked: false }, 'boot_not_verified'],
      [{ challenge, verifiedBootState: 2 }, 'boot_not_verified'],
      [{ challenge, verifiedBootState: 1 }, 'boot_not_verified'],
      [{ challenge, omitExtension: true }, 'no_key_description'],
      [{ challenge, packageName: 'com.evil.app' }, 'wrong_package'],
      [{ challenge, signingCertDigest: crypto.randomBytes(32) }, 'wrong_signing_certificate'],
      [{ challenge, intermediateNotAfter: new Date(Date.now() - 1000) }, 'certificate_expired'],
    ];
    for (const [opts, want] of cases) {
      const key = device();
      const got = await reason(
        verifyKeyAttestation({ chain: await root.chainFor(key, opts), allowedChallenges: [challenge], devicePublicKey: key, nowMs: Date.now() }, policy)
      );
      assert.equal(got, want, JSON.stringify(opts));
    }
  });

  it('a TEST-root chain is refused when only the Google roots are trusted (as in production)', async () => {
    const key = device();
    const got = await reason(
      verifyKeyAttestation(
        { chain: await root.chainFor(key, { challenge }), allowedChallenges: [challenge], devicePublicKey: key, nowMs: Date.now() },
        { ...policy, trustedRoots: loadGoogleRoots() }
      )
    );
    assert.equal(got, 'untrusted_root');
  });

  it('V18_ANDROID_CERT_DIGESTS accepts hex with colons and base64', () => {
    const hex = TEST_SIGNING_CERT_DIGEST.toString('hex');
    assert.equal(normalizeDigest(hex.toUpperCase().match(/../g)!.join(':')), hex);
    assert.equal(normalizeDigest(TEST_SIGNING_CERT_DIGEST.toString('base64')), hex);
    assert.throws(() => normalizeDigest('abc'));
  });
});

describe('Android attestation: revocation list fetch and cache', () => {
  it('fetches, caches on disk, and fails closed in production when the copy is too old', async () => {
    const dir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'v18-rl-'));
    const cacheFile = path.join(dir, 'status.json');
    let now = Date.UTC(2027, 0, 1);
    let calls = 0;
    let up = true;
    const fetchFn = (async () => {
      calls++;
      if (!up) throw new Error('network down');
      return new Response(JSON.stringify({ entries: { 'ABC123': { status: 'REVOKED', reason: 'KEY_COMPROMISE' }, '0f': { status: 'SUSPENDED' } } }));
    }) as unknown as typeof fetch;
    const list = new GoogleRevocationList({ cacheFile, devMode: false, fetchFn, clock: () => now });
    // The bundled snapshot is older than a day at this clock, so the first use fetches.
    const set = await list.revokedSerials();
    assert.equal(calls, 1);
    assert.ok(set.has('abc123') && set.has('f'));
    assert.ok(fs.existsSync(cacheFile));
    // A restart reads the cache without the network.
    up = false;
    const again = new GoogleRevocationList({ cacheFile, devMode: false, fetchFn, clock: () => now });
    assert.ok((await again.revokedSerials()).has('abc123'));
    // Four days later Google still cannot be reached: production refuses.
    now += 4 * 86_400_000;
    await assert.rejects(again.revokedSerials(), (e: any) => e.code === 'ATTESTATION_UNAVAILABLE');
    list.close();
    again.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
