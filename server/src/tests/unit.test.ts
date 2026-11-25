import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { ChallengeService } from '../challenge/service.js';
import { openSqlite } from '../db/sql.js';
import { ChallengeRepo, RateLimitRepo } from '../db/state.js';
import {
  parseDevicePublicKey,
  signingStrings,
  verifyDeviceSignature,
} from '../device/device-keys.js';
import { ApiError } from '../errors.js';
import { verifyTestDevProof } from '../issuers/test-dev.js';
import { MemoryKeyStore } from '../keys/keystore.js';
import { keyIdFor, TicketKeyService } from '../keys/ticket-keys.js';
import { NullifierStore } from '../nullifier/store.js';
import { RateLimiter } from '../tickets/rate-limit.js';
import { DAY, FakeClock, MINUTE, TestDevice } from './helpers.js';

const isApiError = (code: string) => (err: unknown) => err instanceof ApiError && err.code === code;

const memRepo = () => new ChallengeRepo(openSqlite(':memory:'));

describe('Challenge service', () => {
  it('makes 64-hex-character challenges that expire in 5 minutes', async () => {
    const clock = new FakeClock();
    const svc = new ChallengeService(memRepo(), 300, clock.now);
    const c = await svc.createChallenge();
    assert.match(c.challenge, /^[0-9a-f]{64}$/);
    assert.equal(Date.parse(c.expiresAt) - clock.now(), 300_000);
    svc.close();
  });

  it('accepts a challenge once only', async () => {
    const svc = new ChallengeService(memRepo());
    const { challenge } = await svc.createChallenge();
    assert.equal(await svc.isOpen(challenge), true);
    assert.equal(await svc.verifyAndConsume(challenge), true);
    assert.equal(await svc.verifyAndConsume(challenge), false);
    assert.equal(await svc.isOpen(challenge), false);
    svc.close();
  });

  it('rejects an expired challenge', async () => {
    const clock = new FakeClock();
    const svc = new ChallengeService(memRepo(), 300, clock.now);
    const { challenge } = await svc.createChallenge();
    clock.advance(5 * MINUTE + 1);
    assert.equal(await svc.verifyAndConsume(challenge), false);
    svc.close();
  });

  it('rejects unknown and malformed challenges', async () => {
    const svc = new ChallengeService(memRepo());
    assert.equal(await svc.verifyAndConsume('a'.repeat(64)), false);
    assert.equal(await svc.verifyAndConsume(''), false);
    assert.equal(await svc.verifyAndConsume(42), false);
    await assert.rejects(svc.consumeOrThrow('nope'), isApiError('CHALLENGE_INVALID'));
    svc.close();
  });
});

describe('Nullifier store', () => {
  it('records a hash once and reports it', async () => {
    const store = new NullifierStore(openSqlite(':memory:'));
    const h = NullifierStore.hashFor('test_dev', 'alice');
    assert.equal(await store.has(h), false);
    assert.equal(await store.record(h, 'test_dev'), true);
    assert.equal(await store.record(h, 'test_dev'), false);
    assert.equal(await store.has(h), true);
    assert.equal(await store.count(), 1);
  });

  it('keeps methods apart and stores only a SHA-256 hash', () => {
    const a = NullifierStore.hashFor('test_dev', '123');
    const b = NullifierStore.hashFor('anon_aadhaar', '123');
    assert.notEqual(a, b);
    assert.match(a, /^[0-9a-f]{64}$/);
    assert.ok(!a.includes('123'));
  });
});

describe('Device keys and signatures (protocol 3.4)', () => {
  it('computes the RFC 7638 thumbprint (the RFC example key)', async () => {
    const key = await parseDevicePublicKey({
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
      alg: 'RS256',
    });
    assert.equal(key.thumbprint, 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
    assert.equal(key.alg, 'RS256');
  });

  it('accepts ES256 signatures as DER and as raw r||s', async () => {
    const dev = await TestDevice.es256();
    const key = await parseDevicePublicKey(dev.jwkWithAlg);
    assert.equal(key.thumbprint, dev.thumbprint);
    const s = signingStrings.cardIssue('ab'.repeat(32), dev.thumbprint);
    const der = dev.sign(s);
    const raw = dev.sign(s, { raw: true });
    assert.equal(Buffer.from(raw.sig, 'base64url').length, 64);
    assert.equal(verifyDeviceSignature(key, der, s), true);
    assert.equal(verifyDeviceSignature(key, raw, s), true);
  });

  it('accepts RS256 (PKCS#1 v1.5) signatures', async () => {
    const dev = await TestDevice.rs256();
    const key = await parseDevicePublicKey(dev.jwkWithAlg);
    const s = signingStrings.cardDelete('card_x', 'cd'.repeat(32));
    assert.equal(verifyDeviceSignature(key, dev.sign(s), s), true);
  });

  it('rejects a signature over a different string, a tampered one, or the wrong alg', async () => {
    const dev = await TestDevice.es256();
    const key = await parseDevicePublicKey(dev.jwkWithAlg);
    const s = 'v18-card-issue\nAAA\nBBB';
    const sig = dev.sign(s);
    assert.equal(verifyDeviceSignature(key, sig, s + '\n'), false);
    const bad = Buffer.from(sig.sig, 'base64url');
    bad[bad.length - 1] ^= 1;
    assert.equal(verifyDeviceSignature(key, { alg: 'ES256', sig: bad.toString('base64url') }, s), false);
    assert.equal(verifyDeviceSignature(key, { alg: 'RS256', sig: sig.sig }, s), false);
    assert.equal(verifyDeviceSignature(key, null, s), false);
  });

  it('builds the exact signing strings (joined with \\n, no trailing newline)', () => {
    assert.equal(signingStrings.cardIssue('C', 'T'), 'v18-card-issue\nC\nT');
    assert.equal(signingStrings.ticketRequest('K', 'C', 'v18-age18-20261109', 'B'), 'v18-ticket-request\nK\nC\nv18-age18-20261109\nB');
    assert.equal(signingStrings.linkApprove('K', 'C', 'L'), 'v18-link-approve\nK\nC\nL');
    assert.equal(signingStrings.cardDelete('K', 'C'), 'v18-card-delete\nK\nC');
  });

  it('refuses private keys, other curves, off-curve points and weak RSA', async () => {
    const dev = await TestDevice.es256();
    await assert.rejects(parseDevicePublicKey({ ...dev.publicJwk, d: 'AAAA' }), isApiError('BAD_DEVICE_KEY'));
    await assert.rejects(parseDevicePublicKey({ ...dev.publicJwk, crv: 'P-384' }), isApiError('BAD_DEVICE_KEY'));
    await assert.rejects(parseDevicePublicKey({ ...dev.publicJwk, alg: 'RS256' }), isApiError('BAD_DEVICE_KEY'));
    await assert.rejects(
      parseDevicePublicKey({
        kty: 'EC',
        crv: 'P-256',
        x: Buffer.alloc(32, 1).toString('base64url'),
        y: Buffer.alloc(32, 2).toString('base64url'),
      }),
      isApiError('BAD_DEVICE_KEY')
    );
    const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
    const weak = publicKey.export({ format: 'jwk' });
    await assert.rejects(parseDevicePublicKey({ kty: 'RSA', n: weak.n, e: weak.e }), isApiError('BAD_DEVICE_KEY'));
    await assert.rejects(parseDevicePublicKey({ kty: 'oct', k: 'AAAA' }), isApiError('BAD_DEVICE_KEY'));
  });
});

describe('test_dev issuer (TEST ONLY)', () => {
  const now = Date.UTC(2026, 10, 9, 12);

  it('certifies 18+ for 30 days', () => {
    const r = verifyTestDevProof({ testSubjectId: 'alice', birthDate: '1990-01-01' }, now);
    assert.equal(r.minAgeCertified, 18);
    assert.equal(r.assuranceLevel, 'test');
    assert.equal(r.validUntilMs - now, 30 * DAY);
    assert.equal(r.rawNullifier, 'alice');
  });

  it('turns 18 exactly on the birthday', () => {
    assert.doesNotThrow(() => verifyTestDevProof({ testSubjectId: 'a', birthDate: '2008-11-09' }, now));
    assert.throws(() => verifyTestDevProof({ testSubjectId: 'a', birthDate: '2008-11-10' }, now), isApiError('UNDER_AGE'));
  });

  it('never outlives the ID, and refuses an expired ID', () => {
    const r = verifyTestDevProof({ testSubjectId: 'a', birthDate: '1990-01-01', idValidUntil: '2026-11-19' }, now);
    assert.equal(r.validUntilMs, Date.UTC(2026, 10, 20));
    assert.throws(
      () => verifyTestDevProof({ testSubjectId: 'a', birthDate: '1990-01-01', idValidUntil: '2026-11-08' }, now),
      isApiError('ID_EXPIRED')
    );
  });

  it('refuses bad input', () => {
    assert.throws(() => verifyTestDevProof({ birthDate: '1990-01-01' }, now), isApiError('BAD_REQUEST'));
    assert.throws(() => verifyTestDevProof({ testSubjectId: 'a', birthDate: '1990-02-30' }, now), isApiError('BAD_REQUEST'));
    assert.throws(() => verifyTestDevProof({ testSubjectId: 'a', birthDate: '01/01/1990' }, now), isApiError('BAD_REQUEST'));
    assert.throws(() => verifyTestDevProof('nope', now), isApiError('BAD_REQUEST'));
  });
});

describe('Rate limiter', () => {
  it('allows N per hour, then says how long to wait, then allows again (stored in the database)', async () => {
    const clock = new FakeClock();
    const repo = new RateLimitRepo(openSqlite(':memory:'));
    const rl = new RateLimiter(repo, 'test', 2, 3_600_000, clock.now);
    assert.equal((await rl.take('c')).ok, true);
    clock.advance(10 * MINUTE);
    assert.equal((await rl.take('c')).ok, true);
    const third = await rl.take('c');
    assert.equal(third.ok, false);
    if (!third.ok) assert.equal(third.retryAfterSeconds, 50 * 60);
    assert.equal((await rl.take('other')).ok, true);
    // Another limiter name never shares counts.
    assert.equal((await new RateLimiter(repo, 'other-limit', 2, 3_600_000, clock.now).take('c')).ok, true);
    clock.advance(50 * MINUTE + 1);
    assert.equal((await rl.take('c')).ok, true);
    rl.close();
  });
});

describe('RFC 9474 blind signature cycle with a ticket key', () => {
  it('blinds, signs, finalizes and verifies with plain RSA-PSS; tampering fails', async () => {
    const clock = new FakeClock();
    const keys = new TicketKeyService(new MemoryKeyStore(), { thresholds: [18], rotationDays: 7, modulusBits: 2048 }, clock.now);
    await keys.refresh();
    const key = keys.currentKey(18);
    assert.equal(key.kid, keyIdFor(18, key.nbf));

    const suite = RSABSSA.SHA384.PSS.Randomized();
    const pub = await crypto.subtle.importKey('jwk', key.publicJwk, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
    const prepared = suite.prepare(new TextEncoder().encode('{"v":1}'));
    const { blindedMsg, inv } = await suite.blind(pub, prepared);
    const blindSig = await keys.blindSign(key, blindedMsg);
    assert.equal(blindSig.length, 256);
    const sig = await suite.finalize(pub, prepared, blindSig, inv);

    const nodeKey = crypto.createPublicKey({ key: key.publicJwk, format: 'jwk' });
    const verify = (msg: Uint8Array) =>
      crypto.verify('sha384', msg, { key: nodeKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 }, sig);
    assert.equal(verify(prepared), true);
    const tampered = new Uint8Array(prepared);
    tampered[tampered.length - 1] ^= 0xff;
    assert.equal(verify(tampered), false);

    // Wrong size and out-of-range blinded messages are refused.
    await assert.rejects(keys.blindSign(key, new Uint8Array(255)), isApiError('BAD_BLINDED_MESSAGE'));
    await assert.rejects(keys.blindSign(key, new Uint8Array(256).fill(0xff)), isApiError('BAD_BLINDED_MESSAGE'));
    keys.close();
  });
});
