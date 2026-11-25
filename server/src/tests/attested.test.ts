/**
 * Nullifier service (4c.2) and the hardware-attested card methods (4c.3,
 * 4c.4, 4c.6, 4d.3): emrtd_attested (with the passport_attested alias),
 * philsys_qr_attested, mynumber_attested and face_estimate.
 *
 * "Production" servers here trust ONE extra TEST attestation root next to
 * Google's roots, so a generated chain can stand in for a real locked phone.
 * The real-phone chains are tested in attestation.test.ts.
 */
import 'reflect-metadata';
import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { TEST_SIGNING_CERT_DIGEST, TestAttestationRoot } from '../attestation/test-chain.js';
import { api, DAY, HOUR, makeTicket, newChallenge, ss, startServer, TestDevice, TestServer } from './helpers.js';

const DIGEST = TEST_SIGNING_CERT_DIGEST.toString('hex');
let root: TestAttestationRoot;

before(async () => {
  root = await TestAttestationRoot.create('V18 TEST attestation root', Date.UTC(2026, 10, 9));
});

function keyObject(dev: TestDevice): crypto.KeyObject {
  return crypto.createPublicKey({ key: dev.publicJwk as crypto.JsonWebKey, format: 'jwk' });
}

async function chain(srv: TestServer, dev: TestDevice, challenge: string, over: Record<string, unknown> = {}) {
  return root.chainFor(keyObject(dev), { challenge, nowMs: srv.clock.now(), ...over });
}

function prodServer(extra: Record<string, unknown> = {}) {
  return startServer({
    extraAttestationRoots: [root.rootCert],
    config: { devMode: false, androidCertDigests: [DIGEST], aadhaarNullifierSeed: '1', ...extra },
  });
}

// ---- The app side of the nullifier OPRF (RFC 9474 PSSZERO-Deterministic) -------------

async function nullifierFor(srv: TestServer, message: string, opts: { attest?: boolean; dev?: TestDevice } = {}) {
  const keys = (await api(srv.url, 'GET', '/v1/keys/nullifier')).body.keys;
  const jwk = keys[0];
  const suite = RSABSSA.SHA384.PSSZero.Deterministic();
  const pub = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e }, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
  const msg = new TextEncoder().encode(message);
  const prepared = suite.prepare(msg);
  const { blindedMsg, inv } = await suite.blind(pub, prepared);
  const blindedMessage = Buffer.from(blindedMsg).toString('base64url');
  const dev = opts.dev ?? (await TestDevice.es256());
  const challenge = await newChallenge(srv.url);
  const body: Record<string, unknown> = {
    challenge,
    blindedMessage,
    devicePublicKey: dev.jwkWithAlg,
    deviceSignature: dev.sign(`v18-nullifier\n${challenge}\n${dev.thumbprint}\n${blindedMessage}`),
  };
  if (opts.attest !== false) body.keyAttestation = await chain(srv, dev, challenge);
  const r = await api(srv.url, 'POST', '/v1/nullifier/blind-sign', body);
  if (r.status !== 200) return { r, nullifier: null as string | null };
  const sig = await suite.finalize(pub, prepared, Buffer.from(r.body.blindSignature, 'base64url'), inv);
  return { r, nullifier: crypto.createHash('sha256').update(sig).digest('base64url') };
}

const passportProof = (nullifier: string, over: Record<string, unknown> = {}) => ({
  over18: true,
  docExpiry: '2030-01-31',
  issuingState: 'IND',
  docType: 'P',
  passiveAuth: 'ok',
  chipAuth: 'active_auth',
  nullifier,
  nullifierKeyId: 'v18-nullifier-1',
  ...over,
});

async function issueAttested(
  srv: TestServer,
  method: string,
  proof: unknown,
  opts: { attest?: boolean; chainOpts?: Record<string, unknown>; dev?: TestDevice } = {}
) {
  const dev = opts.dev ?? (await TestDevice.es256());
  const challenge = await newChallenge(srv.url);
  const body: Record<string, unknown> = {
    method,
    challenge,
    devicePublicKey: dev.jwkWithAlg,
    deviceSignature: dev.sign(ss.cardIssue(challenge, dev.thumbprint)),
    proof,
  };
  if (opts.attest !== false) body.keyAttestation = await chain(srv, dev, challenge, opts.chainOpts);
  return { r: await api(srv.url, 'POST', '/v1/card/issue', body), dev };
}

describe('Nullifier service (4c.2)', () => {
  let srv: TestServer;
  before(async () => {
    srv = await prodServer();
  });
  after(async () => srv.close());

  it('publishes v18-nullifier-1 as RSABSSA-SHA384-PSSZERO-Deterministic', async () => {
    const r = await api(srv.url, 'GET', '/v1/keys/nullifier');
    assert.equal(r.status, 200);
    assert.equal(r.body.keys.length, 1);
    assert.equal(r.body.keys[0].kid, 'v18-nullifier-1');
    assert.equal(r.body.keys[0].alg, 'RSABSSA-SHA384-PSSZERO-Deterministic');
    assert.equal(r.headers.get('access-control-allow-origin'), null);
  });

  it('the same document gives the same nullifier from different devices; another document gives another', async () => {
    const a = await nullifierFor(srv, 'v18-doc-v1|IND|K1234567');
    const b = await nullifierFor(srv, 'v18-doc-v1|IND|K1234567');
    const c = await nullifierFor(srv, 'v18-doc-v1|IND|K7654321');
    assert.equal(a.r.status, 200, JSON.stringify(a.r.body));
    assert.equal(a.r.body.keyId, 'v18-nullifier-1');
    assert.equal(a.r.body.attestation.hardwareVerified, true);
    assert.match(a.nullifier!, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(a.nullifier, b.nullifier);
    assert.notEqual(a.nullifier, c.nullifier);
  });

  it('the key survives a restart (the same key store gives the same nullifier)', async () => {
    const store = (srv.services as any).nullifierKey.store;
    const s2 = await startServer({ keyStore: store, extraAttestationRoots: [root.rootCert], config: { devMode: false, androidCertDigests: [DIGEST], aadhaarNullifierSeed: '1' } });
    assert.equal((await nullifierFor(s2, 'v18-doc-v1|IND|K1')).nullifier, (await nullifierFor(srv, 'v18-doc-v1|IND|K1')).nullifier);
    await s2.close();
  });

  it('production needs a valid attestation for this challenge', async () => {
    const none = await nullifierFor(srv, 'x', { attest: false });
    assert.equal(none.r.status, 400);
    assert.equal(none.r.body.code, 'ATTESTATION_REQUIRED');
    // An attestation made for another challenge.
    const dev = await TestDevice.es256();
    const challenge = await newChallenge(srv.url);
    const blindedMessage = Buffer.alloc(256, 1).toString('base64url');
    const r = await api(srv.url, 'POST', '/v1/nullifier/blind-sign', {
      challenge,
      blindedMessage,
      devicePublicKey: dev.jwkWithAlg,
      deviceSignature: dev.sign(`v18-nullifier\n${challenge}\n${dev.thumbprint}\n${blindedMessage}`),
      keyAttestation: await chain(srv, dev, 'f'.repeat(64)),
    });
    assert.equal(r.body.reason, 'challenge_mismatch');
  });

  it('checks the signing string and the blinded size', async () => {
    const dev = await TestDevice.es256();
    const challenge = await newChallenge(srv.url);
    const blindedMessage = Buffer.alloc(256, 1).toString('base64url');
    const bad = await api(srv.url, 'POST', '/v1/nullifier/blind-sign', {
      challenge,
      blindedMessage,
      devicePublicKey: dev.jwkWithAlg,
      deviceSignature: dev.sign(`v18-card-issue\n${challenge}\n${dev.thumbprint}`),
      keyAttestation: await chain(srv, dev, challenge),
    });
    assert.equal(bad.status, 401);
    assert.equal(bad.body.code, 'BAD_DEVICE_SIGNATURE');
    const c2 = await newChallenge(srv.url);
    const short = Buffer.alloc(100, 1).toString('base64url');
    const r = await api(srv.url, 'POST', '/v1/nullifier/blind-sign', {
      challenge: c2,
      blindedMessage: short,
      devicePublicKey: dev.jwkWithAlg,
      deviceSignature: dev.sign(`v18-nullifier\n${c2}\n${dev.thumbprint}\n${short}`),
      keyAttestation: await chain(srv, dev, c2),
    });
    assert.equal(r.body.code, 'BAD_BLINDED_MESSAGE');
  });

  it('rate limits: 5 per device key per day', async () => {
    const dev = await TestDevice.es256();
    for (let i = 0; i < 5; i++) assert.equal((await nullifierFor(srv, `m${i}`, { dev })).r.status, 200);
    const sixth = await nullifierFor(srv, 'm6', { dev });
    assert.equal(sixth.r.status, 429);
    assert.equal(sixth.r.body.code, 'RATE_LIMITED');
    assert.ok(Number(sixth.r.headers.get('retry-after')) > 0);
    srv.clock.advance(DAY + 1000);
    assert.equal((await nullifierFor(srv, 'm7', { dev })).r.status, 200);
  });

  it('rate limits: 20 per IP per hour (V18_NULLIFIER_PER_IP_PER_HOUR)', async () => {
    const s = await prodServer({ nullifierPerIpPerHour: 20 });
    for (let i = 0; i < 20; i++) assert.equal((await nullifierFor(s, `ip${i}`)).r.status, 200, `request ${i}`);
    assert.equal((await nullifierFor(s, 'ip21')).r.status, 429);
    s.clock.advance(HOUR + 1000);
    assert.equal((await nullifierFor(s, 'ip22')).r.status, 200);
    await s.close();
  });

  it('dev mode accepts no attestation and says so', async () => {
    const dev = await startServer();
    const r = await nullifierFor(dev, 'x', { attest: false });
    assert.equal(r.r.status, 200);
    assert.deepEqual(r.r.body.attestation.devModeExceptions, ['no_attestation']);
    assert.match(r.r.body.attestation.note, /TEST MODE/);
    await dev.close();
  });

  it('production without V18_ANDROID_CERT_DIGESTS: attested methods are not configured (503)', async () => {
    const s = await startServer({ config: { devMode: false, androidCertDigests: [], aadhaarNullifierSeed: '1' } });
    const r = await nullifierFor(s, 'x');
    assert.equal(r.r.status, 503);
    assert.equal((await api(s.url, 'GET', '/v1/health')).body.methods.emrtd_attested, 'not_configured');
    await s.close();
  });
});

describe('emrtd_attested and the passport_attested alias (4c.4, 4d.3)', () => {
  let srv: TestServer;
  before(async () => {
    srv = await prodServer();
  });
  after(async () => srv.close());

  it('issues a "substantial" card that works for tickets and ends at the document expiry when sooner', async () => {
    const { nullifier } = await nullifierFor(srv, 'v18-doc-v1|IND|P1111111');
    const soon = new Date(srv.clock.now() + 40 * DAY).toISOString().slice(0, 10);
    const { r, dev } = await issueAttested(srv, 'emrtd_attested', passportProof(nullifier!, { docExpiry: soon }));
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.equal(r.body.method, 'emrtd_attested');
    assert.equal(r.body.assuranceLevel, 'substantial');
    assert.equal(r.body.attestation.hardwareVerified, true);
    assert.equal(r.body.validUntil, new Date(Date.parse(`${soon}T00:00:00Z`) + DAY).toISOString());
    assert.ok(await makeTicket(srv, r.body.cardId, dev, { origin: 'https://site.test', challenge: 'c'.repeat(20) }));
  });

  it('caps one document at 3 cards, counting passport_attested and emrtd_attested together', async () => {
    const { nullifier } = await nullifierFor(srv, 'v18-doc-v1|DEU|C01X00T47');
    const ok1 = await issueAttested(srv, 'passport_attested', { ...passportProof(nullifier!), docType: undefined, issuingState: 'D<<' });
    assert.equal(ok1.r.status, 201, JSON.stringify(ok1.r.body));
    assert.equal(ok1.r.body.method, 'passport_attested');
    assert.equal((await issueAttested(srv, 'emrtd_attested', passportProof(nullifier!, { issuingState: 'D<<' }))).r.status, 201);
    assert.equal((await issueAttested(srv, 'emrtd_attested', passportProof(nullifier!, { docType: 'I', issuingState: 'D<<' }))).r.status, 201);
    const fourth = await issueAttested(srv, 'passport_attested', passportProof(nullifier!, { issuingState: 'D<<' }));
    assert.equal(fourth.r.status, 409);
    assert.equal(fourth.r.body.code, 'NULLIFIER_OVERUSED');
  });

  it('accepts chip ID cards and residence permits (docType I, A, C) and refuses other letters', async () => {
    for (const docType of ['I', 'A', 'C']) {
      const { nullifier } = await nullifierFor(srv, `v18-doc-v1|FRA|${docType}9`);
      assert.equal((await issueAttested(srv, 'emrtd_attested', passportProof(nullifier!, { docType }))).r.status, 201, docType);
    }
    const { nullifier } = await nullifierFor(srv, 'v18-doc-v1|FRA|X');
    assert.equal((await issueAttested(srv, 'emrtd_attested', passportProof(nullifier!, { docType: 'V' }))).r.body.reason, 'malformed');
  });

  it('refuses bad proofs: under 18, expired, failed passive auth, wrong key ID, personal data, bad shapes', async () => {
    const { nullifier } = await nullifierFor(srv, 'v18-doc-v1|IND|BAD');
    const n = nullifier!;
    const cases: [Record<string, unknown>, number, string][] = [
      [passportProof(n, { over18: false }), 403, 'UNDER_AGE'],
      [passportProof(n, { docExpiry: '2026-01-01' }), 400, 'ID_EXPIRED'],
      [passportProof(n, { passiveAuth: 'failed' }), 400, 'passive_auth_failed'],
      [passportProof(n, { nullifierKeyId: 'v18-nullifier-2' }), 400, 'wrong_nullifier_key'],
      [passportProof(n, { name: 'Alice' }), 400, 'unexpected_field'],
      [passportProof(n, { documentNumber: 'P1234567' }), 400, 'unexpected_field'],
      [passportProof(n, { chipAuth: 'maybe' }), 400, 'malformed'],
      [passportProof(n, { issuingState: 'in' }), 400, 'malformed'],
      [passportProof('short'), 400, 'malformed'],
    ];
    for (const [proof, status, code] of cases) {
      const { r } = await issueAttested(srv, 'emrtd_attested', proof);
      assert.equal(r.status, status, JSON.stringify(proof));
      assert.equal(r.body.reason ?? r.body.code, code, JSON.stringify(proof));
    }
  });

  it('refuses unattested, unlocked or software-key phones in production', async () => {
    const { nullifier } = await nullifierFor(srv, 'v18-doc-v1|IND|NOATT');
    assert.equal((await issueAttested(srv, 'emrtd_attested', passportProof(nullifier!), { attest: false })).r.body.code, 'ATTESTATION_REQUIRED');
    assert.equal(
      (await issueAttested(srv, 'emrtd_attested', passportProof(nullifier!), { chainOpts: { deviceLocked: false } })).r.body.reason,
      'boot_not_verified'
    );
    assert.equal(
      (await issueAttested(srv, 'emrtd_attested', passportProof(nullifier!), { chainOpts: { securityLevel: 0 } })).r.body.reason,
      'software_security_level'
    );
  });
});

describe('philsys_qr_attested and mynumber_attested (4d.3; My Number switched on for these tests)', () => {
  let srv: TestServer;
  before(async () => {
    srv = await prodServer({ enableMyNumber: true });
  });
  after(async () => srv.close());

  it('PhilSys QR: a card with the method full validity; the PSA check must be ok', async () => {
    const { nullifier } = await nullifierFor(srv, 'v18-philsys-v1|1234-5678-9012-3456');
    const ok = await issueAttested(srv, 'philsys_qr_attested', { over18: true, qrSignature: 'ok', nullifier, nullifierKeyId: 'v18-nullifier-1' });
    assert.equal(ok.r.status, 201, JSON.stringify(ok.r.body));
    assert.equal(Date.parse(ok.r.body.validUntil) - srv.clock.now(), 180 * DAY);
    const bad = await issueAttested(srv, 'philsys_qr_attested', { over18: true, qrSignature: 'bad', nullifier, nullifierKeyId: 'v18-nullifier-1' });
    assert.equal(bad.r.body.reason, 'qr_signature_failed');
    const pcn = await issueAttested(srv, 'philsys_qr_attested', { over18: true, qrSignature: 'ok', pcn: '1234', nullifier, nullifierKeyId: 'v18-nullifier-1' });
    assert.equal(pcn.r.body.reason, 'unexpected_field');
  });

  it('My Number Card: ends at the JPKI certificate expiry when sooner; the chain must be ok', async () => {
    const { nullifier } = await nullifierFor(srv, 'v18-jpki-v1|ab12');
    const certExpiry = new Date(srv.clock.now() + 20 * DAY).toISOString().slice(0, 10);
    const ok = await issueAttested(srv, 'mynumber_attested', { over18: true, jpkiChain: 'ok', certExpiry, nullifier, nullifierKeyId: 'v18-nullifier-1' });
    assert.equal(ok.r.status, 201, JSON.stringify(ok.r.body));
    assert.equal(ok.r.body.validUntil, new Date(Date.parse(`${certExpiry}T00:00:00Z`) + DAY).toISOString());
    const bad = await issueAttested(srv, 'mynumber_attested', { over18: true, jpkiChain: 'failed', certExpiry, nullifier, nullifierKeyId: 'v18-nullifier-1' });
    assert.equal(bad.r.body.reason, 'jpki_chain_failed');
  });

  it('nullifiers of different methods never share a cap', async () => {
    const { nullifier } = await nullifierFor(srv, 'v18-philsys-v1|SAME');
    for (let i = 0; i < 3; i++) {
      assert.equal((await issueAttested(srv, 'philsys_qr_attested', { over18: true, qrSignature: 'ok', nullifier, nullifierKeyId: 'v18-nullifier-1' })).r.status, 201);
    }
    const mn = await issueAttested(srv, 'mynumber_attested', { over18: true, jpkiChain: 'ok', certExpiry: '2031-01-01', nullifier, nullifierKeyId: 'v18-nullifier-1' });
    assert.equal(mn.r.status, 201);
  });
});

describe('mynumber_attested is off by default (PROTOCOL.md 4d.4b)', () => {
  const JP = {
    version: 1,
    countries: [
      {
        code: 'JP',
        name: 'Japan',
        region: 'asia',
        methods: [
          { method: 'emrtd_attested', label: 'Passport (chip)', documents: ['Japanese passport'], docTypes: ['P'], needs: ['nfc'], privacy: 'on_device', platforms: ['android'] },
          { method: 'mynumber_attested', label: 'My Number Card', documents: ['My Number Card'], needs: ['nfc', 'password'], privacy: 'on_device', platforms: ['android'] },
        ],
      },
    ],
  };
  const catalogFile = () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-jp-'));
    fs.writeFileSync(path.join(dir, 'countries.json'), JSON.stringify(JP));
    return path.join(dir, 'countries.json');
  };
  const myNumberProof = (nullifier: string) => ({ over18: true, jpkiChain: 'ok', certExpiry: '2031-01-01', nullifier, nullifierKeyId: 'v18-nullifier-1' });

  it('health says "disabled", card issue gives 501 METHOD_DISABLED, and the catalog leaves it out of JP', async () => {
    for (const devMode of [true, false]) {
      const srv = await (devMode ? startServer({ config: { catalogPath: catalogFile() } }) : prodServer({ catalogPath: catalogFile() }));
      assert.equal((await api(srv.url, 'GET', '/v1/health')).body.methods.mynumber_attested, 'disabled');
      const { r } = await issueAttested(srv, 'mynumber_attested', myNumberProof(crypto.randomBytes(32).toString('base64url')));
      assert.equal(r.status, 501);
      assert.equal(r.body.code, 'METHOD_DISABLED');
      assert.match(r.body.error, /4d.4b/);
      const jp = (await api(srv.url, 'GET', '/v1/catalog?country=JP')).body.countries[0];
      assert.deepEqual(jp.methods.map((m: any) => m.method), ['emrtd_attested']);
      await srv.close();
    }
  });

  it('V18_ENABLE_MYNUMBER=1 turns the kept code back on (health, card, catalog)', async () => {
    const srv = await startServer({ env: { V18_ENABLE_MYNUMBER: '1' }, config: { catalogPath: catalogFile() } });
    assert.equal(srv.services.config.enableMyNumber, true);
    assert.equal((await api(srv.url, 'GET', '/v1/health')).body.methods.mynumber_attested, 'ready');
    const { r } = await issueAttested(srv, 'mynumber_attested', myNumberProof(crypto.randomBytes(32).toString('base64url')));
    assert.equal(r.status, 201, JSON.stringify(r.body));
    const jp = (await api(srv.url, 'GET', '/v1/catalog?country=JP')).body.countries[0];
    assert.deepEqual(jp.methods.map((m: any) => m.method), ['emrtd_attested', 'mynumber_attested']);
    await srv.close();
  });
});

describe('face_estimate (4c.6)', () => {
  const faceProof = (over: Record<string, unknown> = {}) => ({ estimator: 'v18-face-test-model', challengeAge: 25, passed: true, liveness: 'passed', ...over });

  it('is off (501) unless V18_FACE_MODELS names the model', async () => {
    const srv = await prodServer();
    const { r } = await issueAttested(srv, 'face_estimate', faceProof());
    assert.equal(r.status, 501);
    assert.equal(r.body.code, 'METHOD_DISABLED');
    assert.equal((await api(srv.url, 'GET', '/v1/health')).body.methods.face_estimate, 'disabled');
    await srv.close();
  });

  it('with an accepted model: a "low" 30-day card; wrong model, low challenge age, no liveness and a fail are refused', async () => {
    const srv = await prodServer({ faceModels: ['v18-face-test-model'] });
    const ok = await issueAttested(srv, 'face_estimate', faceProof());
    assert.equal(ok.r.status, 201, JSON.stringify(ok.r.body));
    assert.equal(ok.r.body.assuranceLevel, 'low');
    assert.equal(Date.parse(ok.r.body.validUntil) - srv.clock.now(), 30 * DAY);
    assert.equal((await issueAttested(srv, 'face_estimate', faceProof({ estimator: 'other' }))).r.body.reason, 'unknown_estimator');
    assert.equal((await issueAttested(srv, 'face_estimate', faceProof({ challengeAge: 21 }))).r.body.reason, 'challenge_age_too_low');
    assert.equal((await issueAttested(srv, 'face_estimate', faceProof({ liveness: 'failed' }))).r.body.reason, 'liveness_failed');
    const fail = await issueAttested(srv, 'face_estimate', faceProof({ passed: false }));
    assert.equal(fail.r.status, 403);
    assert.equal(fail.r.body.reason, 'face_estimate_not_passed');
    assert.equal((await issueAttested(srv, 'face_estimate', faceProof({ image: 'x' }))).r.body.reason, 'unexpected_field');
    await srv.close();
  });
});

describe('passport_zk and unknown methods', () => {
  it('passport_zk is 501 METHOD_NOT_READY; connector methods point to /v1/connect', async () => {
    const srv = await startServer();
    const dev = await TestDevice.es256();
    const c = await newChallenge(srv.url);
    const r = await api(srv.url, 'POST', '/v1/card/issue', { method: 'passport_zk', challenge: c, devicePublicKey: dev.jwkWithAlg, deviceSignature: dev.sign(ss.cardIssue(c, dev.thumbprint)) });
    assert.equal(r.status, 501);
    assert.equal(r.body.code, 'METHOD_NOT_READY');
    const c2 = await newChallenge(srv.url);
    const r2 = await api(srv.url, 'POST', '/v1/card/issue', { method: 'connector:singpass', challenge: c2 });
    assert.equal(r2.body.code, 'METHOD_UNKNOWN');
    assert.match(r2.body.error, /\/v1\/connect/);
    await srv.close();
  });
});
