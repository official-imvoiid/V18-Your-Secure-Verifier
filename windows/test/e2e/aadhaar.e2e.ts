// Aadhaar end to end, with the REAL proof builder (dist/prover.cjs) and the official circuit files.
//
// Part 1 (no server needed): a real Groth16 proof from a fresh TEST QR, checked with
//   @anon-aadhaar/core's verify(), the same verifier the V18 server uses.
//   Circuit files: V18_ARTIFACTS_DIR, or the server's copy in server/assets/artifacts (read only).
// Part 2 (live server): the whole app flow against "npm run dev --prefix server": the app downloads
//   the files from GET /v1/artifacts/*, checks them, builds the proof, and the server issues a real
//   anon_aadhaar card, which then makes a ticket. Skips with a message if the server can't do Aadhaar.
//
// Windows Hello is played by FakeHelloAddon (RS256 keys in memory), unless V18_REAL_HELLO=1, which
// uses the real Windows Hello (a person must approve each prompt).
// Run: npm run build, then npm run test:e2e.

import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ArtifactStore } from '../../src/main/artifacts.js';
import { V18Engine } from '../../src/main/engine.js';
import { HelloKeyProvider, newKeyName, type HelloAddon } from '../../src/main/keys.js';
import { nodeProverSpawner, runProver } from '../../src/main/prover-host.js';
import { aadhaarSignal } from '../../src/shared/aadhaar-signal.js';
import { ApiError, V18Api } from '../../src/shared/api.js';
import { b64urlEncode } from '../../src/shared/b64url.js';
import { devicePublicKeyBody, jwkThumbprint } from '../../src/shared/jwk.js';
import { cardDeleteString, cardIssueString, signingBytes, ticketRequestString } from '../../src/shared/signing.js';
import { blindTicket, buildTicketPayload, finalizeTicket, pickTicketKey, verifyTicketString } from '../../src/shared/ticket.js';
import { FakeHelloAddon } from '../helpers/fake-hello.js';
import { makeTestAadhaarQr } from '../helpers/test-aadhaar.js';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..', '..');
const bundle = path.join(root, 'dist', 'prover.cjs');
const assetsDir = path.join(root, 'assets');
const filesDir = process.env.V18_ARTIFACTS_DIR ?? path.join(root, '..', 'server', 'assets', 'artifacts');
const have = (f: string) => existsSync(path.join(filesDir, f));
const offlineSkip = !existsSync(bundle)
  ? 'run "npm run build" first'
  : have('aadhaar-verifier.wasm') && have('circuit_final.zkey') && have('vkey.json')
    ? false
    : `no circuit files in ${filesDir} (set V18_ARTIFACTS_DIR)`;
const testCert = () => readFileSync(path.join(assetsDir, 'aadhaar', 'anon-aadhaar-test-certificate.pem'), 'utf8');
const log = (...a: unknown[]) => console.log('   [aadhaar]', ...a);

describe('real Anon Aadhaar proof on this PC (no server needed)', { skip: offlineSkip }, () => {
  // snarkjs keeps its worker threads (globalThis.curve_bn128) alive after verify(); stop them.
  after(async () => {
    await (globalThis as { curve_bn128?: { terminate(): Promise<void> } }).curve_bn128?.terminate();
  });
  it("builds a real proof that @anon-aadhaar/core's verifier accepts, revealing only 18+", async () => {
    const signal = aadhaarSignal('a'.repeat(64), 'test-thumbprint');
    const r = await runProver(nodeProverSpawner(bundle), {
      type: 'prove',
      qrText: makeTestAadhaarQr(),
      certPem: testCert(),
      nullifierSeed: '180018001800180018',
      signal,
      wasmPath: path.join(filesDir, 'aadhaar-verifier.wasm'),
      zkeyPath: path.join(filesDir, 'circuit_final.zkey'),
      vkeyPath: path.join(filesDir, 'vkey.json'),
    });
    log(`proof built in ${(r.ms.total / 1000).toFixed(1)} s (witness ${(r.ms.witness / 1000).toFixed(1)} s, Groth16 ${(r.ms.prove / 1000).toFixed(1)} s)`);
    const core = require('@anon-aadhaar/core') as {
      init(a: { wasmURL: string; zkeyURL: string; vkeyURL: string; artifactsOrigin: number }): Promise<void>;
      verify(pcd: unknown, test?: boolean): Promise<boolean>;
      hash(m: string): string;
      ArtifactsOrigin: { local: number };
      testPublicKeyHash: string;
    };
    await core.init({ wasmURL: '', zkeyURL: '', vkeyURL: path.join(filesDir, 'vkey.json'), artifactsOrigin: core.ArtifactsOrigin.local });
    assert.equal(r.proof.proof.pubkeyHash, core.testPublicKeyHash, 'TEST key');
    assert.equal(r.proof.proof.signalHash, core.hash(signal), 'signal binding (PROTOCOL 4b item 1)');
    assert.equal(r.proof.proof.ageAbove18, '1');
    assert.deepEqual([r.proof.proof.gender, r.proof.proof.pincode, r.proof.proof.state], ['0', '0', '0'], 'reveals only 18+');
    assert.equal(await core.verify(r.proof, true), true);
    // Change one public value and the proof no longer verifies.
    const bad = JSON.parse(JSON.stringify(r.proof));
    bad.proof.signalHash = core.hash(aadhaarSignal('b'.repeat(64), 'test-thumbprint'));
    assert.equal(await core.verify(bad, true), false);
  });
});

const BASE_2A = 'http://localhost:8080/v1';
let serverSkip: string | false = offlineSkip;
if (!serverSkip) {
  try {
    const h = await new V18Api(BASE_2A).health();
    const m = (h.methods as Record<string, unknown> | undefined)?.anon_aadhaar;
    if (!h.devMode) serverSkip = 'the server on :8080 is not in dev mode';
    else if (m !== 'ready') serverSkip = `the server says anon_aadhaar is "${String(m)}"`;
  } catch {
    serverSkip = 'no V18 server on http://localhost:8080';
  }
}

describe('the REAL server accepts a real proof from this PC (card issue, ticket, delete)', { skip: serverSkip }, () => {
  it('real proof -> POST /v1/card/issue -> anon_aadhaar card -> ticket -> signed delete', async () => {
    const api = new V18Api(BASE_2A);
    const health = await api.health();
    const seed = String(health.aadhaarNullifierSeed);
    const realHello = process.env.V18_REAL_HELLO === '1';
    const addon: HelloAddon = realHello ? require(path.join(root, 'native', 'v18-hello', 'v18_hello.node')) : new FakeHelloAddon();
    const keys = new HelloKeyProvider(addon);
    const name = newKeyName();
    try {
      const jwk = await keys.create(name);
      const thumb = jwkThumbprint(jwk);
      const { challenge } = await api.challenge();
      const sig = await keys.sign(name, signingBytes(cardIssueString(challenge, thumb)));
      const r = await runProver(nodeProverSpawner(bundle), {
        type: 'prove',
        qrText: makeTestAadhaarQr(),
        certPem: testCert(),
        nullifierSeed: seed,
        signal: aadhaarSignal(challenge, thumb),
        wasmPath: path.join(filesDir, 'aadhaar-verifier.wasm'),
        zkeyPath: path.join(filesDir, 'circuit_final.zkey'),
        vkeyPath: path.join(filesDir, 'vkey.json'),
      });
      const card = await api.issueCard({
        method: 'anon_aadhaar',
        challenge,
        devicePublicKey: devicePublicKeyBody(jwk),
        deviceSignature: { alg: sig.alg, sig: b64urlEncode(sig.sig) },
        proof: r.proof,
      });
      log(`REAL SERVER ACCEPTED the proof: ${card.method} card, assurance "${card.assuranceLevel}", valid until ${card.validUntil}; proof ${(r.ms.total / 1000).toFixed(1)} s; Windows Hello: ${realHello ? 'REAL' : 'fake RS256 key'}`);
      assert.equal(card.method, 'anon_aadhaar');
      assert.equal(card.minAgeCertified, 18);
      assert.equal((await api.cardStatus(card.cardId)).status, 'active');

      // The same proof can't be used again (its challenge is spent).
      await assert.rejects(
        api.issueCard({ method: 'anon_aadhaar', challenge, devicePublicKey: devicePublicKeyBody(jwk), deviceSignature: { alg: sig.alg, sig: b64urlEncode(sig.sig) }, proof: r.proof }),
        (e: unknown) => e instanceof ApiError && e.status >= 400,
      );

      // A ticket from the new card verifies with the server's JWKS.
      const jwks = await api.keys();
      const key = pickTicketKey(jwks, 18, Math.floor(Date.now() / 1000))!;
      const blinded = await blindTicket(key, buildTicketPayload({ origin: 'http://localhost:3000', challenge: 'aadhaar-e2e-ticket-0001', minAge: 18, nowMs: Date.now() }));
      const c2 = await api.challenge();
      const s2 = await keys.sign(name, signingBytes(ticketRequestString(card.cardId, c2.challenge, key.kid, blinded.blindedMessage)));
      const bs = await api.blindSign({ cardId: card.cardId, challenge: c2.challenge, keyId: key.kid, blindedMessage: blinded.blindedMessage, deviceSignature: { alg: s2.alg, sig: b64urlEncode(s2.sig) } });
      const ticket = await finalizeTicket(blinded, bs.blindSignature);
      assert.equal((await verifyTicketString(ticket, key)).ok, true);

      // Signed delete frees the nullifier slot.
      const c3 = await api.challenge();
      const s3 = await keys.sign(name, signingBytes(cardDeleteString(card.cardId, c3.challenge)));
      await api.deleteCard(card.cardId, { challenge: c3.challenge, deviceSignature: { alg: s3.alg, sig: b64urlEncode(s3.sig) } });
      assert.equal((await api.cardStatus(card.cardId)).status, 'revoked');
    } finally {
      await keys.remove(name).catch(() => undefined);
    }
  });
});

const BASE = 'http://localhost:8080/v1';
let liveSkip: string | false = offlineSkip;
if (!liveSkip) {
  try {
    const h = await new V18Api(BASE).health();
    const m = (h.methods as Record<string, unknown> | undefined)?.anon_aadhaar;
    const man = await fetch(`${BASE}/artifacts/manifest`).catch(() => null);
    if (!h.devMode) liveSkip = 'the server on :8080 is not in dev mode';
    else if (m !== 'ready') liveSkip = `the server says anon_aadhaar is "${String(m)}"`;
    else if (!man || !man.ok) liveSkip = `the server has no GET /v1/artifacts/manifest (${man ? man.status : 'unreachable'})`;
  } catch {
    liveSkip = 'no V18 server on http://localhost:8080';
  }
}

describe('Aadhaar card from the REAL server, through the whole app flow', { skip: liveSkip }, () => {
  const cache = mkdtempSync(path.join(os.tmpdir(), 'v18-e2e-artifacts-'));
  after(() => rmSync(cache, { recursive: true, force: true }));

  it('downloads and checks the files, builds the proof, gets a real anon_aadhaar card, and uses it for a ticket', async () => {
    let data: any = { serverUrl: BASE, settings: { firstRunDone: true } };
    const realHello = process.env.V18_REAL_HELLO === '1';
    const addon: HelloAddon = realHello ? require(path.join(root, 'native', 'v18-hello', 'v18_hello.node')) : new FakeHelloAddon();
    const e = new V18Engine({
      debug: true,
      store: { load: () => data, save: (j) => (data = JSON.parse(j)) },
      hello: new HelloKeyProvider(addon),
      testKeys: null,
      makeQr: async () => 'data:,qr',
      onChange: () => undefined,
      assetsDir,
      artifacts: new ArtifactStore(cache),
      spawnProver: nodeProverSpawner(bundle),
    });
    await e.init();
    assert.equal(e.getView().aadhaarReady, true);
    const qrFile = path.join(cache, 'test-qr.txt');
    writeFileSync(qrFile, makeTestAadhaarQr());
    await e.aadhaarReadFile(qrFile);
    assert.equal(e.getView().aadhaar?.stage, 'read');
    const t0 = Date.now();
    await e.aadhaarBuild();
    const v = e.getView();
    assert.equal(v.screen, 'card-saved', JSON.stringify(v.error));
    log(`whole flow ${((Date.now() - t0) / 1000).toFixed(1)} s (download + check + ${v.lastProofSeconds} s proof), Windows Hello: ${realHello ? 'REAL' : 'fake RS256 keys'}`);
    assert.equal(data.card.method, 'anon_aadhaar');
    const status = await new V18Api(BASE).cardStatus(data.card.cardId);
    assert.equal(status.status, 'active');

    // The new card makes a ticket for a site, which verifies with the server's JWKS.
    const res = await fetch(`${BASE}/pairing/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://localhost:3000' },
      body: JSON.stringify({ origin: 'http://localhost:3000', challenge: 'aadhaar-e2e-' + Date.now(), minAge: 18, ttlSeconds: 120 }),
    });
    assert.equal(res.status, 201);
    const s = (await res.json()) as { sessionId: string; deepLink: string };
    await e.handleDeepLink(s.deepLink);
    await e.askApprove();
    assert.equal(e.getView().ask?.stage, 'sent', JSON.stringify(e.getView().ask));
    const poll = (await (await fetch(`${BASE}/pairing/${s.sessionId}`)).json()) as { ticket?: string };
    assert.ok(poll.ticket);
    const keys = await new V18Api(BASE).keys();
    const kid = poll.ticket!.split('.')[0];
    const checked = await verifyTicketString(poll.ticket!, keys.find((k) => k.kid === kid)!);
    assert.ok(checked.ok, 'ticket verifies with the JWKS');

    // Clean up: signed delete frees the nullifier slot.
    await e.deleteCard();
    assert.equal(data.card ?? null, null);
    e.shutdown();
  });
});
