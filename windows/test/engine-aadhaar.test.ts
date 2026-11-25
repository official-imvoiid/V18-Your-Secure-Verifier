// The Aadhaar flow in the engine, against the protocol mock server: QR file -> seal check ->
// proof files -> Windows Hello key -> challenge -> signature -> proof builder -> card.
// The proof builder here is a FAKE (test/helpers/fake-prover.ts); the real one runs in
// test/e2e/aadhaar.e2e.ts against the real server.

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ArtifactStore } from '../src/main/artifacts.js';
import { V18Engine, type EngineDeps } from '../src/main/engine.js';
import { HelloKeyProvider } from '../src/main/keys.js';
import type { ViewState } from '../src/main/view.js';
import { FakeHelloAddon } from './helpers/fake-hello.js';
import { fakeProver } from './helpers/fake-prover.js';
import { MOCK_NULLIFIER_SEED, startMockServer, type MockServer } from './helpers/mock-server.js';
import { dobForAge, makeTestAadhaarQr } from './helpers/test-aadhaar.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const assetsDir = path.join(here, '..', 'assets');
const tmp = mkdtempSync(path.join(os.tmpdir(), 'v18-engine-aadhaar-'));

const files = {
  'aadhaar-verifier.wasm': randomBytes(20_000),
  'circuit_final.zkey': randomBytes(200_000),
  'vkey.json': Buffer.from('{"protocol":"groth16"}'),
};
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const pins = {
  wasm: { name: 'aadhaar-verifier.wasm', sha256: sha(files['aadhaar-verifier.wasm']), bytes: files['aadhaar-verifier.wasm'].length },
  zkey: { name: 'circuit_final.zkey', sha256: sha(files['circuit_final.zkey']), bytes: files['circuit_final.zkey'].length },
  vkey: { name: 'vkey.json', sha256: sha(files['vkey.json']), bytes: files['vkey.json'].length },
};

function qrFile(opts: Parameters<typeof makeTestAadhaarQr>[0] = {}): string {
  const f = path.join(tmp, `qr-${randomBytes(4).toString('hex')}.txt`);
  writeFileSync(f, makeTestAadhaarQr(opts));
  return f;
}

function waitFor(get: () => ViewState, pred: (v: ViewState) => boolean, ms = 8000): Promise<ViewState> {
  const end = Date.now() + ms;
  return new Promise((resolve, reject) => {
    const t = () => {
      const v = get();
      if (pred(v)) return resolve(v);
      if (Date.now() > end) return reject(new Error('timed out; last view: ' + JSON.stringify({ screen: v.screen, error: v.error, work: v.work?.steps })));
      setTimeout(t, 5);
    };
    t();
  });
}

describe('Aadhaar flow in the engine (mock server, fake proof builder)', () => {
  let mock: MockServer;
  before(async () => {
    mock = await startMockServer({ devMode: true, artifacts: files });
  });
  after(async () => {
    await mock.close();
  });

  function makeEngine(over: Partial<EngineDeps> = {}) {
    let data: any = { serverUrl: mock.url, settings: { firstRunDone: true } };
    const hello = new FakeHelloAddon();
    const views: ViewState[] = [];
    const prover = fakeProver();
    const engine = new V18Engine({
      debug: true,
      store: { load: () => data, save: (j) => (data = JSON.parse(j)) },
      hello: new HelloKeyProvider(hello),
      testKeys: null,
      makeQr: async () => 'data:,qr',
      onChange: (v) => views.push(v),
      extraServerOrigins: [mock.origin],
      assetsDir,
      artifacts: new ArtifactStore(mkdtempSync(path.join(tmp, 'cache-')), undefined, pins),
      spawnProver: prover,
      ...over,
    });
    return { engine, hello, views, prover, stored: () => data, view: () => engine.getView() };
  }

  it('makes an anon_aadhaar card from a TEST QR, bound to this challenge and key', async () => {
    const { engine, hello, views, prover, stored, view } = makeEngine();
    await engine.init();
    assert.equal(view().aadhaarReady, true);
    const qr = makeTestAadhaarQr();
    const f = path.join(tmp, 'adult.txt');
    writeFileSync(f, qr);
    await engine.aadhaarReadFile(f);
    assert.equal(view().screen, 'card-qr');
    assert.equal(view().aadhaar?.stage, 'read');
    assert.equal(view().aadhaar?.testQr, true);
    await engine.aadhaarBuild();
    assert.equal(view().screen, 'card-saved', JSON.stringify(view().error));
    assert.equal(stored().card.method, 'anon_aadhaar');
    assert.equal(view().proofFilesCached, true);
    assert.equal(typeof view().lastProofSeconds, 'number');
    // One job, with the server's seed and the protocol signal; two Hello prompts (make key, sign).
    assert.equal(prover.jobs.length, 1);
    assert.equal(prover.jobs[0].nullifierSeed, MOCK_NULLIFIER_SEED);
    assert.match(prover.jobs[0].signal, /^0x[0-9a-f]{64}$/);
    assert.equal(prover.killed, 1);
    assert.equal(hello.signCount, 1);
    assert.equal(mock.aadhaarProofs.length >= 1, true);
    // Progress was shown for downloading, checking and proving.
    const steps = views.filter((v) => v.screen === 'card-working').map((v) => v.work?.steps.findIndex((s) => s.state === 'cur'));
    for (const i of [0, 2, 3, 4, 5]) assert.ok(steps.includes(i), `step ${i} shown`);
    assert.ok(views.some((v) => v.work?.progress?.label === 'Combining points (1 of 5)'));
    // The QR never reached a window, and is gone from memory.
    for (const v of views) assert.ok(!JSON.stringify(v).includes(qr.slice(0, 40)));
    assert.equal((engine as any).pendingQr, null);
  });

  it('refuses a QR from someone under 18 before building anything', async () => {
    const { engine, prover, view } = makeEngine();
    await engine.init();
    await engine.aadhaarReadFile(qrFile({ dob: dobForAge(15) }));
    assert.equal(view().aadhaar?.message, 'under18');
    await engine.aadhaarBuild();
    assert.equal(prover.jobs.length, 0);
    assert.equal(view().screen, 'card-qr');
  });

  it('shows the under-18 screen if the proof says under 18', async () => {
    const prover = fakeProver({ ageAbove18: '0' });
    const { engine, hello, view, stored } = makeEngine({ spawnProver: prover });
    await engine.init();
    await engine.aadhaarReadFile(qrFile());
    await engine.aadhaarBuild();
    assert.equal(view().screen, 'err-under18');
    assert.equal(stored().card ?? null, null);
    assert.equal(hello.keys.size, 0, 'the new Windows Hello key was removed');
  });

  it('cancel during the proof sends nothing, removes the key and kills the proof builder', async () => {
    const prover = fakeProver({ delayMs: 2000 });
    const { engine, hello, view, stored } = makeEngine({ spawnProver: prover });
    await engine.init();
    await engine.aadhaarReadFile(qrFile());
    const run = engine.aadhaarBuild();
    await waitFor(view, (v) => v.work?.steps[4]?.state === 'cur');
    assert.equal(view().work?.cancellable, true);
    engine.aadhaarCancel();
    await run;
    assert.equal(view().screen, 'card-qr');
    assert.match(view().notice ?? '', /Nothing was sent/);
    assert.equal(prover.killed, 1);
    assert.equal(stored().card ?? null, null);
    await waitFor(view, () => hello.keys.size === 0);
    assert.equal(mock.calls.filter((c) => c === 'POST /card/issue').length >= 0, true);
  });

  it('a seal the circuit refuses shows the seal error', async () => {
    const prover = fakeProver({ fail: { type: 'error', code: 'BAD_QR', message: "The circuit didn't accept this QR." } });
    const { engine, view } = makeEngine({ spawnProver: prover });
    await engine.init();
    await engine.aadhaarReadFile(qrFile());
    await engine.aadhaarBuild();
    assert.equal(view().screen, 'err-seal');
  });

  it('a crashed proof builder shows a plain error and sends nothing', async () => {
    const prover = fakeProver({ crash: true });
    const { engine, view, stored } = makeEngine({ spawnProver: prover });
    await engine.init();
    await engine.aadhaarReadFile(qrFile());
    await engine.aadhaarBuild();
    assert.equal(view().screen, 'err-general');
    assert.match(view().error?.detail ?? '', /memory|stopped/);
    assert.equal(stored().card ?? null, null);
  });

  it('the same Aadhaar can make at most 3 cards (nullifier)', async () => {
    const qr = makeTestAadhaarQr();
    const f = path.join(tmp, 'same.txt');
    writeFileSync(f, qr);
    for (let i = 0; i < 3; i++) {
      const { engine, view } = makeEngine();
      await engine.init();
      await engine.aadhaarReadFile(f);
      await engine.aadhaarBuild();
      assert.equal(view().screen, 'card-saved', `card ${i + 1}`);
    }
    const { engine, view } = makeEngine();
    await engine.init();
    await engine.aadhaarReadFile(f);
    await engine.aadhaarBuild();
    assert.equal(view().screen, 'err-general');
    assert.match(view().error?.title ?? '', /too many age cards/);
  });

  it('leaving the screen drops the QR from memory', async () => {
    const { engine, view } = makeEngine();
    await engine.init();
    await engine.aadhaarReadFile(qrFile());
    assert.ok((engine as any).pendingQr);
    engine.go('home');
    assert.equal((engine as any).pendingQr, null);
    assert.equal(view().aadhaar, null);
  });

  it('hides Aadhaar when the server is not set up for it, and says why if tried', async () => {
    const plain = await startMockServer({ devMode: true });
    try {
      let data: any = { serverUrl: plain.url, settings: { firstRunDone: true } };
      const engine = new V18Engine({
        debug: true,
        store: { load: () => data, save: (j) => (data = JSON.parse(j)) },
        hello: new HelloKeyProvider(new FakeHelloAddon()),
        testKeys: null,
        makeQr: async () => '',
        onChange: () => undefined,
        extraServerOrigins: [plain.origin],
        assetsDir,
        artifacts: new ArtifactStore(mkdtempSync(path.join(tmp, 'c-')), undefined, pins),
        spawnProver: fakeProver(),
      });
      await engine.init();
      assert.equal(engine.getView().aadhaarReady, false);
      await engine.aadhaarReadFile(qrFile());
      await engine.aadhaarBuild();
      assert.equal(engine.getView().screen, 'err-general');
      assert.match(engine.getView().error?.title ?? '', /can't make Aadhaar cards/);
    } finally {
      await plain.close();
    }
  });

  it('start with Windows is off by default and can be turned on and off', async () => {
    let on = false;
    const { engine, view } = makeEngine({ loginItem: { get: () => on, set: (v) => void (on = v) } });
    await engine.init();
    assert.equal(view().startWithWindows, false);
    await engine.setSettings({ startWithWindows: true });
    assert.equal(on, true);
    assert.equal(view().startWithWindows, true);
    await engine.setSettings({ startWithWindows: false });
    assert.equal(view().startWithWindows, false);
    const { engine: e2, view: v2 } = makeEngine();
    await e2.init();
    assert.equal(v2().startWithWindows, null, 'hidden when the build cannot change it');
  });
});
