// Anon Aadhaar circuit files: manifest, pins, download, resume, SHA-256 checks, cache.
// Small made-up files stand in for the real ones here; the real 620 MB set is used in the e2e test.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { ArtifactError, ArtifactStore, checkPins, parseManifest } from '../src/main/artifacts.js';
import { ARTIFACT_PINS } from '../src/shared/artifact-pins.js';
import { startMockServer, type MockServer } from './helpers/mock-server.js';

const files = {
  'aadhaar-verifier.wasm': randomBytes(300_000),
  'circuit_final.zkey': randomBytes(2_000_000),
  'vkey.json': Buffer.from('{"protocol":"groth16","curve":"bn128"}'),
  'circuit_final_0.gz': randomBytes(1000), // optional chunk: the app ignores it
};
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const pins = {
  wasm: { name: 'aadhaar-verifier.wasm', sha256: sha(files['aadhaar-verifier.wasm']), bytes: files['aadhaar-verifier.wasm'].length },
  zkey: { name: 'circuit_final.zkey', sha256: sha(files['circuit_final.zkey']), bytes: files['circuit_final.zkey'].length },
  vkey: { name: 'vkey.json', sha256: sha(files['vkey.json']), bytes: files['vkey.json'].length },
};

describe('proof files (PROTOCOL 4c.1)', () => {
  let mock: MockServer;
  before(async () => {
    mock = await startMockServer({ artifacts: files });
  });
  after(async () => {
    await mock.close();
  });
  const tmp = () => mkdtempSync(path.join(os.tmpdir(), 'v18-artifacts-'));

  it('pins the official Anon Aadhaar v2 files', () => {
    assert.equal(ARTIFACT_PINS.wasm.name, 'aadhaar-verifier.wasm');
    assert.equal(ARTIFACT_PINS.zkey.name, 'circuit_final.zkey');
    assert.equal(ARTIFACT_PINS.vkey.name, 'vkey.json');
    for (const p of Object.values(ARTIFACT_PINS)) assert.match(p.sha256, /^[0-9a-f]{64}$/, p.name);
  });

  it('reads the manifest (array or {artifacts}), ignores extra files, and needs all three', () => {
    const list = [
      { name: 'aadhaar-verifier.wasm', sha256: 'a'.repeat(64), bytes: 10 },
      { name: 'circuit_final.zkey', sha256: 'b'.repeat(64), bytes: 10 },
      { name: 'vkey.json', sha256: 'c'.repeat(64), bytes: 10 },
      { name: 'circuit_final_0.gz', sha256: 'd'.repeat(64), bytes: 10 },
      { name: '../evil.wasm', sha256: 'e'.repeat(64), bytes: 10 },
    ];
    assert.deepEqual(parseManifest(list).map((e) => e.role).sort(), ['vkey', 'wasm', 'zkey']);
    assert.equal(parseManifest({ artifacts: list }).length, 3);
    assert.throws(() => parseManifest(list.slice(1)), (e: unknown) => e instanceof ArtifactError && e.code === 'MANIFEST_BAD');
    assert.throws(() => parseManifest({ nope: 1 }), ArtifactError);
  });

  it('refuses files that are not the ones this app was built for', () => {
    const entries = parseManifest([
      { name: 'aadhaar-verifier.wasm', sha256: pins.wasm.sha256, bytes: pins.wasm.bytes },
      { name: 'circuit_final.zkey', sha256: 'f'.repeat(64), bytes: pins.zkey.bytes },
      { name: 'vkey.json', sha256: pins.vkey.sha256, bytes: pins.vkey.bytes },
    ]);
    assert.throws(() => checkPins(entries, pins), (e: unknown) => e instanceof ArtifactError && e.code === 'NOT_PINNED');
  });

  it('downloads, checks and caches; the second time nothing is downloaded', async () => {
    const dir = tmp();
    const store = new ArtifactStore(dir, undefined, pins);
    assert.equal(store.isCached(), false);
    const entries = await store.manifest(mock.url);
    assert.equal(store.missingBytes(entries), 2_300_000 + files['vkey.json'].length);
    const seen: string[] = [];
    const paths = await store.ensure(mock.url, entries, (p) => seen.push(p.phase));
    // Hashed while downloading, so no second pass in this run.
    assert.ok(seen.includes('download') && !seen.includes('check'));
    assert.deepEqual(readFileSync(paths.zkey), files['circuit_final.zkey']);
    assert.equal(existsSync(path.join(dir, 'circuit_final_0.gz')), false);
    assert.equal(store.isCached(), true);
    const before = mock.calls.filter((c) => c.startsWith('GET /artifacts/') && c !== 'GET /artifacts/manifest').length;
    await store.ensure(mock.url, entries);
    const after2 = mock.calls.filter((c) => c.startsWith('GET /artifacts/') && c !== 'GET /artifacts/manifest').length;
    assert.equal(after2, before);
    // A new app run checks the cached files once (SHA-256) before using them.
    const seen2: string[] = [];
    await new ArtifactStore(dir, undefined, pins).ensure(mock.url, entries, (p) => seen2.push(p.phase));
    assert.ok(seen2.includes('check') && !seen2.includes('download'));
  });

  it('carries on where a broken download stopped (HTTP Range), and checks it from the first byte', async () => {
    const dir = tmp();
    const store = new ArtifactStore(dir, undefined, pins);
    const entries = await store.manifest(mock.url);
    mock.breakNextDownloadAt = 1_000_000;
    // The wasm comes first (300 KB, not broken); the zkey breaks at 1 MB.
    await assert.rejects(store.ensure(mock.url, entries), (e: unknown) => e instanceof ArtifactError && e.code === 'DOWNLOAD_FAILED');
    assert.ok(existsSync(path.join(dir, 'circuit_final.zkey.part')));
    const paths = await store.ensure(mock.url, entries);
    assert.deepEqual(readFileSync(paths.zkey), files['circuit_final.zkey']);
  });

  it('finds a damaged cached file, deletes it, and gets it again', async () => {
    const dir = tmp();
    const entries = await new ArtifactStore(dir, undefined, pins).manifest(mock.url);
    await new ArtifactStore(dir, undefined, pins).ensure(mock.url, entries);
    const zkey = path.join(dir, 'circuit_final.zkey');
    const bad = Buffer.from(readFileSync(zkey));
    bad[12345] ^= 0xff;
    writeFileSync(zkey, bad);
    // A new app run re-hashes before use.
    const store = new ArtifactStore(dir, undefined, pins);
    await assert.rejects(store.ensure(mock.url, entries), (e: unknown) => e instanceof ArtifactError && e.code === 'BAD_HASH');
    assert.equal(existsSync(zkey), false);
    const paths = await store.ensure(mock.url, entries);
    assert.deepEqual(readFileSync(paths.zkey), files['circuit_final.zkey']);
  });

  it('never keeps a download whose SHA-256 is wrong', async () => {
    const dir = tmp();
    const lying = { ...pins, vkey: { ...pins.vkey } };
    const store = new ArtifactStore(dir, undefined, lying);
    // The server says one hash (matching the pin), but sends other bytes.
    const entries = (await store.manifest(mock.url)).map((e) => (e.role === 'vkey' ? { ...e, sha256: '0'.repeat(64) } : e));
    await assert.rejects(store.ensure(mock.url, entries), (e: unknown) => e instanceof ArtifactError && e.code === 'BAD_HASH');
    assert.equal(existsSync(path.join(dir, 'vkey.json')), false);
  });

  it('says plainly when the server has no proof files', async () => {
    const plain = await startMockServer();
    try {
      await assert.rejects(new ArtifactStore(tmp(), undefined, pins).manifest(plain.url), (e: unknown) => e instanceof ArtifactError && e.code === 'NO_ARTIFACTS');
    } finally {
      await plain.close();
    }
  });

  it('can delete the cached files', async () => {
    const dir = tmp();
    const store = new ArtifactStore(dir, undefined, pins);
    await store.ensure(mock.url, await store.manifest(mock.url));
    assert.equal(store.isCached(), true);
    store.clear();
    assert.equal(store.isCached(), false);
  });
});
