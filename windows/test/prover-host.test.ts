// The proof builder host: messages, errors, crash, timeout, cancel. Plus the real bundled proof
// builder (dist/prover.cjs) refusing a broken QR (run "npm run build" first; skipped otherwise).
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { nodeProverSpawner, ProverError, runProver } from '../src/main/prover-host.js';
import type { ProveJob } from '../src/prover/protocol.js';
import { fakeProver } from './helpers/fake-prover.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const job: ProveJob = { type: 'prove', qrText: '1', certPem: '', nullifierSeed: '1', signal: '0x00', wasmPath: 'w', zkeyPath: 'z', vkeyPath: 'v' };

describe('proof builder host', () => {
  it('relays progress and returns the proof', async () => {
    const seen: string[] = [];
    const r = await runProver(fakeProver(), job, { onProgress: (s) => seen.push(s) });
    assert.deepEqual(seen, ['inputs', 'witness', 'prove']);
    assert.equal(r.proof.proof.signalHash, '0x00');
    assert.equal(typeof r.ms.total, 'number');
  });

  it('passes on the builder\'s own errors', async () => {
    await assert.rejects(
      runProver(fakeProver({ fail: { type: 'error', code: 'SELF_CHECK_FAILED', message: 'no' } }), job),
      (e: unknown) => e instanceof ProverError && e.code === 'SELF_CHECK_FAILED',
    );
  });

  it('reports a crash (for example out of memory)', async () => {
    await assert.rejects(runProver(fakeProver({ crash: true }), job), (e: unknown) => e instanceof ProverError && e.code === 'CRASHED' && /memory/.test(e.message));
  });

  it('stops after the time limit and kills the process', async () => {
    const p = fakeProver({ delayMs: 5000 });
    await assert.rejects(runProver(p, job, { timeoutMs: 50 }), (e: unknown) => e instanceof ProverError && e.code === 'TIMEOUT');
    assert.equal(p.killed, 1);
  });

  it('can be cancelled', async () => {
    const p = fakeProver({ delayMs: 5000 });
    const ctl = new AbortController();
    setTimeout(() => ctl.abort(), 20);
    await assert.rejects(runProver(p, job, { signal: ctl.signal }), (e: unknown) => e instanceof ProverError && e.code === 'CANCELLED');
    assert.equal(p.killed, 1);
  });

  const bundle = path.join(here, '..', 'dist', 'prover.cjs');
  it('the real bundled proof builder refuses a QR that is not an Aadhaar QR', { skip: existsSync(bundle) ? false : 'run "npm run build" first' }, async () => {
    const cert = readFileSync(path.join(here, '..', 'assets', 'aadhaar', 'anon-aadhaar-test-certificate.pem'), 'utf8');
    await assert.rejects(
      runProver(nodeProverSpawner(bundle), { ...job, qrText: '12345', certPem: cert, nullifierSeed: '180018001800180018' }),
      (e: unknown) => e instanceof ProverError && e.code === 'BAD_QR',
    );
  });
});
