// A stand-in for the proof builder process, for unit tests only. It does NOT make a real
// zero-knowledge proof: it sends the same messages as dist/prover.cjs, with a proof object whose
// public fields come from the job (signal, seed), so the engine's wiring can be tested quickly.
// The real proof builder is tested in test/e2e/aadhaar.e2e.ts against the real server.

import { createHash } from 'node:crypto';
import type { ProverChannel, SpawnProver } from '../../src/main/prover-host.js';
import type { ProveJob, ProverMessage } from '../../src/prover/protocol.js';

export interface FakeProverOptions {
  /** Answer with this error instead of a proof. */
  fail?: ProverMessage & { type: 'error' };
  /** ageAbove18 in the fake proof (default '1'). */
  ageAbove18?: string;
  /** Wait this long before answering (ms), so tests can cancel. */
  delayMs?: number;
  /** Simulate a crash (the process exits without answering). */
  crash?: boolean;
}

export function fakeProver(opts: FakeProverOptions = {}): SpawnProver & { jobs: ProveJob[]; killed: number } {
  const jobs: ProveJob[] = [];
  const spawn = (() => {
    let onMsg: (m: unknown) => void = () => undefined;
    let onExit: (c: number | null) => void = () => undefined;
    let dead = false;
    const ch: ProverChannel = {
      send(job) {
        jobs.push(job);
        const emit = (m: ProverMessage) => setTimeout(() => !dead && onMsg(m), 1);
        emit({ type: 'progress', stage: 'inputs', pct: 0 });
        emit({ type: 'progress', stage: 'witness', pct: 0 });
        emit({ type: 'progress', stage: 'prove', pct: 40, label: 'Combining points (1 of 5)' });
        setTimeout(() => {
          if (dead) return;
          if (opts.crash) return onExit(134);
          if (opts.fail) return onMsg(opts.fail);
          // The fake nullifier depends on the QR, like the real one depends on its photo bytes.
          const nullifier = BigInt('0x' + createHash('sha256').update(job.qrText).digest('hex').slice(0, 30)).toString();
          onMsg({
            type: 'done',
            ms: { inputs: 1, witness: 1, prove: 1, selfcheck: 1 },
            proof: {
              type: 'anon-aadhaar',
              id: 'fake',
              claim: { pubKey: [], signalHash: job.signal, ageAbove18: true, gender: null, pincode: null, state: null },
              proof: {
                groth16Proof: { pi_a: [], pi_b: [], pi_c: [], protocol: 'groth16', curve: 'bn128' },
                pubkeyHash: '1',
                timestamp: '1',
                nullifierSeed: job.nullifierSeed,
                nullifier,
                // The mock server checks the binding; the real server checks hash(signal) instead.
                signalHash: job.signal,
                ageAbove18: opts.ageAbove18 ?? '1',
                gender: '0',
                pincode: '0',
                state: '0',
              },
            },
          });
        }, opts.delayMs ?? 5);
      },
      onMessage: (cb) => void (onMsg = cb),
      onExit: (cb) => void (onExit = cb),
      kill() {
        dead = true;
        spawn.killed++;
      },
    };
    return ch;
  }) as SpawnProver & { jobs: ProveJob[]; killed: number };
  spawn.jobs = jobs;
  spawn.killed = 0;
  return spawn;
}
