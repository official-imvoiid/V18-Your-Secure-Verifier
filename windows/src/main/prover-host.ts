// Runs the proof builder (dist/prover.cjs) in its own process and relays its progress.
// The Electron app uses a utility process (see main.ts); tests use a Node child process.
// Main process only. The QR text goes to the child over the local IPC pipe and nowhere else.

import { fork } from 'node:child_process';
import type { AnonAadhaarProofObject, ProveJob, ProverErrorCode, ProverMessage, ProveStage } from '../prover/protocol.js';

export interface ProverChannel {
  send(job: ProveJob): void;
  onMessage(cb: (msg: unknown) => void): void;
  onExit(cb: (code: number | null) => void): void;
  kill(): void;
}
export type SpawnProver = () => ProverChannel;

export class ProverError extends Error {
  constructor(public readonly code: ProverErrorCode, message: string) {
    super(message);
    this.name = 'ProverError';
  }
}

export interface ProveResult {
  proof: AnonAadhaarProofObject;
  ms: { inputs: number; witness: number; prove: number; selfcheck: number; total: number };
}

/** A proof builder as a normal Node child process (tests, and any non-Electron use). */
export function nodeProverSpawner(scriptPath: string): SpawnProver {
  return () => {
    const child = fork(scriptPath, [], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'], execArgv: ['--max-old-space-size=6144'] });
    return {
      send: (job) => void child.send(job),
      onMessage: (cb) => void child.on('message', cb),
      onExit: (cb) => void child.on('exit', (code) => cb(code)),
      kill: () => void child.kill(),
    };
  };
}

function isMsg(v: unknown): v is ProverMessage {
  return !!v && typeof v === 'object' && typeof (v as { type?: unknown }).type === 'string';
}

export function runProver(
  spawn: SpawnProver,
  job: ProveJob,
  opts: { onProgress?: (stage: ProveStage, pct: number, label?: string) => void; signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<ProveResult> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    let ch: ProverChannel;
    try {
      ch = spawn();
    } catch {
      return reject(new ProverError('CRASHED', "V18's proof builder couldn't start."));
    }
    let done = false;
    const finish = (fn: () => void) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      try {
        ch.kill();
      } catch {
        /* already gone */
      }
      fn();
    };
    const onAbort = () => finish(() => reject(new ProverError('CANCELLED', 'Cancelled.')));
    const timer = setTimeout(
      () => finish(() => reject(new ProverError('TIMEOUT', 'Building the proof took too long on this PC.'))),
      opts.timeoutMs ?? 15 * 60 * 1000,
    );
    if (opts.signal?.aborted) return onAbort();
    opts.signal?.addEventListener('abort', onAbort);
    ch.onMessage((m) => {
      if (!isMsg(m)) return;
      if (m.type === 'progress') opts.onProgress?.(m.stage, m.pct, m.label);
      else if (m.type === 'done') finish(() => resolve({ proof: m.proof, ms: { ...m.ms, total: Date.now() - started } }));
      else if (m.type === 'error') finish(() => reject(new ProverError(m.code, m.message)));
    });
    ch.onExit((code) =>
      finish(() =>
        reject(
          new ProverError(
            'CRASHED',
            code === 134 || code === 3221225477 || code === -1073741571
              ? 'The proof builder stopped (this PC may not have enough free memory: close other big apps and try again).'
              : 'The proof builder stopped unexpectedly.',
          ),
        ),
      ),
    );
    ch.send(job);
  });
}
