// V18 proof builder: makes the Anon Aadhaar zero-knowledge proof (Groth16) on this PC.
//
// Runs in its own process (never in a window): an Electron utility process in the app, or a
// normal Node child process in tests. It gets one job, builds one proof, sends it back, and is
// then stopped by the main process. It has no network access of its own and writes nothing to disk.
//
// - Circuit inputs: `generateArgs` from @anon-aadhaar/core (the official input builder), asked to
//   reveal ONLY "age above 18", with V18's signal and the server's nullifier seed (PROTOCOL 4b).
// - Proof: snarkjs `wtns.calculate` + `groth16.prove`, the same two steps as Anon Aadhaar's own
//   prover (`groth16.fullProve`), split so we can report real progress.
// - Self-check: snarkjs `groth16.verify` with the pinned vkey.json before anything is sent.
//
// Privacy: the QR text (name, birth date, photo...) is only in this process's memory. Nothing is logged.

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isMainThread } from 'node:worker_threads';
import { generateArgs } from '@anon-aadhaar/core/dist/index.js';
import * as snarkjs from 'snarkjs';
import type { AnonAadhaarProofObject, ProveJob, ProverMessage, ProveStage } from './protocol.js';

interface Port {
  postMessage(msg: unknown): void;
  on(ev: 'message', cb: (e: { data: unknown }) => void): void;
}
const parentPort = (process as unknown as { parentPort?: Port }).parentPort;

function send(msg: ProverMessage): void {
  if (parentPort) parentPort.postMessage(msg);
  else process.send?.(msg);
}

function onJob(cb: (job: unknown) => void): void {
  if (parentPort) parentPort.on('message', (e) => cb(e.data));
  else process.on('message', cb);
}

// snarkjs's own log lines while proving, in the order they appear, with how far along each one is.
// Measured on a real proof (see docs/windows/WALKTHROUGH.md); the bar only ever moves forward.
const PROVE_MARKS: [RegExp, number, string][] = [
  // Measured on this PC (2026-11-23): 19.5 s for the Groth16 step, stage start times in %.
  [/^Reading Wtns/, 2, 'Reading the circuit values'],
  [/^Reading Coeffs/, 3, 'Reading the circuit values'],
  [/^Building ABC/, 3, 'Working through the circuit'],
  [/^IFFT_A/, 32, 'Working through the circuit'],
  [/^IFFT_B/, 39, 'Working through the circuit'],
  [/^IFFT_C/, 46, 'Working through the circuit'],
  [/^Join ABC/, 52, 'Working through the circuit'],
  [/^Reading A Points/, 53, 'Combining points (1 of 5)'],
  [/^Reading B1 Points/, 59, 'Combining points (2 of 5)'],
  [/^Reading B2 Points/, 64, 'Combining points (3 of 5)'],
  [/^Reading C Points/, 73, 'Combining points (4 of 5)'],
  [/^Reading H Points/, 79, 'Combining points (5 of 5)'],
];

function progress(stage: ProveStage, pct: number, label?: string): void {
  send({ type: 'progress', stage, pct: Math.max(0, Math.min(100, Math.round(pct))), label });
}

function isJob(v: unknown): v is ProveJob {
  const j = v as Record<string, unknown>;
  return (
    !!j &&
    j.type === 'prove' &&
    ['qrText', 'certPem', 'nullifierSeed', 'signal', 'wasmPath', 'zkeyPath', 'vkeyPath'].every((k) => typeof j[k] === 'string')
  );
}

async function prove(job: ProveJob): Promise<void> {
  const t0 = Date.now();
  progress('inputs', 0, 'Preparing the circuit inputs');
  let args: Awaited<ReturnType<typeof generateArgs>>;
  try {
    args = await generateArgs({
      qrData: job.qrText,
      certificateFile: job.certPem,
      nullifierSeed: BigInt(job.nullifierSeed),
      fieldsToRevealArray: ['revealAgeAbove18'],
      signal: job.signal,
    });
  } catch {
    return send({ type: 'error', code: 'BAD_QR', message: "This QR can't be turned into a proof." });
  }
  const input = {
    qrDataPadded: args.qrDataPadded.value!,
    qrDataPaddedLength: args.qrDataPaddedLength.value!,
    delimiterIndices: args.delimiterIndices.value!,
    signature: args.signature.value!,
    pubKey: args.pubKey.value!,
    nullifierSeed: args.nullifierSeed.value!,
    signalHash: args.signalHash.value!,
    revealAgeAbove18: args.revealAgeAbove18.value!,
    revealGender: args.revealGender.value!,
    revealPinCode: args.revealPinCode.value!,
    revealState: args.revealState.value!,
  };
  // Only "age above 18" may be revealed (PROTOCOL 3.5).
  if (input.revealAgeAbove18 !== '1' || input.revealGender !== '0' || input.revealPinCode !== '0' || input.revealState !== '0') {
    return send({ type: 'error', code: 'PROVE_FAILED', message: 'Internal check failed: the proof would reveal more than "18+".' });
  }
  const t1 = Date.now();

  progress('witness', 0, 'Running the circuit on your QR');
  const wtns = { type: 'mem' } as unknown as string;
  try {
    await snarkjs.wtns.calculate(input as never, job.wasmPath, wtns);
  } catch {
    // The circuit refuses QRs whose seal or format doesn't match (for example a changed QR).
    return send({ type: 'error', code: 'BAD_QR', message: "The circuit didn't accept this QR (its seal or format doesn't match)." });
  }
  const t2 = Date.now();

  let best = 0;
  progress('prove', 0, 'Starting the proof');
  const logger = {
    debug(msg: string) {
      for (const [re, pct, label] of PROVE_MARKS) {
        if (re.test(msg) && pct > best) {
          best = pct;
          progress('prove', pct, label);
        }
      }
    },
    info() {},
    warn() {},
    error() {},
  };
  let result: { proof: snarkjs.Groth16Proof; publicSignals: snarkjs.PublicSignals };
  try {
    result = await snarkjs.groth16.prove(job.zkeyPath, wtns, logger as never);
  } catch (err) {
    const oom = /memory|allocation|heap/i.test(String(err instanceof Error ? err.message : err));
    return send({ type: 'error', code: oom ? 'OUT_OF_MEMORY' : 'PROVE_FAILED', message: oom ? 'This PC ran out of memory while building the proof.' : 'Building the proof failed.' });
  }
  progress('prove', 100, 'Proof built');
  const t3 = Date.now();

  progress('selfcheck', 0, 'Checking the proof on this PC');
  const ps = result.publicSignals.map(String);
  // Public signals of the Anon Aadhaar v2 circuit: [pubkeyHash, nullifier, timestamp,
  // ageAbove18, gender, pincode, state, nullifierSeed, signalHash].
  const proof: AnonAadhaarProofObject['proof'] = {
    groth16Proof: result.proof as unknown as AnonAadhaarProofObject['proof']['groth16Proof'],
    pubkeyHash: ps[0],
    timestamp: ps[2],
    nullifierSeed: input.nullifierSeed,
    nullifier: ps[1],
    signalHash: input.signalHash,
    ageAbove18: ps[3],
    gender: ps[4],
    pincode: ps[5],
    state: ps[6],
  };
  let ok = false;
  try {
    const vkey = JSON.parse(readFileSync(job.vkeyPath, 'utf8'));
    ok = await snarkjs.groth16.verify(
      vkey,
      [proof.pubkeyHash, proof.nullifier, proof.timestamp, proof.ageAbove18, proof.gender, proof.pincode, proof.state, proof.nullifierSeed, proof.signalHash],
      result.proof,
    );
  } catch {
    ok = false;
  }
  if (!ok || ps[7] !== proof.nullifierSeed || ps[8] !== proof.signalHash) {
    return send({ type: 'error', code: 'SELF_CHECK_FAILED', message: "The proof didn't pass V18's own check on this PC, so it wasn't sent." });
  }
  const t4 = Date.now();
  const out: AnonAadhaarProofObject = {
    type: 'anon-aadhaar',
    id: randomUUID(),
    claim: { pubKey: input.pubKey, signalHash: input.signalHash, ageAbove18: proof.ageAbove18 === '1', gender: null, pincode: null, state: null },
    proof,
  };
  send({ type: 'done', proof: out, ms: { inputs: t1 - t0, witness: t2 - t1, prove: t3 - t2, selfcheck: t4 - t3 } });
}

// snarkjs's helper threads load this same file; only the main thread takes jobs.
let started = false;
if (isMainThread) onJob((msg) => {
  if (started || !isJob(msg)) return;
  started = true;
  prove(msg).catch(() => send({ type: 'error', code: 'PROVE_FAILED', message: 'Building the proof failed.' }));
});
