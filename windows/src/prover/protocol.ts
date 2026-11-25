// Messages between the V18 main process and the proof builder (dist/prover.cjs).
// The proof builder is a separate Node process (an Electron utility process in the app, a normal
// Node child process in tests). One job per process: it builds one proof, then exits.

export interface ProveJob {
  type: 'prove';
  /** The Aadhaar Secure QR number. Personal data: kept only in memory, never logged. */
  qrText: string;
  /** PEM certificate of the key that sealed the QR (UIDAI, or the Anon Aadhaar TEST key). */
  certPem: string;
  /** The server's V18_AADHAAR_NULLIFIER_SEED (decimal). */
  nullifierSeed: string;
  /** "0x" + hex(SHA-256(challenge + "|" + deviceKeyThumbprint)), PROTOCOL 4b item 1. */
  signal: string;
  wasmPath: string;
  zkeyPath: string;
  vkeyPath: string;
}

export type ProveStage = 'inputs' | 'witness' | 'prove' | 'selfcheck';

export type ProverMessage =
  | { type: 'progress'; stage: ProveStage; pct: number; label?: string }
  | { type: 'done'; proof: AnonAadhaarProofObject; ms: { inputs: number; witness: number; prove: number; selfcheck: number } }
  | { type: 'error'; code: ProverErrorCode; message: string };

export type ProverErrorCode = 'BAD_QR' | 'PROVE_FAILED' | 'SELF_CHECK_FAILED' | 'OUT_OF_MEMORY' | 'CRASHED' | 'CANCELLED' | 'TIMEOUT';

/** The Anon Aadhaar proof object, the same shape as `AnonAadhaarCore` from @anon-aadhaar/core. */
export interface AnonAadhaarProofObject {
  type: 'anon-aadhaar';
  id: string;
  claim: {
    pubKey: string[];
    signalHash: string;
    ageAbove18: boolean | null;
    gender: null;
    pincode: null;
    state: null;
  };
  proof: {
    groth16Proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[]; protocol: string; curve: string };
    pubkeyHash: string;
    timestamp: string;
    nullifierSeed: string;
    nullifier: string;
    signalHash: string;
    ageAbove18: string;
    gender: string;
    pincode: string;
    state: string;
  };
}
