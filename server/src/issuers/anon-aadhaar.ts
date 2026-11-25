import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ARTIFACTS_DIR, hashFile, loadManifest } from '../artifacts/manifest.js';
import { serverRoot } from '../config.js';
import { ApiError } from '../errors.js';
import { isPlainObject, sha256Hex } from '../util.js';
import { CARD_VALIDITY_DAYS, DAY_MS, IssuerResult } from './types.js';

/**
 * `anon_aadhaar` issuer (protocol 3.5, 4b items 1 and 2, 4c.1).
 *
 * The app proves "age above 18" from an Aadhaar Secure QR with the official
 * Anon Aadhaar v2 circuit. The server checks:
 *   1. the QR was signed by a bundled UIDAI key (assets/uidai/production), or
 *      by the Anon Aadhaar TEST key in dev mode only;
 *   2. the nullifier seed is the server's V18_AADHAAR_NULLIFIER_SEED;
 *   3. the signal binds this request (4b item 1):
 *      signal = "0x" + hex(SHA-256(UTF-8(challenge + "|" + deviceKeyThumbprint)));
 *   4. the Groth16 proof verifies with the PINNED vkey.json (snarkjs);
 *   5. ONLY "age above 18" is revealed, and it is 1.
 */

export interface AnonAadhaarPublicProof {
  groth16Proof: Record<string, unknown>;
  pubkeyHash: string;
  timestamp: string;
  nullifierSeed: string;
  nullifier: string;
  signalHash: string;
  ageAbove18: string;
  gender: string;
  pincode: string;
  state: string;
}

/** Verifies the Groth16 proof itself. */
export interface AnonAadhaarProofVerifier {
  readonly description: string;
  verify(proof: AnonAadhaarPublicProof): Promise<boolean>;
  close?(): Promise<void>;
}

interface AnonAadhaarLib {
  hash(message: string | bigint | number): string;
  testPublicKeyHash: string;
  productionPublicKeyHash: string;
}

let lib: AnonAadhaarLib | null = null;
/** Loads `@anon-aadhaar/core` on first use (it pulls in snarkjs). */
export function anonAadhaarLib(): AnonAadhaarLib {
  if (!lib) {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    lib = require('@anon-aadhaar/core') as AnonAadhaarLib;
  }
  return lib;
}

interface Snarkjs {
  groth16: { verify(vk: unknown, publicSignals: string[], proof: unknown): Promise<boolean> };
}

/** The public signals in the circuit's order (the same order `@anon-aadhaar/core` verify() uses). */
export function publicSignals(p: AnonAadhaarPublicProof): string[] {
  return [p.pubkeyHash, p.nullifier, p.timestamp, p.ageAbove18, p.gender, p.pincode, p.state, p.nullifierSeed, p.signalHash];
}

/**
 * The real verifier: snarkjs Groth16 with the official v2 `vkey.json`
 * from server/assets/artifacts/, whose SHA-256 must equal the pin in the
 * manifest (PROTOCOL.md 4c.1). It refuses to load a file that does not match.
 */
export class PinnedVkeyVerifier implements AnonAadhaarProofVerifier {
  readonly description: string;

  private constructor(
    private readonly vkey: unknown,
    readonly sha256: string
  ) {
    this.description = `snarkjs groth16, pinned vkey.json sha256 ${sha256.slice(0, 16)}...`;
  }

  /** Returns null (with a reason) when the file is missing or not pinned. */
  static async load(dir = ARTIFACTS_DIR): Promise<{ verifier: PinnedVkeyVerifier | null; reason: string | null }> {
    const file = path.join(dir, 'vkey.json');
    const pin = loadManifest().files.find((f) => f.name === 'vkey.json')?.sha256 ?? null;
    if (!pin) return { verifier: null, reason: 'vkey.json has no SHA-256 pin in assets/artifacts/manifest.json' };
    if (!fs.existsSync(file)) return { verifier: null, reason: 'vkey.json is missing: run npm run fetch-artifacts' };
    const h = await hashFile(file);
    if (h.sha256 !== pin) {
      throw new Error(`assets/artifacts/vkey.json does not match its pinned SHA-256 (got ${h.sha256}). Run npm run fetch-artifacts.`);
    }
    return { verifier: new PinnedVkeyVerifier(JSON.parse(fs.readFileSync(file, 'utf8')), h.sha256), reason: null };
  }

  async verify(proof: AnonAadhaarPublicProof): Promise<boolean> {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const snarkjs = require('snarkjs') as Snarkjs;
    return snarkjs.groth16.verify(this.vkey, publicSignals(proof), proof.groth16Proof);
  }

  /** snarkjs keeps worker threads for the bn128 curve; stop them on shutdown. */
  async close(): Promise<void> {
    await stopSnarkjsCurve();
  }
}

export async function stopSnarkjsCurve(): Promise<void> {
  const g = globalThis as { curve_bn128?: { terminate(): Promise<void> } | null };
  if (g.curve_bn128) {
    const c = g.curve_bn128;
    g.curve_bn128 = null;
    await c.terminate();
  }
}

// ---- UIDAI keys ---------------------------------------------------------------

export const UIDAI_DIR = path.join(serverRoot, 'assets', 'uidai');

export interface UidaiKey {
  file: string;
  pubkeyHash: string;
  test: boolean;
}

/** Poseidon hash of the RSA modulus, exactly as the circuit computes `pubkeyHash` (121-bit words, merged in pairs). */
export async function pubkeyHashOf(certificate: Buffer | string): Promise<string> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { poseidonLarge } = require('@zk-email/helpers/dist/hash') as {
    poseidonLarge(input: bigint, numChunks: number, bitsPerChunk: number): Promise<bigint>;
  };
  const cert = new crypto.X509Certificate(certificate);
  const jwk = cert.publicKey.export({ format: 'jwk' });
  if (jwk.kty !== 'RSA' || !jwk.n) throw new Error('UIDAI certificate is not an RSA key');
  const n = BigInt('0x' + Buffer.from(jwk.n, 'base64url').toString('hex'));
  return (await poseidonLarge(n, 9, 242)).toString();
}

export async function loadUidaiKeys(dir = UIDAI_DIR): Promise<UidaiKey[]> {
  const out: UidaiKey[] = [];
  for (const [sub, test] of [['production', false], ['test', true]] as const) {
    const d = path.join(dir, sub);
    if (!fs.existsSync(d)) continue;
    for (const f of fs.readdirSync(d).filter((x) => /\.(cer|crt|pem)$/i.test(x)).sort()) {
      out.push({ file: `${sub}/${f}`, pubkeyHash: await pubkeyHashOf(fs.readFileSync(path.join(d, f))), test });
    }
  }
  return out;
}

/** The signal the app must put in the proof, and its hash. */
export function anonAadhaarSignal(challenge: string, deviceKeyThumbprint: string): { signal: string; signalHash: string } {
  const signal = '0x' + sha256Hex(`${challenge}|${deviceKeyThumbprint}`);
  return { signal, signalHash: anonAadhaarLib().hash(signal) };
}

const NUM = /^\d{1,80}$/;
const FIELDS = ['pubkeyHash', 'timestamp', 'nullifierSeed', 'nullifier', 'signalHash', 'ageAbove18', 'gender', 'pincode', 'state'] as const;

const invalid = (reason: string, message: string) => new ApiError(400, 'PROOF_INVALID', message, { reason });

/** Accepts an AnonAadhaarCore object, `{proof: ...}`, or a serialized PCD `{pcd: "<json>"}`. */
export function extractPublicProof(input: unknown): AnonAadhaarPublicProof {
  let obj: unknown = input;
  if (isPlainObject(obj) && typeof obj.pcd === 'string') {
    try {
      obj = JSON.parse(obj.pcd);
    } catch {
      throw invalid('malformed', 'proof.pcd is not valid JSON');
    }
  }
  if (!isPlainObject(obj) || !isPlainObject(obj.proof)) {
    throw invalid('malformed', 'proof must be an Anon Aadhaar proof object (with a "proof" member)');
  }
  const p = obj.proof;
  for (const f of FIELDS) {
    const v = p[f];
    if (typeof v !== 'string' || !NUM.test(v)) throw invalid('malformed', `proof.proof.${f} must be a decimal string`);
  }
  const g = p.groth16Proof;
  if (!isPlainObject(g) || !Array.isArray(g.pi_a) || !Array.isArray(g.pi_b) || !Array.isArray(g.pi_c)) {
    throw invalid('malformed', 'proof.proof.groth16Proof must have pi_a, pi_b and pi_c');
  }
  const out: Record<string, unknown> = {
    groth16Proof: { pi_a: g.pi_a, pi_b: g.pi_b, pi_c: g.pi_c, protocol: 'groth16', curve: 'bn128' },
  };
  for (const f of FIELDS) out[f] = p[f];
  return out as unknown as AnonAadhaarPublicProof;
}

export interface AnonAadhaarContext {
  challenge: string;
  deviceKeyThumbprint: string;
  devMode: boolean;
  nullifierSeed: string | null;
  verifier: AnonAadhaarProofVerifier | null;
  uidaiKeys: UidaiKey[];
  nowMs: number;
}

export async function verifyAnonAadhaarProof(input: unknown, ctx: AnonAadhaarContext): Promise<IssuerResult> {
  if (!ctx.verifier || !ctx.nullifierSeed) {
    throw new ApiError(
      503,
      'METHOD_NOT_CONFIGURED',
      'Anon Aadhaar is not set up on this server (needs the pinned vkey.json from npm run fetch-artifacts, and V18_AADHAAR_NULLIFIER_SEED)'
    );
  }
  const p = extractPublicProof(input);

  // 1. Which UIDAI key signed the QR?
  const key = ctx.uidaiKeys.find((k) => k.pubkeyHash === BigInt(p.pubkeyHash).toString());
  if (!key) throw invalid('unknown_issuer_key', 'The proof was not made with a known UIDAI key');
  if (key.test && !ctx.devMode) {
    throw invalid('test_key_rejected', 'Test Aadhaar proofs are only accepted by a dev-mode server');
  }

  // 2. Nullifier seed must be ours, so nullifiers are V18-specific.
  if (BigInt(p.nullifierSeed) !== BigInt(ctx.nullifierSeed)) {
    throw invalid('wrong_nullifier_seed', 'The proof uses the wrong nullifier seed');
  }

  // 3. The signal must bind this challenge and this device key.
  const expected = anonAadhaarSignal(ctx.challenge, ctx.deviceKeyThumbprint);
  if (BigInt(p.signalHash) !== BigInt(expected.signalHash)) {
    throw invalid('signal_mismatch', 'The proof is not bound to this challenge and device key');
  }

  // 4. The zero-knowledge proof itself (with the pinned verification key).
  let ok = false;
  try {
    ok = await ctx.verifier.verify(p);
  } catch {
    ok = false;
  }
  if (!ok) throw invalid('bad_proof', 'The zero-knowledge proof did not verify');

  // 5. Reveal only "age above 18", and it must be 1.
  if (BigInt(p.gender) !== 0n || BigInt(p.pincode) !== 0n || BigInt(p.state) !== 0n) {
    throw invalid('reveals_too_much', 'The proof must reveal only "age above 18" (not gender, PIN code or state)');
  }
  if (BigInt(p.ageAbove18) !== 1n) {
    throw new ApiError(403, 'UNDER_AGE', 'The proof does not show age above 18');
  }

  return {
    rawNullifier: BigInt(p.nullifier).toString(),
    assuranceLevel: key.test ? 'test' : 'substantial',
    minAgeCertified: 18,
    // Aadhaar has no expiry date, so the card gets the method's full validity.
    validUntilMs: ctx.nowMs + CARD_VALIDITY_DAYS.anon_aadhaar * DAY_MS,
  };
}
