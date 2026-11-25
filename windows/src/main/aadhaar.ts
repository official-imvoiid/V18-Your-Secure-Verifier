// Aadhaar Secure QR, read on this PC (PROTOCOL.md 3.5 and 4c, method "anon_aadhaar").
//
// This file reads the QR (from a QR picture or a text file holding the QR number), unpacks it,
// and checks UIDAI's RSA seal with Node's crypto, before any proof is built:
//   - the real UIDAI key (the one the Anon Aadhaar v2 circuit accepts) is always trusted;
//   - the Anon Aadhaar project's TEST key is trusted only when the server is in TEST MODE.
// The zero-knowledge proof itself is built by the prover (src/prover/), from the same QR text.
//
// Privacy: the name, birth date and every other field exist only in local variables here and in
// the prover's memory. They are never stored, logged, or sent to a window. The window only learns
// "seal OK" and "over 18: yes/no". The QR text is handed back to the engine (main process memory
// only), which drops it as soon as the proof is made or the user leaves the screen.

import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { gunzipSync, inflateSync } from 'node:zlib';
import jpeg from 'jpeg-js';
import jsQRModule from 'jsqr';
import { PNG } from 'pngjs';
import type { AadhaarView } from './view.js';

type JsQr = (data: Uint8ClampedArray, width: number, height: number) => { data: string } | null;
// jsqr is CommonJS with a default export; this works both bundled and under tsx.
const jsQR: JsQr = ((jsQRModule as unknown as { default?: JsQr }).default ?? jsQRModule) as unknown as JsQr;

const MAX_FILE = 8 * 1024 * 1024;
const SIG_LEN = 256;
/** The Anon Aadhaar v2 circuit reads at most 512 * 3 bytes after SHA-256 padding (9 bytes or more). */
export const MAX_SIGNED_BYTES = 512 * 3 - 9;

/** Bundled seal certificates (in windows/assets/aadhaar/, see docs/windows/WALKTHROUGH.md). */
export const UIDAI_CERT_FILE = 'uidai-offline-publickey-2021.cer';
export const TEST_CERT_FILE = 'anon-aadhaar-test-certificate.pem';

export class AadhaarError extends Error {
  constructor(public readonly code: 'NOT_A_QR' | 'NOT_SECURE_QR' | 'OLD_QR' | 'TOO_LONG' | 'UNSUPPORTED_FILE' | 'TOO_BIG', message: string) {
    super(message);
  }
}

/** Decimal QR number -> big-endian bytes (the Secure QR format). */
function decimalToBytes(text: string): Uint8Array {
  let hex = BigInt(text).toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

export interface SecureQr {
  signedData: Uint8Array;
  signature: Uint8Array;
  version: string;
  dob: { y: number; m: number; d: number } | null;
}

export function parseSecureQr(qrText: string): SecureQr {
  const t = qrText.trim();
  if (!/^\d{200,10000}$/.test(t)) throw new AadhaarError('NOT_SECURE_QR', "This QR isn't an Aadhaar Secure QR.");
  const packed = decimalToBytes(t);
  let data: Buffer;
  try {
    data = inflateSync(packed);
  } catch {
    try {
      data = gunzipSync(packed);
    } catch {
      throw new AadhaarError('NOT_SECURE_QR', "This QR isn't an Aadhaar Secure QR.");
    }
  }
  if (data.length <= SIG_LEN + 10) throw new AadhaarError('NOT_SECURE_QR', 'The QR is too short.');
  const signedData = new Uint8Array(data.subarray(0, data.length - SIG_LEN));
  const signature = new Uint8Array(data.subarray(data.length - SIG_LEN));
  // Fields are separated by byte 255. Look for the birth date among the first fields.
  const parts: string[] = [];
  let cur: number[] = [];
  for (let i = 0; i < signedData.length && parts.length < 8; i++) {
    if (signedData[i] === 255) {
      parts.push(Buffer.from(cur).toString('latin1'));
      cur = [];
    } else cur.push(signedData[i]);
  }
  let dob: SecureQr['dob'] = null;
  for (const p of parts) {
    let m = /^(\d{2})[-/](\d{2})[-/](\d{4})$/.exec(p);
    if (m) {
      dob = { d: +m[1], m: +m[2], y: +m[3] };
      break;
    }
    m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(p);
    if (m) {
      dob = { y: +m[1], m: +m[2], d: +m[3] };
      break;
    }
  }
  return { signedData, signature, version: parts[0] ?? '', dob };
}

export function isOver18(dob: { y: number; m: number; d: number }, now = new Date()): boolean {
  const y = now.getFullYear() - dob.y - (now.getMonth() + 1 < dob.m || (now.getMonth() + 1 === dob.m && now.getDate() < dob.d) ? 1 : 0);
  return y >= 18;
}

export function sealIsValid(qr: SecureQr, keys: KeyObject[]): boolean {
  return keys.some((k) => {
    try {
      return verify('sha256', qr.signedData, k, qr.signature);
    } catch {
      return false;
    }
  });
}

function decodeQrImage(file: string, bytes: Buffer): string {
  const ext = path.extname(file).toLowerCase();
  let rgba: { data: Uint8Array | Buffer; width: number; height: number };
  if (ext === '.png') {
    const png = PNG.sync.read(bytes);
    rgba = { data: png.data, width: png.width, height: png.height };
  } else {
    rgba = jpeg.decode(bytes, { useTArray: true, maxMemoryUsageInMB: 256 });
  }
  const code = jsQR(new Uint8ClampedArray(rgba.data.buffer, rgba.data.byteOffset, rgba.data.byteLength), rgba.width, rgba.height);
  if (!code) throw new AadhaarError('NOT_A_QR', "V18 couldn't find a QR code in this picture. Try a sharper picture, with the whole QR in it.");
  return code.data;
}

/** One seal key V18 trusts, with the certificate the prover needs. */
export interface SealKey {
  key: KeyObject;
  certPem: string;
  test: boolean;
}

function certToPem(bytes: Buffer): string {
  const text = bytes.toString('latin1');
  if (text.includes('-----BEGIN CERTIFICATE-----')) return text;
  // A DER .cer file: wrap it as PEM (the Anon Aadhaar input builder reads PEM).
  const b64 = bytes.toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

/** The seal keys V18 trusts. The TEST key only when the server is in TEST MODE. */
export function trustedSealKeys(assetsDir: string, testMode: boolean): SealKey[] {
  const out: SealKey[] = [];
  const load = (file: string, test: boolean) => {
    const certPem = certToPem(readFileSync(path.join(assetsDir, 'aadhaar', file)));
    out.push({ key: createPublicKey(certPem), certPem, test });
  };
  load(UIDAI_CERT_FILE, false);
  if (testMode) load(TEST_CERT_FILE, true);
  return out;
}

/** What the engine keeps (in memory only) after a QR passes, so the prover can use it. */
export interface AcceptedQr {
  qrText: string;
  certPem: string;
  test: boolean;
}

export interface QrReadResult {
  view: AadhaarView;
  accepted: AcceptedQr | null;
}

export function readAadhaarQrText(text: string, opts: { keys: SealKey[]; now?: Date }): QrReadResult {
  const qr = parseSecureQr(text);
  if (qr.version !== 'V2') {
    throw new AadhaarError(
      'OLD_QR',
      "This is an older kind of Aadhaar QR, which V18 can't use. Download a new e-Aadhaar from UIDAI (myaadhaar.uidai.gov.in) and use the QR from it.",
    );
  }
  const match = opts.keys.find((k) => sealIsValid(qr, [k.key])) ?? null;
  const seal = match !== null;
  const adult = qr.dob ? isOver18(qr.dob, opts.now) : false;
  const fits = qr.signedData.length <= MAX_SIGNED_BYTES;
  const checks = [
    { label: 'QR read on this PC', ok: true },
    {
      label: match
        ? match.test
          ? 'The seal is real, and nothing was changed (TEST seal, TEST MODE only)'
          : "The seal is real (UIDAI's key), and nothing was changed"
        : "The seal didn't check out",
      ok: seal,
    },
    { label: adult ? '"Over 18" can be proven from it' : qr.dob ? 'This ID is for someone under 18' : 'No birth date found in the QR', ok: adult },
  ];
  if (seal && adult && !fits) checks.push({ label: 'This QR holds more data than the proof can read', ok: false });
  const good = seal && adult && fits;
  const view: AadhaarView = {
    stage: good ? 'read' : 'error',
    checks,
    testQr: match?.test ?? false,
    message: good ? undefined : !adult && qr.dob && seal ? 'under18' : !fits && seal && adult ? 'too-long' : 'seal',
  };
  return { view, accepted: good && match ? { qrText: text.trim(), certPem: match.certPem, test: match.test } : null };
}

export async function readAadhaarFile(file: string, opts: { testMode: boolean; assetsDir: string; now?: Date }): Promise<QrReadResult> {
  const fileName = path.basename(file);
  try {
    if (statSync(file).size > MAX_FILE) throw new AadhaarError('TOO_BIG', 'This file is too big. Choose a picture of the QR (under 8 MB).');
    const ext = path.extname(file).toLowerCase();
    const bytes = readFileSync(file);
    let text: string;
    if (ext === '.txt') text = bytes.toString('utf8');
    else if (ext === '.png' || ext === '.jpg' || ext === '.jpeg') text = decodeQrImage(file, bytes);
    else throw new AadhaarError('UNSUPPORTED_FILE', 'Choose a picture of the QR (PNG or JPG), or a .txt file holding the QR number. For an e-Aadhaar PDF, take a screenshot of its QR.');
    const r = readAadhaarQrText(text, { keys: trustedSealKeys(opts.assetsDir, opts.testMode), now: opts.now });
    return { view: { ...r.view, fileName }, accepted: r.accepted };
  } catch (err) {
    return { view: { stage: 'error', fileName, message: err instanceof AadhaarError ? err.message : "V18 couldn't read this file.", checks: [] }, accepted: null };
  }
}
