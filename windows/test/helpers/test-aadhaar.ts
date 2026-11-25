// Makes TEST Aadhaar Secure QR codes (test only).
//
// It takes the Anon Aadhaar project's published sample QR (UIDAI's sample person, already in the
// V2 format), puts in the current time (and, if asked, another birth date), and signs it again
// with the Anon Aadhaar project's published TEST key. See test/fixtures/anon-aadhaar/README.md.
// The real circuit accepts these, but every proof made from them says "TEST key", so only a
// dev-mode server takes them.

import { randomInt, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync, inflateSync } from 'node:zlib';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'anon-aadhaar');
const SAMPLE = () => readFileSync(path.join(dir, 'anon-aadhaar-sample-qr.txt'), 'utf8').trim();
const TEST_PRIVATE_KEY = () => readFileSync(path.join(dir, 'anon-aadhaar-test-private-key.pem'), 'utf8');

function toBytes(decimal: string): Buffer {
  let hex = BigInt(decimal).toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

/** "YYYYMMDDhhmmssSSS" in Indian Standard Time (UTC+5:30), as UIDAI writes it. */
function istStamp(now: Date): string {
  const t = new Date(now.getTime() + 330 * 60000);
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${t.getUTCFullYear()}${p(t.getUTCMonth() + 1)}${p(t.getUTCDate())}${p(t.getUTCHours())}${p(t.getUTCMinutes())}${p(t.getUTCSeconds())}${p(t.getUTCMilliseconds(), 3)}`;
}

export interface TestQrOptions {
  /** Birth date as "DD-MM-YYYY". Default: the sample's 01-01-1984 (an adult). */
  dob?: string;
  now?: Date;
  /** New random photo bytes, so the QR has its own nullifier. Default true. */
  uniquePhoto?: boolean;
}

/** A fresh TEST Aadhaar Secure QR, as the decimal number a QR scanner reads. */
export function makeTestAadhaarQr(opts: TestQrOptions = {}): string {
  const data = inflateSync(toBytes(SAMPLE()));
  const signed = data.subarray(0, data.length - 256);
  // Field layout (V2): 0 "V2", 1 email/mobile flag, 2 reference ID (last 4 digits + time), 3 name, 4 birth date, ...
  // Only the first five fields are touched. The rest (which holds the photo bytes) is kept as is.
  const cut: number[] = [];
  for (let i = 0; i < signed.length && cut.length < 5; i++) if (signed[i] === 255) cut.push(i);
  const fields = [0, 1, 2, 3, 4].map((k) => signed.subarray(k === 0 ? 0 : cut[k - 1] + 1, cut[k]));
  const rest = signed.subarray(cut[4]);
  const ref = fields[2].toString('latin1');
  fields[2] = Buffer.from(ref.slice(0, 4) + istStamp(opts.now ?? new Date()), 'latin1');
  if (opts.dob) {
    if (!/^\d{2}-\d{2}-\d{4}$/.test(opts.dob)) throw new Error('dob must be DD-MM-YYYY');
    fields[4] = Buffer.from(opts.dob, 'latin1');
  }
  const parts: Buffer[] = [];
  fields.forEach((f, k) => parts.push(f, k < 4 ? Buffer.from([255]) : Buffer.alloc(0)));
  const newSigned = Buffer.concat([...parts, rest]);
  if (opts.uniquePhoto !== false) {
    // The Anon Aadhaar nullifier comes from the photo bytes (after the 18th field). New random
    // "photo" bytes give every TEST QR its own nullifier, the way Anon Aadhaar's own test tool
    // does, so tests never run into the 3-cards-per-ID limit.
    let begin = -1;
    for (let k = 0; k < 18; k++) begin = newSigned.indexOf(255, begin + 1);
    for (let i = begin + 1; i < newSigned.length - 1; i++) newSigned[i] = randomInt(0, 255);
  }
  const signature = sign('sha256', newSigned, TEST_PRIVATE_KEY());
  return BigInt('0x' + deflateSync(Buffer.concat([newSigned, signature])).toString('hex')).toString(10);
}

/** A birth date that makes someone `years` old today. */
export function dobForAge(years: number, now = new Date()): string {
  return `01-01-${now.getFullYear() - years}`;
}
