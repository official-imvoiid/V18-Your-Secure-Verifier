// Aadhaar Secure QR reading and seal check on this PC.
// TEST QRs only: made by test/helpers/test-aadhaar.ts with the Anon Aadhaar project's published TEST key.
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';
import QRCode from 'qrcode';
import { isOver18, MAX_SIGNED_BYTES, parseSecureQr, readAadhaarFile, readAadhaarQrText, trustedSealKeys } from '../src/main/aadhaar.js';
import { aadhaarSignal } from '../src/shared/aadhaar-signal.js';
import { dobForAge, makeTestAadhaarQr } from './helpers/test-aadhaar.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const assetsDir = path.join(here, '..', 'assets');
const tmp = mkdtempSync(path.join(os.tmpdir(), 'v18-aadhaar-'));
const testKeys = trustedSealKeys(assetsDir, true);
const prodKeys = trustedSealKeys(assetsDir, false);

function repack(signed: Uint8Array, signature: Uint8Array): string {
  return BigInt('0x' + deflateSync(Buffer.concat([signed, signature])).toString('hex')).toString(10);
}

function selfSignedQr(fields: string[], extra = 0) {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const signed = Buffer.concat([Buffer.from(fields.join('\xff') + '\xff', 'latin1'), Buffer.alloc(extra, 1)]);
  return repack(signed, sign('sha256', signed, privateKey));
}

describe('Aadhaar Secure QR (read on this PC)', () => {
  it('bundles the real UIDAI key and, for TEST MODE only, the Anon Aadhaar TEST key', () => {
    assert.equal(prodKeys.length, 1);
    assert.equal(prodKeys[0].test, false);
    assert.match(prodKeys[0].certPem, /BEGIN CERTIFICATE/);
    assert.equal(testKeys.length, 2);
    assert.equal(testKeys[1].test, true);
  });

  it('accepts a TEST QR (Anon Aadhaar TEST seal) in TEST MODE and hands its text to the engine only', () => {
    const qr = makeTestAadhaarQr();
    const r = readAadhaarQrText(qr, { keys: testKeys });
    assert.equal(r.view.stage, 'read');
    assert.equal(r.view.testQr, true);
    assert.deepEqual(r.view.checks?.map((c) => c.ok), [true, true, true]);
    assert.match(r.view.checks![1].label, /TEST seal/);
    assert.ok(r.accepted);
    assert.equal(r.accepted.test, true);
    assert.equal(r.accepted.qrText, qr);
    assert.match(r.accepted.certPem, /BEGIN CERTIFICATE/);
  });

  it('refuses the TEST seal when the server is not in TEST MODE', () => {
    const r = readAadhaarQrText(makeTestAadhaarQr(), { keys: prodKeys });
    assert.equal(r.view.stage, 'error');
    assert.equal(r.view.checks![1].ok, false);
    assert.equal(r.accepted, null);
  });

  it('never puts the name, birth date or QR in what the window sees', () => {
    const r = readAadhaarQrText(makeTestAadhaarQr(), { keys: testKeys });
    const shown = JSON.stringify(r.view);
    for (const secret of ['Sumit', 'Kumar', '1984', '110051', 'Delhi']) assert.ok(!shown.includes(secret), secret);
  });

  it('finds the seal broken when one byte of the data changes', () => {
    const qr = parseSecureQr(makeTestAadhaarQr());
    const changed = Buffer.from(qr.signedData);
    const i = changed.indexOf(Buffer.from('1984'));
    changed[i + 3] = '0'.charCodeAt(0);
    const r = readAadhaarQrText(repack(changed, qr.signature), { keys: testKeys });
    assert.equal(r.view.stage, 'error');
    assert.equal(r.view.checks![1].ok, false);
    assert.equal(r.accepted, null);
  });

  it('refuses a QR signed by an unknown key', () => {
    const r = readAadhaarQrText(selfSignedQr(['V2', '3', '1234', 'TEST PERSON', '01-01-1990', 'F']), { keys: testKeys });
    assert.equal(r.view.checks![1].ok, false);
    assert.equal(r.accepted, null);
  });

  it('spots someone under 18 (and keeps nothing)', () => {
    const r = readAadhaarQrText(makeTestAadhaarQr({ dob: dobForAge(15) }), { keys: testKeys });
    assert.equal(r.view.stage, 'error');
    assert.equal(r.view.message, 'under18');
    assert.equal(r.accepted, null);
    const now = new Date('2026-11-10T12:00:00Z');
    assert.equal(isOver18({ d: 10, m: 11, y: 2008 }, now), true);
    assert.equal(isOver18({ d: 11, m: 11, y: 2008 }, now), false);
  });

  it('refuses old (pre-V2) QRs with a plain explanation', () => {
    assert.throws(() => readAadhaarQrText(selfSignedQr(['3', '1234', 'TEST PERSON', '01-01-1990', 'F']), { keys: testKeys }), /older kind of Aadhaar QR/);
  });

  it('refuses QRs too long for the circuit', () => {
    const qr = parseSecureQr(makeTestAadhaarQr());
    assert.ok(qr.signedData.length <= MAX_SIGNED_BYTES);
  });

  it('refuses things that are not a Secure QR', () => {
    assert.throws(() => parseSecureQr('hello'), /isn't an Aadhaar Secure QR/);
    assert.throws(() => parseSecureQr('1'.repeat(300)), /isn't an Aadhaar Secure QR/);
  });

  it('reads the QR from a PNG picture and from a .txt file', async () => {
    const text = makeTestAadhaarQr();
    const png = path.join(tmp, 'qr.png');
    await QRCode.toFile(png, [{ data: text, mode: 'numeric' }], { errorCorrectionLevel: 'L', margin: 2, scale: 3 });
    const v1 = await readAadhaarFile(png, { testMode: true, assetsDir });
    assert.equal(v1.view.fileName, 'qr.png');
    assert.equal(v1.view.stage, 'read', JSON.stringify(v1.view));
    assert.equal(v1.accepted?.qrText, text);
    const txt = path.join(tmp, 'qr.txt');
    writeFileSync(txt, text + '\n');
    const v2 = await readAadhaarFile(txt, { testMode: true, assetsDir });
    assert.equal(v2.view.stage, 'read');
  });

  it('explains which files work (PDF: take a screenshot of the QR)', async () => {
    const pdf = path.join(tmp, 'e-aadhaar.pdf');
    writeFileSync(pdf, '%PDF-1.4');
    const v = await readAadhaarFile(pdf, { testMode: false, assetsDir });
    assert.equal(v.view.stage, 'error');
    assert.match(v.view.message ?? '', /screenshot/);
    assert.equal(v.accepted, null);
  });

  it('makes the signal exactly as PROTOCOL 4b item 1 says', () => {
    // Expected values made with a separate tool (sha256sum) over "challenge|thumbprint".
    assert.equal(aadhaarSignal('abc', 'def'), '0x0def6826e591afbb7b4431daaa6f2a78c1e5af533cb94b6db1635efbf255cb16');
    assert.equal(
      aadhaarSignal('0'.repeat(64), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'),
      '0xbe795b5ab7aa2fcabddd3689a1e71bf18f4428710335da04af1c6f6a33701dce',
    );
  });
});
