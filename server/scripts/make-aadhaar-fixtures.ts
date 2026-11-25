/**
 * npm run make-aadhaar-fixtures   (TEST DATA ONLY, takes a few minutes)
 *
 * Makes REAL Anon Aadhaar proofs with the official v2 circuit files
 * (server/assets/artifacts, checked against their pins) and the Node prover
 * (snarkjs groth16.fullProve via @anon-aadhaar/core), and saves them as test
 * fixtures in server/test-fixtures/anon-aadhaar/proofs.json, because proving
 * takes about 20 to 60 seconds each.
 *
 * Input: UIDAI's public SAMPLE Secure QR (no real person), turned into a V2
 * QR and re-signed with the Anon Aadhaar project's published TEST key, exactly
 * like the official generateTestData.ts script. A proof made this way carries
 * the TEST pubkeyHash, so only a dev-mode server accepts it.
 *
 * Each proof is bound to a fixed TEST challenge and a fixed TEST device key
 * (PROTOCOL.md 4b item 1), which the server test inserts into its database.
 */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { calculateJwkThumbprint } from 'jose';
import { hashFile, loadManifest } from '../src/artifacts/manifest.js';

const ROOT = path.resolve(__dirname, '..');
const FIX = path.join(ROOT, 'test-fixtures', 'anon-aadhaar');
const ART = path.join(ROOT, 'assets', 'artifacts');
const SEED = '180018001800180018';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const aa = require('@anon-aadhaar/core');

function signedQr(opts: { dob?: string; gender?: string }): string {
  const sample = JSON.parse(fs.readFileSync(path.join(FIX, 'uidai-sample-qr.json'), 'utf8')).qrData as string;
  const decoded = aa.decompressByteArray(aa.convertBigIntToByteArray(BigInt(sample)));
  const dataToSign: Uint8Array = aa.createCustomV2TestData({ signedData: decoded.slice(0, decoded.length - 256), dob: opts.dob });
  const signature = crypto.sign('sha256', Buffer.from(dataToSign), fs.readFileSync(path.join(FIX, 'testPrivateKey.pem'), 'utf8'));
  return aa.rawDataToCompressedQR(Buffer.concat([Buffer.from(dataToSign), signature])).toString();
}

async function main(): Promise<void> {
  const manifest = loadManifest();
  for (const name of ['aadhaar-verifier.wasm', 'circuit_final.zkey']) {
    const pin = manifest.files.find((f) => f.name === name)!.sha256;
    const h = await hashFile(path.join(ART, name));
    if (h.sha256 !== pin) throw new Error(`${name} does not match its pin. Run npm run fetch-artifacts.`);
  }
  await aa.init({
    wasmURL: path.join(ART, 'aadhaar-verifier.wasm'),
    zkeyURL: path.join(ART, 'circuit_final.zkey'),
    vkeyURL: path.join(ART, 'vkey.json'),
    artifactsOrigin: aa.ArtifactsOrigin.local,
  });
  const certificate = fs.readFileSync(path.join(ROOT, 'assets', 'uidai', 'test', 'anon-aadhaar-testCertificate.pem'), 'utf8');

  // A fixed TEST device key and TEST challenge for the binding (4b item 1).
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pub = publicKey.export({ format: 'jwk' });
  const devicePublicJwk = { kty: 'EC', crv: 'P-256', x: pub.x!, y: pub.y! };
  const thumbprint = await calculateJwkThumbprint(devicePublicJwk as never, 'sha256');
  const challenge = crypto.randomBytes(32).toString('hex');
  const signal = '0x' + crypto.createHash('sha256').update(`${challenge}|${thumbprint}`).digest('hex');

  const tenYearsAgo = new Date(Date.now() - 10 * 365.25 * 86_400_000);
  const dd = (n: number) => String(n).padStart(2, '0');
  const under18Dob = `${dd(tenYearsAgo.getUTCDate())}-${dd(tenYearsAgo.getUTCMonth() + 1)}-${tenYearsAgo.getUTCFullYear()}`;

  const cases: { id: string; dob?: string; reveal: string[] }[] = [
    { id: 'over18_reveal_age_only', reveal: ['revealAgeAbove18'] },
    { id: 'over18_reveals_gender_too', reveal: ['revealAgeAbove18', 'revealGender'] },
    { id: 'under18_reveal_age_only', dob: under18Dob, reveal: ['revealAgeAbove18'] },
  ];
  const proofs: Record<string, unknown> = {};
  for (const c of cases) {
    const t0 = Date.now();
    const args = await aa.generateArgs({
      qrData: signedQr({ dob: c.dob }),
      certificateFile: certificate,
      nullifierSeed: BigInt(SEED),
      fieldsToRevealArray: c.reveal,
      signal,
    });
    const core = await aa.prove(args);
    const okLib = await aa.verify(core, true);
    const ms = Date.now() - t0;
    process.stderr.write(`${c.id}: proved and checked by @anon-aadhaar/core verify() = ${okLib} in ${(ms / 1000).toFixed(1)} s\n`);
    if (!okLib) throw new Error(`${c.id}: the library refused its own proof`);
    proofs[c.id] = JSON.parse(JSON.stringify({ type: core.type, id: core.id, claim: core.claim, proof: core.proof }));
  }

  const out = {
    about:
      'TEST ONLY. Real Anon Aadhaar v2 proofs (official circuit files, Node prover) from the UIDAI public sample QR re-signed with the Anon Aadhaar TEST key. Made by npm run make-aadhaar-fixtures.',
    madeAt: new Date().toISOString(),
    nullifierSeed: SEED,
    challenge,
    devicePublicJwk,
    devicePrivateJwk: privateKey.export({ format: 'jwk' }),
    thumbprint,
    signal,
    under18Dob,
    proofs,
  };
  fs.writeFileSync(path.join(FIX, 'proofs.json'), JSON.stringify(out, null, 2) + '\n');
  process.stderr.write(`Wrote ${path.join(FIX, 'proofs.json')}\n`);
  const curve = (globalThis as { curve_bn128?: { terminate(): Promise<void> } }).curve_bn128;
  if (curve) await curve.terminate();
  process.exit(0);
}

main().catch((err) => {
  process.stderr.write(`make-aadhaar-fixtures failed: ${(err as Error).stack}\n`);
  process.exit(1);
});
