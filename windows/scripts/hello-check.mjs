// Windows Hello check for V18 ("npm run hello:check").
//
// What it does, step by step (nothing is sent anywhere):
//   1. Asks Windows whether Windows Hello is set up for this account.
//   2. Makes a throwaway Windows Hello key (Windows shows its Hello prompt).
//   3. Signs a test string with it (Windows shows the Hello prompt again), and checks the
//      signature is RS256 (RSASSA-PKCS1-v1_5 with SHA-256), exactly what V18 sends to its server.
//   4. Asks Windows whether the key is kept in the TPM security chip.
//   5. Deletes the throwaway key.
// Exit code: 0 = all good, 2 = Windows Hello is not set up, 1 = something failed.
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const addonPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'native', 'v18-hello', 'v18_hello.node');
let hello;
try {
  hello = require(addonPath);
} catch (err) {
  console.error('The Windows Hello helper could not be loaded. Run "npm run build:native" first.\n', err.message);
  process.exit(1);
}
const name = 'v18-hello-check-' + randomBytes(6).toString('hex');
const t0 = Date.now();
const secs = () => ((Date.now() - t0) / 1000).toFixed(1) + ' s';

console.log('V18 Windows Hello check');
console.log('=======================\n');
const supported = await hello.isSupported();
console.log('Windows Hello set up for this Windows account:', supported ? 'YES' : 'NO');
const age = await hello.ageConsentGroup();
console.log(`Windows age group check: child = ${age.child}, minor = ${age.minor}  ("not_enforced" means Windows doesn't know, which is normal for local accounts)`);
if (!supported) {
  console.log(`
Windows Hello is not set up, so V18 can't keep an age card on this PC yet. To set it up:
  1. Press the Windows key, type "Sign-in options", and press Enter
     (or open Settings > Accounts > Sign-in options).
  2. Under "Ways to sign in", choose "PIN (Windows Hello)", then "Set up".
  3. Type your Windows password if asked, then choose a PIN.
     (Face or fingerprint is optional; a PIN is enough.)
  4. Come back here and run:  npm run hello:check
`);
  process.exit(2);
}
let ok = true;
try {
  console.log('\n1. Making a test key. Approve the Windows Hello prompt (it may open behind this window)...');
  const spki = await hello.createKey(name);
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  const jwk = key.export({ format: 'jwk' });
  console.log(`   OK after ${secs()}: ${jwk.kty} ${Buffer.from(jwk.n, 'base64url').length * 8}-bit key, e=${jwk.e}`);

  const data = Buffer.from('v18-hello-check\n' + randomBytes(16).toString('hex'), 'utf8');
  console.log('2. Signing a test string. Approve the Windows Hello prompt again...');
  const sig = await hello.sign(name, data);
  ok = verify('sha256', data, key, sig);
  console.log(`   Signature: ${sig.length} bytes. RS256 check: ${ok ? 'PASSED' : 'FAILED'} (after ${secs()})`);

  const att = await hello.attestation(name);
  console.log(`3. Is the key in the TPM security chip? ${att === 'success' ? 'YES (TPM-backed and attested)' : att === 'not_supported' ? 'No TPM attestation on this PC (the key is still kept by Windows Hello)' : att}`);
} catch (err) {
  ok = false;
  const m = /^V18HELLO:([A-Za-z]+):/.exec(err.message ?? '');
  console.error('\nWindows Hello check failed:', m?.[1] === 'UserCanceled' ? 'the Windows Hello prompt was cancelled.' : err.message);
} finally {
  await hello.deleteKey(name).catch(() => undefined);
  console.log('4. Test key deleted.');
}
console.log(ok ? '\nAll good: V18 can keep an age card on this PC.' : '\nSomething went wrong (see above).');
process.exitCode = ok ? 0 : 1;
