// The REAL Windows Hello helper (native/v18-hello/v18_hello.node), through the same
// HelloKeyProvider the app uses. Only calls that never show a Windows Hello prompt run here:
// make-key and sign-with-a-real-key need a person at the PC, so they are in "npm run hello:check".
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { DeviceKeyError, HelloKeyProvider, type HelloAddon } from '../src/main/keys.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const addonPath = path.join(here, '..', 'native', 'v18-hello', 'v18_hello.node');
const skip = process.platform !== 'win32' ? 'Windows only' : existsSync(addonPath) ? false : 'run "npm run build:native" first';
const addon = skip ? null : (createRequire(import.meta.url)(addonPath) as HelloAddon);

describe('real Windows Hello helper (no prompts)', { skip }, () => {
  const provider = new HelloKeyProvider(addon);
  const missing = 'v18-card-doesnotexist' + Date.now();

  it('loads and answers isSupported and the age group', async () => {
    assert.equal(typeof (await addon!.isSupported()), 'boolean');
    const g = await addon!.ageConsentGroup();
    assert.equal(typeof g.child, 'string');
    assert.equal(typeof g.minor, 'string');
  });

  it('check() tells the truth about Windows Hello on this account', async () => {
    const supported = await addon!.isSupported();
    const c = await provider.check();
    if (supported) assert.deepEqual(c, { ok: true });
    else assert.equal(!c.ok && c.code, 'HELLO_NOT_SET_UP');
  });

  it('a missing key is reported as KEY_NOT_FOUND, with no prompt', async () => {
    await assert.rejects(provider.publicKey(missing), (e: unknown) => e instanceof DeviceKeyError && e.code === 'KEY_NOT_FOUND');
    await assert.rejects(provider.sign(missing, new Uint8Array([1, 2, 3])), (e: unknown) => e instanceof DeviceKeyError && e.code === 'KEY_NOT_FOUND');
  });

  it('removing a missing key is fine, and its protection is unknown', async () => {
    await provider.remove(missing);
    assert.equal(await provider.protection(missing), 'unknown');
  });
});
