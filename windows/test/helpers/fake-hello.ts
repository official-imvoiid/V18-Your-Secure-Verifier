// A stand-in for the Rust Windows Hello addon, for tests only: RSA-2048 keys in memory and
// RS256 signatures (what KeyCredential.RequestSignAsync returns). No prompt, no TPM.

import { createPublicKey, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import type { HelloAddon } from '../../src/main/keys.js';

export class FakeHelloAddon implements HelloAddon {
  keys = new Map<string, KeyObject>();
  supported = true;
  cancelNext = false;
  signCount = 0;
  async isSupported() {
    return this.supported;
  }
  async createKey(name: string) {
    if (!this.supported) throw new Error('V18HELLO:NotFound: Windows Hello did not make the key');
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.keys.set(name, privateKey);
    return Buffer.from(this.pub(name));
  }
  private pub(name: string): Buffer {
    const k = this.keys.get(name);
    if (!k) throw new Error('V18HELLO:NotFound: could not open the Windows Hello key');
    return createPublicKey(k).export({ format: 'der', type: 'spki' }) as Buffer;
  }
  async publicKey(name: string) {
    return Buffer.from(this.pub(name));
  }
  async sign(name: string, data: Buffer) {
    if (this.cancelNext) {
      this.cancelNext = false;
      throw new Error('V18HELLO:UserCanceled: Windows Hello did not sign');
    }
    const k = this.keys.get(name);
    if (!k) throw new Error('V18HELLO:NotFound: could not open the Windows Hello key');
    this.signCount++;
    return sign('sha256', data, k);
  }
  async deleteKey(name: string) {
    this.keys.delete(name);
  }
  async attestation() {
    return 'success';
  }
  async ageConsentGroup() {
    return { child: 'not_enforced', minor: 'not_enforced' };
  }
}
