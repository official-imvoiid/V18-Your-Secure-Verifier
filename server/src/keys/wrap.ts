import * as crypto from 'node:crypto';

/**
 * Encryption at rest for signing keys (PROTOCOL.md 4c.7).
 *
 * A KeyWrapper turns a private key (as JSON bytes) into a sealed blob and
 * back. The blob is bound to the key ID (AES-GCM additional data), so a
 * sealed key cannot be swapped onto another key ID.
 *
 *  - LocalKekWrapper: AES-256-GCM with the 32-byte V18_KEK (Node crypto).
 *  - KmsKeyWrapper: envelope encryption through a cloud KMS. Each key gets a
 *    fresh data key; the KMS encrypts only that data key. Plug in any KMS by
 *    implementing `KmsClient` (for example AWS KMS Encrypt/Decrypt or Google
 *    Cloud KMS encrypt/decrypt). No cloud SDK ships here, because using one
 *    needs the user's own cloud account.
 */
export interface KeyWrapper {
  readonly kind: string;
  wrap(plain: Buffer, keyId: string): Promise<string>;
  unwrap(sealed: string, keyId: string): Promise<Buffer>;
}

const AAD = (keyId: string) => Buffer.from(`v18-key-wrap-v1|${keyId}`, 'utf8');

function seal(key: Buffer, plain: Buffer, keyId: string): Buffer {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(AAD(keyId));
  const body = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]);
}

function open(key: Buffer, sealed: Buffer, keyId: string): Buffer {
  if (sealed.length < 29) throw new Error('Sealed key is too short');
  const d = crypto.createDecipheriv('aes-256-gcm', key, sealed.subarray(0, 12));
  d.setAAD(AAD(keyId));
  d.setAuthTag(sealed.subarray(12, 28));
  return Buffer.concat([d.update(sealed.subarray(28)), d.final()]);
}

export class LocalKekWrapper implements KeyWrapper {
  readonly kind = 'kek';
  /** First 8 hex characters of SHA-256(KEK), so operators can tell keys apart without exposing them. */
  readonly kekId: string;

  constructor(private readonly kek: Buffer) {
    if (kek.length !== 32) throw new Error('V18_KEK must be 32 bytes');
    this.kekId = crypto.createHash('sha256').update(kek).digest('hex').slice(0, 8);
  }

  async wrap(plain: Buffer, keyId: string): Promise<string> {
    return `kek1.${this.kekId}.${seal(this.kek, plain, keyId).toString('base64url')}`;
  }

  async unwrap(sealed: string, keyId: string): Promise<Buffer> {
    const [v, id, blob] = sealed.split('.');
    if (v !== 'kek1' || !blob) throw new Error(`Key ${keyId} was not sealed with a V18_KEK`);
    if (id !== this.kekId) throw new Error(`Key ${keyId} was sealed with another V18_KEK (${id}, this one is ${this.kekId})`);
    try {
      return open(this.kek, Buffer.from(blob, 'base64url'), keyId);
    } catch {
      throw new Error(`Key ${keyId} could not be decrypted (wrong V18_KEK or damaged data)`);
    }
  }
}

/** The two calls a KMS must offer. `context` should be passed to the KMS as encryption context / AAD. */
export interface KmsClient {
  readonly name: string;
  encrypt(plaintext: Buffer, context: string): Promise<Buffer>;
  decrypt(ciphertext: Buffer, context: string): Promise<Buffer>;
}

export class KmsKeyWrapper implements KeyWrapper {
  readonly kind: string;

  constructor(private readonly kms: KmsClient) {
    this.kind = `kms:${kms.name}`;
  }

  async wrap(plain: Buffer, keyId: string): Promise<string> {
    const dataKey = crypto.randomBytes(32);
    const wrappedDataKey = await this.kms.encrypt(dataKey, `v18-key-wrap-v1|${keyId}`);
    const body = seal(dataKey, plain, keyId);
    dataKey.fill(0);
    return `kms1.${wrappedDataKey.toString('base64url')}.${body.toString('base64url')}`;
  }

  async unwrap(sealed: string, keyId: string): Promise<Buffer> {
    const [v, wdk, blob] = sealed.split('.');
    if (v !== 'kms1' || !wdk || !blob) throw new Error(`Key ${keyId} was not sealed by a KMS`);
    const dataKey = await this.kms.decrypt(Buffer.from(wdk, 'base64url'), `v18-key-wrap-v1|${keyId}`);
    try {
      return open(dataKey, Buffer.from(blob, 'base64url'), keyId);
    } finally {
      dataKey.fill(0);
    }
  }
}
