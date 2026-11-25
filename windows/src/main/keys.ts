// Device keys (PROTOCOL.md 3.4). Two providers:
//  - HelloKeyProvider: the real one. RSA-2048 keys made and kept by Windows Hello (in the TPM
//    when the PC has one). Every signature shows the Windows Hello prompt. Signatures are RS256.
//  - TestSoftwareKeyProvider: ONLY when the app is started with --v18-test-software-key. An
//    ES256 key held in memory, never saved, no prompt. The whole UI shows a "TEST KEY" banner.
// There is no automatic fallback from one to the other.

import { generateKeyPairSync, randomBytes, sign as nodeSign, type KeyObject } from 'node:crypto';
import { b64urlEncode } from '../shared/b64url.js';
import { spkiToJwk, verifyDeviceSignature, type DeviceJwk } from '../shared/jwk.js';
import type { DeviceAlg } from '../shared/signing.js';

export type KeyErrorCode =
  | 'ADDON_MISSING'
  | 'HELLO_NOT_SET_UP'
  | 'USER_CANCELED'
  | 'KEY_NOT_FOUND'
  | 'DEVICE_LOCKED'
  | 'SELF_CHECK_FAILED'
  | 'HELLO_ERROR';

export class DeviceKeyError extends Error {
  constructor(public readonly code: KeyErrorCode, message: string) {
    super(message);
    this.name = 'DeviceKeyError';
  }
}

export type KeyProtection = 'tpm' | 'hello' | 'test-software' | 'unknown';

export interface DeviceKeyProvider {
  readonly kind: 'hello' | 'test-software';
  /** Can this provider make keys right now? Never shows a prompt. */
  check(): Promise<{ ok: true } | { ok: false; code: KeyErrorCode; detail: string }>;
  /** Make a new key. Windows Hello shows its prompt. */
  create(name: string): Promise<DeviceJwk>;
  /** Public key of an existing key (no prompt). */
  publicKey(name: string): Promise<DeviceJwk>;
  /** Sign the UTF-8 bytes of a signing string. Windows Hello shows its prompt every time. */
  sign(name: string, data: Uint8Array): Promise<{ alg: DeviceAlg; sig: Uint8Array }>;
  remove(name: string): Promise<void>;
  protection(name: string): Promise<KeyProtection>;
}

export function newKeyName(): string {
  return 'v18-card-' + b64urlEncode(randomBytes(12));
}

export function aliasFor(provider: DeviceKeyProvider, name: string): string {
  return `${provider.kind}:${name}`;
}

export function splitAlias(alias: string): { kind: 'hello' | 'test-software'; name: string } | null {
  const m = /^(hello|test-software):(v18-card-[A-Za-z0-9_-]+)$/.exec(alias);
  return m ? { kind: m[1] as 'hello' | 'test-software', name: m[2] } : null;
}

// ---------------------------------------------------------------------------------------------

/** The shape of the Rust addon in native/v18-hello (napi-rs). */
export interface HelloAddon {
  isSupported(): Promise<boolean>;
  createKey(name: string): Promise<Buffer>;
  publicKey(name: string): Promise<Buffer>;
  sign(name: string, data: Buffer): Promise<Buffer>;
  deleteKey(name: string): Promise<void>;
  attestation(name: string): Promise<string>;
  ageConsentGroup(): Promise<{ child: string; minor: string }>;
}

function mapHelloError(err: unknown, during: 'create' | 'use'): DeviceKeyError {
  const msg = err instanceof Error ? err.message : String(err);
  const m = /^V18HELLO:([A-Za-z]+):\s*(.*)$/s.exec(msg);
  let code = m?.[1] ?? 'WinError';
  const detail = m?.[2] ?? msg;
  // NTE_NO_KEY (0x8009000D) and NTE_BAD_KEYSET (0x80090016): Windows has no such key, for example
  // DeleteAsync on a key that is already gone. Found by the real-helper test (test/hello-native.test.ts).
  if (code === 'WinError' && /\(0x8009000D\)|\(0x80090016\)/i.test(detail)) code = 'NotFound';
  switch (code) {
    case 'UserCanceled':
    case 'UserPrefersPassword':
      return new DeviceKeyError('USER_CANCELED', 'Windows Hello was cancelled.');
    case 'NotFound':
      // When Hello is not set up, creating a key also reports NotFound.
      return during === 'create'
        ? new DeviceKeyError('HELLO_NOT_SET_UP', 'Windows Hello is not set up on this Windows account.')
        : new DeviceKeyError('KEY_NOT_FOUND', 'The Windows Hello key for this age card is missing.');
    case 'SecurityDeviceLocked':
      return new DeviceKeyError('DEVICE_LOCKED', 'The security chip is locked after too many wrong tries.');
    default:
      return new DeviceKeyError('HELLO_ERROR', `Windows Hello error: ${detail}`);
  }
}

export class HelloKeyProvider implements DeviceKeyProvider {
  readonly kind = 'hello' as const;
  private readonly protectionCache = new Map<string, KeyProtection>();

  constructor(private readonly addon: HelloAddon | null, private readonly loadError?: string) {}

  async check() {
    if (!this.addon) return { ok: false as const, code: 'ADDON_MISSING' as const, detail: this.loadError ?? 'Windows Hello helper not found' };
    try {
      if (await this.addon.isSupported()) return { ok: true as const };
      return { ok: false as const, code: 'HELLO_NOT_SET_UP' as const, detail: 'Windows Hello is not set up on this Windows account.' };
    } catch (err) {
      return { ok: false as const, code: 'HELLO_ERROR' as const, detail: String(err instanceof Error ? err.message : err) };
    }
  }

  private need(): HelloAddon {
    if (!this.addon) throw new DeviceKeyError('ADDON_MISSING', this.loadError ?? 'Windows Hello helper not found');
    return this.addon;
  }

  async create(name: string): Promise<DeviceJwk> {
    let spki: Buffer;
    try {
      spki = await this.need().createKey(name);
    } catch (err) {
      throw err instanceof DeviceKeyError ? err : mapHelloError(err, 'create');
    }
    return spkiToJwk(spki);
  }

  async publicKey(name: string): Promise<DeviceJwk> {
    try {
      return spkiToJwk(await this.need().publicKey(name));
    } catch (err) {
      throw err instanceof DeviceKeyError ? err : mapHelloError(err, 'use');
    }
  }

  async sign(name: string, data: Uint8Array) {
    const addon = this.need();
    let sig: Buffer;
    try {
      sig = await addon.sign(name, Buffer.from(data));
    } catch (err) {
      throw mapHelloError(err, 'use');
    }
    // Self-check: the signature must verify as RS256 with the key's public half.
    const jwk = await this.publicKey(name);
    if (!verifyDeviceSignature(jwk, data, sig)) {
      throw new DeviceKeyError('SELF_CHECK_FAILED', 'Windows Hello returned a signature that does not check out.');
    }
    return { alg: 'RS256' as const, sig: new Uint8Array(sig) };
  }

  async remove(name: string): Promise<void> {
    try {
      await this.need().deleteKey(name);
    } catch (err) {
      const mapped = mapHelloError(err, 'use');
      if (mapped.code !== 'KEY_NOT_FOUND') throw mapped;
    }
    this.protectionCache.delete(name);
  }

  async protection(name: string): Promise<KeyProtection> {
    const cached = this.protectionCache.get(name);
    if (cached) return cached;
    let result: KeyProtection = 'unknown';
    try {
      const a = await this.need().attestation(name);
      result = a === 'success' ? 'tpm' : a === 'not_supported' ? 'hello' : 'unknown';
    } catch {
      result = 'unknown';
    }
    this.protectionCache.set(name, result);
    return result;
  }
}

// ---------------------------------------------------------------------------------------------

/** TEST ONLY. Keys live in memory, are lost when the app quits, and need no approval. */
export class TestSoftwareKeyProvider implements DeviceKeyProvider {
  readonly kind = 'test-software' as const;
  private readonly keys = new Map<string, { priv: KeyObject; jwk: DeviceJwk }>();

  async check() {
    return { ok: true as const };
  }

  async create(name: string): Promise<DeviceJwk> {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = spkiToJwk(publicKey.export({ format: 'der', type: 'spki' }));
    this.keys.set(name, { priv: privateKey, jwk });
    return jwk;
  }

  async publicKey(name: string): Promise<DeviceJwk> {
    const k = this.keys.get(name);
    if (!k) throw new DeviceKeyError('KEY_NOT_FOUND', 'TEST key not found (TEST keys are forgotten when the app quits).');
    return k.jwk;
  }

  async sign(name: string, data: Uint8Array) {
    const k = this.keys.get(name);
    if (!k) throw new DeviceKeyError('KEY_NOT_FOUND', 'TEST key not found (TEST keys are forgotten when the app quits).');
    const sig = nodeSign('sha256', data, { key: k.priv, dsaEncoding: 'ieee-p1363' });
    return { alg: 'ES256' as const, sig: new Uint8Array(sig) };
  }

  async remove(name: string): Promise<void> {
    this.keys.delete(name);
  }

  async protection(): Promise<KeyProtection> {
    return 'test-software';
  }
}
