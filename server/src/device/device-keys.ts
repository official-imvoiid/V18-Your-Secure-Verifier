import * as crypto from 'node:crypto';
import { calculateJwkThumbprint } from 'jose';
import { ApiError } from '../errors.js';
import { decodeBase64url, isPlainObject } from '../util.js';

/**
 * Device keys and device signatures (protocol 3.4).
 *
 * Uses Node's built-in crypto (OpenSSL) for verification and `jose` for the
 * RFC 7638 thumbprint. No home-made cryptography.
 */

export type DeviceAlg = 'ES256' | 'RS256';

export type DevicePublicJwk =
  | { kty: 'EC'; crv: 'P-256'; x: string; y: string }
  | { kty: 'RSA'; n: string; e: string };

export interface DeviceKey {
  alg: DeviceAlg;
  /** Public members only, ready to store. */
  jwk: DevicePublicJwk;
  /** RFC 7638 JWK thumbprint (SHA-256, base64url). */
  thumbprint: string;
  keyObject: crypto.KeyObject;
}

export interface DeviceSignature {
  alg: DeviceAlg;
  sig: string;
}

const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

const badKey = (message: string) => new ApiError(400, 'BAD_DEVICE_KEY', message);

/**
 * Checks a device public key JWK and returns a clean public copy plus its
 * thumbprint. Refuses anything that carries private key parts.
 */
export async function parseDevicePublicKey(input: unknown): Promise<DeviceKey> {
  if (!isPlainObject(input)) throw badKey('devicePublicKey must be a JWK object');
  for (const m of PRIVATE_MEMBERS) {
    if (m in input) throw badKey('devicePublicKey must hold the PUBLIC key only');
  }
  const kty = input.kty;
  const declaredAlg = input.alg;
  let alg: DeviceAlg;
  let jwk: DevicePublicJwk;

  if (kty === 'EC') {
    alg = 'ES256';
    if (input.crv !== 'P-256') throw badKey('EC device keys must use crv P-256');
    const x = decodeOrBadKey(input.x, 'x');
    const y = decodeOrBadKey(input.y, 'y');
    if (x.length !== 32 || y.length !== 32) throw badKey('EC x and y must be 32 bytes each');
    jwk = { kty: 'EC', crv: 'P-256', x: input.x as string, y: input.y as string };
  } else if (kty === 'RSA') {
    alg = 'RS256';
    const n = decodeOrBadKey(input.n, 'n');
    const e = decodeOrBadKey(input.e, 'e');
    if (n[0] === 0) throw badKey('RSA n must not have leading zero bytes');
    const bits = n.length * 8 - Math.clz32(n[0]) + 24;
    if (bits < 2048 || bits > 4096) throw badKey('RSA device keys must be 2048 to 4096 bits');
    if (e.toString('hex') !== '010001') throw badKey('RSA device keys must use e = 65537 (AQAB)');
    jwk = { kty: 'RSA', n: input.n as string, e: input.e as string };
  } else {
    throw badKey('devicePublicKey kty must be "EC" (ES256) or "RSA" (RS256)');
  }

  if (declaredAlg !== undefined && declaredAlg !== alg) {
    throw badKey(`devicePublicKey alg "${String(declaredAlg)}" does not match its key type (${alg})`);
  }

  let keyObject: crypto.KeyObject;
  try {
    // OpenSSL checks the EC point is on the curve.
    keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    throw badKey('devicePublicKey is not a valid public key');
  }

  const thumbprint = await calculateJwkThumbprint(jwk, 'sha256');
  return { alg, jwk, thumbprint, keyObject };
}

function decodeOrBadKey(value: unknown, field: string): Buffer {
  try {
    return decodeBase64url(value, `devicePublicKey.${field}`, 1024);
  } catch {
    throw badKey(`devicePublicKey.${field} must be base64url without padding`);
  }
}

/** Rebuilds a stored public JWK into a key object. */
export function keyFromStoredJwk(alg: DeviceAlg, jwk: DevicePublicJwk): crypto.KeyObject {
  void alg;
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

export function parseDeviceSignature(input: unknown): DeviceSignature | null {
  if (!isPlainObject(input)) return null;
  if (input.alg !== 'ES256' && input.alg !== 'RS256') return null;
  if (typeof input.sig !== 'string' || input.sig.length === 0 || input.sig.length > 1400) return null;
  return { alg: input.alg, sig: input.sig };
}

/**
 * Verifies a device signature over the UTF-8 bytes of `signingString`.
 *  - ES256: ECDSA P-256 SHA-256, signature as DER or as 64-byte raw r||s.
 *  - RS256: RSASSA-PKCS1-v1_5 SHA-256.
 * Returns false (never throws) for any bad input.
 */
export function verifyDeviceSignature(
  key: { alg: DeviceAlg; keyObject: crypto.KeyObject },
  signature: DeviceSignature | null,
  signingString: string
): boolean {
  if (!signature || signature.alg !== key.alg) return false;
  let sig: Buffer;
  try {
    sig = decodeBase64url(signature.sig, 'sig', 1024);
  } catch {
    return false;
  }
  const data = Buffer.from(signingString, 'utf8');
  try {
    if (key.alg === 'ES256') {
      if (sig.length === 64) {
        if (crypto.verify('sha256', data, { key: key.keyObject, dsaEncoding: 'ieee-p1363' }, sig)) return true;
        // A DER signature can (very rarely) also be 64 bytes long; fall through.
      }
      if (sig[0] !== 0x30) return false;
      return crypto.verify('sha256', data, { key: key.keyObject, dsaEncoding: 'der' }, sig);
    }
    return crypto.verify(
      'sha256',
      data,
      { key: key.keyObject, padding: crypto.constants.RSA_PKCS1_PADDING },
      sig
    );
  } catch {
    return false;
  }
}

/** Signing strings from protocol 3.4: fields joined with "\n", no trailing newline. */
export const signingStrings = {
  cardIssue: (challenge: string, deviceKeyThumbprint: string) =>
    ['v18-card-issue', challenge, deviceKeyThumbprint].join('\n'),
  ticketRequest: (cardId: string, challenge: string, keyId: string, blindedMessage: string) =>
    ['v18-ticket-request', cardId, challenge, keyId, blindedMessage].join('\n'),
  linkApprove: (cardId: string, challenge: string, linkId: string) =>
    ['v18-link-approve', cardId, challenge, linkId].join('\n'),
  cardDelete: (cardId: string, challenge: string) => ['v18-card-delete', cardId, challenge].join('\n'),
};
