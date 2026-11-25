// Device public keys as JWK, and RFC 7638 JWK thumbprints (PROTOCOL.md 3.4).

import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { b64urlDecode, b64urlEncode } from './b64url.js';
import type { DeviceAlg } from './signing.js';

export interface RsaJwk {
  kty: 'RSA';
  n: string;
  e: string;
}
export interface EcJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}
export type DeviceJwk = RsaJwk | EcJwk;

/** Turn a DER SubjectPublicKeyInfo (what Windows Hello gives us) into a minimal JWK. */
export function spkiToJwk(spkiDer: Uint8Array): DeviceJwk {
  const key = createPublicKey({ key: Buffer.from(spkiDer), format: 'der', type: 'spki' });
  const jwk = key.export({ format: 'jwk' }) as Record<string, string>;
  if (jwk.kty === 'RSA') {
    const bits = b64urlDecode(jwk.n).length * 8;
    if (bits !== 2048) throw new Error(`device key is RSA-${bits}, expected RSA-2048`);
    return { kty: 'RSA', n: jwk.n, e: jwk.e };
  }
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  }
  throw new Error(`unsupported device key type ${jwk.kty}`);
}

export function algForJwk(jwk: DeviceJwk): DeviceAlg {
  return jwk.kty === 'RSA' ? 'RS256' : 'ES256';
}

/**
 * RFC 7638: SHA-256 over the required members only, in lexicographic order, with no spaces.
 * RSA: {"e","kty","n"}. EC: {"crv","kty","x","y"}.
 */
export function jwkThumbprint(jwk: DeviceJwk): string {
  const canonical =
    jwk.kty === 'RSA'
      ? `{"e":${JSON.stringify(jwk.e)},"kty":"RSA","n":${JSON.stringify(jwk.n)}}`
      : `{"crv":"P-256","kty":"EC","x":${JSON.stringify(jwk.x)},"y":${JSON.stringify(jwk.y)}}`;
  return b64urlEncode(createHash('sha256').update(canonical, 'utf8').digest());
}

/** The `devicePublicKey` object the server expects: the JWK plus its `alg`. */
export function devicePublicKeyBody(jwk: DeviceJwk): DeviceJwk & { alg: DeviceAlg } {
  return { ...jwk, alg: algForJwk(jwk) };
}

/** Check a device signature locally, the same way the server will (used as a self-test). */
export function verifyDeviceSignature(jwk: DeviceJwk, data: Uint8Array, sig: Uint8Array): boolean {
  const key = createPublicKey({ key: jwk as unknown as Record<string, string>, format: 'jwk' });
  if (jwk.kty === 'RSA') {
    return nodeVerify('sha256', data, key, sig);
  }
  const dsaEncoding = sig.length === 64 ? 'ieee-p1363' : 'der';
  return nodeVerify('sha256', data, { key, dsaEncoding }, sig);
}
