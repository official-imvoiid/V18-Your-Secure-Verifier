/** Reading connector settings and keys from environment variables. */
import { readFileSync, existsSync } from 'node:fs';
import { importJWK, importPKCS8, exportJWK, type JWK } from 'jose';
import type { ConnectorId, Env } from './types.js';

/** `V18_CONNECTOR_<ID>_<NAME>`, for example `V18_CONNECTOR_BANKID_SE_CLIENT_ID`. */
export function envName(id: ConnectorId, name: string): string {
  return `V18_CONNECTOR_${id.toUpperCase()}_${name}`;
}

export function envValue(env: Env, id: ConnectorId, name: string): string | undefined {
  const v = env[envName(id, name)];
  return v !== undefined && v.trim() !== '' ? v.trim() : undefined;
}

export function hasAll(env: Env, id: ConnectorId, names: readonly string[]): boolean {
  return names.every((n) => envValue(env, id, n) !== undefined);
}

/** A value that is either inline text or a path to a file holding it. */
export function inlineOrFile(value: string): string {
  const v = value.trim();
  if (v.startsWith('{') || v.startsWith('-----BEGIN') || v.startsWith('<')) return v;
  if (existsSync(v)) return readFileSync(v, 'utf8');
  return v;
}

export interface LoadedPrivateKey {
  key: CryptoKey;
  alg: string;
  kid?: string;
  /** The public half as a JWK, for the RP's published JWKS. */
  publicJwk: JWK;
}

function defaultAlg(jwk: JWK, use: 'sig' | 'enc'): string {
  if (jwk.alg) return jwk.alg;
  if (use === 'enc') return jwk.kty === 'RSA' ? 'RSA-OAEP-256' : 'ECDH-ES+A256KW';
  if (jwk.kty === 'EC') return jwk.crv === 'P-384' ? 'ES384' : jwk.crv === 'P-521' ? 'ES512' : 'ES256';
  if (jwk.kty === 'OKP') return 'EdDSA';
  return 'RS256';
}

/**
 * Loads a private key from a JWK (inline JSON or file) or a PKCS#8 PEM (inline or file).
 * For PEM keys, `pemAlg` says the algorithm, because a PEM file does not carry one.
 */
export async function loadPrivateKey(value: string, use: 'sig' | 'enc', pemAlg?: string): Promise<LoadedPrivateKey> {
  const text = inlineOrFile(value);
  let jwk: JWK;
  let key: CryptoKey;
  let alg: string;
  if (text.trim().startsWith('{')) {
    jwk = JSON.parse(text) as JWK;
    alg = defaultAlg(jwk, use);
    key = (await importJWK(jwk, alg, { extractable: true })) as CryptoKey;
  } else {
    alg = pemAlg ?? (use === 'enc' ? 'ECDH-ES+A256KW' : 'ES256');
    key = (await importPKCS8(text, alg, { extractable: true })) as CryptoKey;
    jwk = await exportJWK(key);
  }
  const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, oth: _oth, k: _k, ...pub } = jwk;
  const publicJwk: JWK = { ...pub, use, alg };
  return { key, alg, kid: jwk.kid, publicJwk };
}

/** True for 127.0.0.1, ::1 and localhost: the only hosts where tests may use plain http. */
export function isLoopback(url: string): boolean {
  try {
    const h = new URL(url).hostname.replace(/^\[|\]$/g, '');
    return h === '127.0.0.1' || h === 'localhost' || h === '::1';
  } catch {
    return false;
  }
}
