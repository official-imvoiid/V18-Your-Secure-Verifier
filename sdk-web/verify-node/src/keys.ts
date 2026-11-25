import * as crypto from 'node:crypto';
import { RULES } from './errors.js';

/** One V18 ticket-signing public key, as listed in the JWKS (PROTOCOL.md 3.2). */
export interface V18Key {
  kid: string;
  publicKey: crypto.KeyObject;
  /** The age threshold this key certifies. Authorization uses this, never the ticket's own minAge. */
  minAge: number;
  /** Not valid before (epoch seconds). */
  nbf: number;
  /** Expires at (epoch seconds). Tickets are still accepted until exp + 600 seconds. */
  exp: number;
}

export interface KeyLookup {
  key: V18Key | null;
  /** Set when the key is unknown because the JWKS could not be fetched. */
  unavailable?: boolean;
  reason?: string;
}

export interface JwksKeyStoreOptions {
  /** V18 server base URL, for example "http://localhost:8080" (a trailing "/v1" is fine too). */
  serverUrl?: string;
  /** Full JWKS URL. Overrides serverUrl. */
  jwksUrl?: string;
  /** How long a fetched JWKS is trusted before it is fetched again. Default 3600 seconds. */
  cacheTtlSeconds?: number;
  /** An unknown keyId triggers a refetch at most this often, so junk tickets cannot flood the V18 server. Default 30. */
  minRefreshIntervalSeconds?: number;
  /** Network timeout for the JWKS fetch. Default 5000 ms. */
  timeoutMs?: number;
  /** For tests. */
  fetch?: typeof fetch;
  /** For tests. Returns epoch milliseconds. */
  clock?: () => number;
}

/** Turns "http://host:8080", "http://host:8080/" or "http://host:8080/v1" into "http://host:8080". */
export function normalizeServerUrl(url: string): string {
  return url.trim().replace(/\/+$/, '').replace(/\/v1$/, '');
}

function isInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v);
}

/**
 * Parses one JWK from the V18 JWKS. Returns null (with a reason) for keys we must not use:
 * wrong algorithm, missing v18_min_age / nbf / exp, or an RSA modulus under 2048 bits.
 */
export function parseV18Jwk(jwk: any): { key: V18Key | null; reason?: string } {
  if (!jwk || typeof jwk !== 'object') return { key: null, reason: 'not an object' };
  const kid = jwk.kid;
  if (typeof kid !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(kid)) return { key: null, reason: 'bad kid' };
  if (jwk.kty !== 'RSA') return { key: null, reason: `${kid}: kty is not RSA` };
  if (jwk.alg !== RULES.ALGORITHM) return { key: null, reason: `${kid}: alg is not ${RULES.ALGORITHM}` };
  if (jwk.use !== undefined && jwk.use !== 'sig') return { key: null, reason: `${kid}: use is not sig` };
  if (!isInt(jwk.v18_min_age) || jwk.v18_min_age < 0) return { key: null, reason: `${kid}: missing v18_min_age` };
  if (!isInt(jwk.nbf) || !isInt(jwk.exp) || jwk.exp <= jwk.nbf) return { key: null, reason: `${kid}: bad nbf/exp` };
  if (typeof jwk.n !== 'string' || typeof jwk.e !== 'string') return { key: null, reason: `${kid}: missing n/e` };

  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
  } catch (e: any) {
    return { key: null, reason: `${kid}: ${e.message}` };
  }
  const bits = publicKey.asymmetricKeyDetails?.modulusLength ?? 0;
  if (bits < 2048) return { key: null, reason: `${kid}: RSA key is only ${bits} bits` };

  return { key: { kid, publicKey, minAge: jwk.v18_min_age, nbf: jwk.nbf, exp: jwk.exp } };
}

/**
 * Loads and caches V18's public keys from `GET /v1/keys`.
 *
 * - Keys that vanish from the JWKS are dropped on the next refresh.
 * - Pinned keys (`addJwk`, `setJwks`) never expire from the cache and need no network.
 */
export class JwksKeyStore {
  private fetched = new Map<string, V18Key>();
  private pinned = new Map<string, V18Key>();
  private lastFetchMs = 0;
  private lastAttemptMs = 0;
  private inFlight: Promise<void> | null = null;
  private readonly jwksUrl: string | null;
  private readonly ttlMs: number;
  private readonly minRefreshMs: number;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;
  private readonly clock: () => number;

  constructor(options: JwksKeyStoreOptions = {}) {
    this.jwksUrl = options.jwksUrl
      ? options.jwksUrl
      : options.serverUrl
        ? `${normalizeServerUrl(options.serverUrl)}/v1/keys`
        : null;
    this.ttlMs = (options.cacheTtlSeconds ?? 3600) * 1000;
    this.minRefreshMs = (options.minRefreshIntervalSeconds ?? 30) * 1000;
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.fetchFn = options.fetch ?? globalThis.fetch;
    this.clock = options.clock ?? Date.now;
  }

  /** Pins one key (for offline use or tests). Throws if the JWK is not a usable V18 key. */
  public addJwk(jwk: unknown): V18Key {
    const { key, reason } = parseV18Jwk(jwk);
    if (!key) throw new Error(`[V18] Unusable key: ${reason}`);
    this.pinned.set(key.kid, key);
    return key;
  }

  /** Pins every usable key in a JWKS object `{ keys: [...] }`. Returns how many were pinned. */
  public setJwks(jwks: unknown): number {
    const keys = (jwks as any)?.keys;
    if (!Array.isArray(keys)) throw new Error('[V18] JWKS must look like { "keys": [...] }');
    this.pinned.clear();
    for (const jwk of keys) {
      const { key } = parseV18Jwk(jwk);
      if (key) this.pinned.set(key.kid, key);
    }
    return this.pinned.size;
  }

  /** Fetches the JWKS now. Throws on network or format errors. */
  public async refresh(): Promise<void> {
    if (!this.jwksUrl) return;
    if (this.inFlight) return this.inFlight;
    this.lastAttemptMs = this.clock();
    this.inFlight = (async () => {
      const res = await this.fetchFn(this.jwksUrl!, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!res.ok) throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
      const data: any = await res.json();
      if (!data || !Array.isArray(data.keys)) throw new Error('JWKS response has no "keys" array');
      const next = new Map<string, V18Key>();
      for (const jwk of data.keys) {
        const { key } = parseV18Jwk(jwk);
        if (key) next.set(key.kid, key);
      }
      this.fetched = next;
      this.lastFetchMs = this.clock();
    })();
    try {
      await this.inFlight;
    } finally {
      this.inFlight = null;
    }
  }

  public async getKey(kid: string): Promise<KeyLookup> {
    const pinned = this.pinned.get(kid);
    if (pinned) return { key: pinned };
    if (!this.jwksUrl) return { key: null };

    const now = this.clock();
    const stale = this.lastFetchMs === 0 || now - this.lastFetchMs >= this.ttlMs;
    const unknown = !this.fetched.has(kid);
    const neverTried = this.lastAttemptMs === 0;
    const mayRetry = neverTried || now - this.lastAttemptMs >= this.minRefreshMs;

    if ((stale || unknown) && mayRetry) {
      try {
        await this.refresh();
      } catch (e: any) {
        const cached = this.fetched.get(kid);
        // A cached key is still fine to use if the refresh failed (V18 being down must not break sites).
        if (cached) return { key: cached };
        return { key: null, unavailable: true, reason: e?.message ?? String(e) };
      }
    }
    return { key: this.fetched.get(kid) ?? null };
  }

  /** Every key currently known (pinned and fetched). */
  public list(): V18Key[] {
    return [...this.fetched.values(), ...this.pinned.values()];
  }
}

/** Old name, kept so existing imports keep working. */
export { JwksKeyStore as KeyCache };
