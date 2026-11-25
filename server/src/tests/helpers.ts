/**
 * Test helpers (not a test file itself).
 *
 * Everything here plays the CLIENT side of the protocol (a phone, a PC, a
 * website) so the tests can talk to a real server over HTTP.
 */
import * as http from 'node:http';
import * as crypto from 'node:crypto';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { calculateJwkThumbprint } from 'jose';
import 'reflect-metadata';
import { createV18, CreateOptions, V18Services } from '../app.js';
import { StaticRevocationList } from '../attestation/android.js';
import { Config } from '../config.js';
import { MemoryKeyStore } from '../keys/keystore.js';

// ---- Database under test ----------------------------------------------------------
// npm test: SQLite in memory. npm run test:pg: a real PostgreSQL (embedded-postgres),
// one fresh database per test server.

export const TEST_DB: 'sqlite' | 'postgres' = process.env.V18_TEST_DB === 'postgres' ? 'postgres' : 'sqlite';

async function pgAdmin<T>(fn: (c: import('pg').Client) => Promise<T>): Promise<T> {
  const base = process.env.V18_TEST_PG_URL;
  if (!base) throw new Error('V18_TEST_DB=postgres needs V18_TEST_PG_URL (npm run test:pg sets it)');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const pg = require('pg') as typeof import('pg');
  const c = new pg.Client({ connectionString: base });
  await c.connect();
  try {
    return await fn(c);
  } finally {
    await c.end();
  }
}

/** A new empty PostgreSQL database for one test server (or null on SQLite). */
export async function freshDatabase(): Promise<{ url: string; drop(): Promise<void> } | null> {
  if (TEST_DB !== 'postgres') return null;
  const name = `v18_t_${crypto.randomBytes(6).toString('hex')}`;
  await pgAdmin((c) => c.query(`CREATE DATABASE ${name}`));
  const u = new URL(process.env.V18_TEST_PG_URL!);
  u.pathname = `/${name}`;
  return {
    url: u.toString(),
    drop: () => pgAdmin((c) => c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`)).then(() => undefined),
  };
}

// ---- Clock ------------------------------------------------------------------

export class FakeClock {
  constructor(public t: number = Date.UTC(2026, 10, 9, 12, 0, 0)) {}
  now = (): number => this.t;
  advance(ms: number): void {
    this.t += ms;
  }
}

export const SECOND = 1000;
export const MINUTE = 60 * SECOND;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

// ---- Server -----------------------------------------------------------------

/** Every table and its rows, on either engine (privacy tests dump them all). */
export async function dumpTables(db: import('../db/sql.js').SqlDb): Promise<Record<string, unknown[]>> {
  const names =
    db.dialect === 'sqlite'
      ? (await db.all<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table'")).map((r) => r.name)
      : (await db.all<{ name: string }>("SELECT table_name AS name FROM information_schema.tables WHERE table_schema = 'public'")).map((r) => r.name);
  const out: Record<string, unknown[]> = {};
  for (const n of names) out[n] = await db.all(`SELECT * FROM ${n}`);
  return out;
}

export async function columnsOf(db: import('../db/sql.js').SqlDb, table: string): Promise<string[]> {
  const rows =
    db.dialect === 'sqlite'
      ? await db.all<{ name: string }>(`PRAGMA table_info(${table})`)
      : await db.all<{ name: string }>('SELECT column_name AS name FROM information_schema.columns WHERE table_name = ?', [table]);
  return rows.map((r) => r.name).sort();
}

export interface TestServer {
  url: string;
  services: V18Services;
  clock: FakeClock;
  close(): Promise<void>;
}

export async function startServer(
  opts: { config?: Partial<Config>; clock?: FakeClock } & Omit<CreateOptions, 'config' | 'clock'> = {}
): Promise<TestServer> {
  const clock = opts.clock ?? new FakeClock();
  const pgdb = await freshDatabase();
  const v18 = await createV18({
    env: opts.env ?? {},
    clock: clock.now,
    // Pass keyStore: undefined to use the real configured store (file or encrypted db).
    keyStore: 'keyStore' in opts ? opts.keyStore : new MemoryKeyStore(),
    aadhaarVerifier: opts.aadhaarVerifier ?? null,
    revocation: opts.revocation ?? new StaticRevocationList(),
    trustedIacas: opts.trustedIacas ?? [],
    // Pass connectorRegistry: undefined to load the real @v18/connectors with `env`.
    connectorRegistry: 'connectorRegistry' in opts ? opts.connectorRegistry : null,
    extraAttestationRoots: opts.extraAttestationRoots,
    keyWrapper: opts.keyWrapper,
    config: {
      devMode: true,
      dbPath: ':memory:',
      databaseUrl: pgdb?.url ?? null,
      publicUrl: 'http://localhost:8080',
      // Tests make many sessions from 127.0.0.1; the per-IP limits have their own tests.
      pairingSessionsPerMinute: 10_000,
      walletPerIpPerMinute: 10_000,
      nullifierPerIpPerHour: 10_000,
      ...opts.config,
    },
  });
  const server = await new Promise<http.Server>((resolve) => {
    const s = v18.app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}`,
    services: v18.services,
    clock,
    async close() {
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await v18.close();
      await pgdb?.drop();
    },
  };
}

export interface ApiResult {
  status: number;
  body: any;
  headers: Headers;
}

export async function api(
  base: string,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {}
): Promise<ApiResult> {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: body === undefined ? headers : { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed: any = text;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    /* not JSON (PEM) */
  }
  return { status: res.status, body: parsed, headers: res.headers };
}

export async function newChallenge(base: string): Promise<string> {
  const r = await api(base, 'POST', '/v1/challenge');
  if (r.status !== 200) throw new Error(`challenge failed: ${r.status}`);
  return r.body.challenge as string;
}

// ---- Device keys (what the phone's Keystore / Windows Hello would do) --------

export class TestDevice {
  private constructor(
    readonly alg: 'ES256' | 'RS256',
    private readonly privateKey: crypto.KeyObject,
    readonly publicJwk: Record<string, string>,
    readonly thumbprint: string
  ) {}

  static async es256(): Promise<TestDevice> {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
    const pub = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
    return new TestDevice('ES256', privateKey, pub, await calculateJwkThumbprint(pub as any, 'sha256'));
  }

  static async rs256(): Promise<TestDevice> {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
    const pub = { kty: 'RSA', n: jwk.n, e: jwk.e };
    return new TestDevice('RS256', privateKey, pub, await calculateJwkThumbprint(pub as any, 'sha256'));
  }

  /** JWK as sent to the server (with "alg"). */
  get jwkWithAlg(): Record<string, string> {
    return { ...this.publicJwk, alg: this.alg };
  }

  /** Signs the UTF-8 bytes. ES256 uses DER unless `raw` is set (64-byte r||s). */
  sign(signingString: string, opts: { raw?: boolean } = {}): { alg: 'ES256' | 'RS256'; sig: string } {
    const data = Buffer.from(signingString, 'utf8');
    const sig =
      this.alg === 'ES256'
        ? crypto.sign('sha256', data, { key: this.privateKey, dsaEncoding: opts.raw ? 'ieee-p1363' : 'der' })
        : crypto.sign('sha256', data, { key: this.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
    return { alg: this.alg, sig: sig.toString('base64url') };
  }
}

export const ss = {
  cardIssue: (challenge: string, thumbprint: string) => `v18-card-issue\n${challenge}\n${thumbprint}`,
  ticket: (cardId: string, challenge: string, keyId: string, blinded: string) =>
    `v18-ticket-request\n${cardId}\n${challenge}\n${keyId}\n${blinded}`,
  linkApprove: (cardId: string, challenge: string, linkId: string) =>
    `v18-link-approve\n${cardId}\n${challenge}\n${linkId}`,
  cardDelete: (cardId: string, challenge: string) => `v18-card-delete\n${cardId}\n${challenge}`,
};

export async function issueTestCard(
  base: string,
  device: TestDevice,
  proof: Record<string, unknown> = { testSubjectId: `subject-${crypto.randomUUID()}`, birthDate: '1990-05-15' }
): Promise<ApiResult> {
  const challenge = await newChallenge(base);
  return api(base, 'POST', '/v1/card/issue', {
    method: 'test_dev',
    challenge,
    devicePublicKey: device.jwkWithAlg,
    deviceSignature: device.sign(ss.cardIssue(challenge, device.thumbprint)),
    proof,
  });
}

// ---- Tickets (what the app does with RFC 9474) -------------------------------

export interface Jwk {
  kty: 'RSA';
  kid: string;
  n: string;
  e: string;
  alg: string;
  use: string;
  v18_min_age: number;
  nbf: number;
  exp: number;
}

export async function getJwks(base: string): Promise<Jwk[]> {
  return (await api(base, 'GET', '/v1/keys')).body.keys as Jwk[];
}

export function currentKey(keys: Jwk[], minAge: number, nowSec: number): Jwk {
  const k = keys.find((x) => x.v18_min_age === minAge && x.nbf <= nowSec && nowSec < x.exp);
  if (!k) throw new Error(`no current key for ${minAge}`);
  return k;
}

/** Imports only {kty, n, e}. WebCrypto refuses the JWK if "alg" is not a WebCrypto name. */
export async function importTicketKey(jwk: Jwk): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e }, { name: 'RSA-PSS', hash: 'SHA-384' }, true, [
    'verify',
  ]);
}

export interface Blinded {
  prepared: Uint8Array;
  inv: Uint8Array;
  blindedMessage: string;
  publicKey: CryptoKey;
}

export async function blindTicket(jwk: Jwk, payload: Record<string, unknown>): Promise<Blinded> {
  const suite = RSABSSA.SHA384.PSS.Randomized();
  const publicKey = await importTicketKey(jwk);
  const prepared = suite.prepare(new TextEncoder().encode(JSON.stringify(payload)));
  const { blindedMsg, inv } = await suite.blind(publicKey, prepared);
  return { prepared, inv, blindedMessage: Buffer.from(blindedMsg).toString('base64url'), publicKey };
}

export function ticketPayload(origin: string, siteChallenge: string, nowSec: number, minAge = 18) {
  return {
    v: 1,
    ticketId: crypto.randomBytes(16).toString('base64url'),
    origin,
    challenge: siteChallenge,
    minAge,
    iat: nowSec,
    expiresAt: nowSec + 300,
  };
}

export async function requestBlindSignature(
  base: string,
  cardId: string,
  device: TestDevice,
  keyId: string,
  blindedMessage: string,
  opts: { raw?: boolean; challenge?: string } = {}
): Promise<ApiResult> {
  const challenge = opts.challenge ?? (await newChallenge(base));
  return api(base, 'POST', '/v1/ticket/blind-sign', {
    cardId,
    challenge,
    keyId,
    blindedMessage,
    deviceSignature: device.sign(ss.ticket(cardId, challenge, keyId, blindedMessage), { raw: opts.raw }),
  });
}

/** Full app flow: blind, ask the server, finalize. Returns the ticket string. */
export async function makeTicket(
  srv: TestServer,
  cardId: string,
  device: TestDevice,
  site: { origin: string; challenge: string; minAge?: number },
  opts: { raw?: boolean } = {}
): Promise<string> {
  const nowSec = Math.floor(srv.clock.now() / 1000);
  const jwk = currentKey(await getJwks(srv.url), site.minAge ?? 18, nowSec);
  const b = await blindTicket(jwk, ticketPayload(site.origin, site.challenge, nowSec, site.minAge ?? 18));
  const r = await requestBlindSignature(srv.url, cardId, device, jwk.kid, b.blindedMessage, opts);
  if (r.status !== 200) throw new Error(`blind-sign failed: ${r.status} ${JSON.stringify(r.body)}`);
  const suite = RSABSSA.SHA384.PSS.Randomized();
  const sig = await suite.finalize(b.publicKey, b.prepared, Buffer.from(r.body.blindSignature, 'base64url'), b.inv);
  return `${r.body.keyId}.${Buffer.from(b.prepared).toString('base64url')}.${Buffer.from(sig).toString('base64url')}`;
}

// ---- TEST-ONLY reference verifier (protocol 3.7) -----------------------------
// The real website libraries live in sdk-web/. This copy exists only so the
// server tests can prove that the tickets it helps make pass all 8 rules.

export type VerifyResult = { ok: true; payload: any } | { ok: false; rule: number; why: string };

export function referenceVerifyTicket(
  ticket: string,
  jwks: Jwk[],
  expected: { origin: string; challenge: string; minAge: number },
  nowSec: number,
  seenTicketIds: Set<string>
): VerifyResult {
  const parts = ticket.split('.');
  if (parts.length !== 3) return { ok: false, rule: 1, why: 'format' };
  const [kid, preparedB64, sigB64] = parts;
  const key = jwks.find((k) => k.kid === kid);
  if (!key || nowSec > key.exp + 600) return { ok: false, rule: 1, why: 'unknown or old key' };
  const prepared = Buffer.from(preparedB64, 'base64url');
  const pub = crypto.createPublicKey({ key: { kty: 'RSA', n: key.n, e: key.e }, format: 'jwk' });
  const sigOk = crypto.verify(
    'sha384',
    prepared,
    { key: pub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48, mgf1HashAlgorithm: 'sha384' } as any,
    Buffer.from(sigB64, 'base64url')
  );
  if (!sigOk) return { ok: false, rule: 2, why: 'signature' };
  let payload: any;
  try {
    payload = JSON.parse(prepared.subarray(32).toString('utf8'));
  } catch {
    return { ok: false, rule: 3, why: 'payload not JSON' };
  }
  if (payload.v !== 1) return { ok: false, rule: 3, why: 'v' };
  if (payload.origin !== expected.origin) return { ok: false, rule: 4, why: 'origin' };
  if (payload.challenge !== expected.challenge) return { ok: false, rule: 5, why: 'challenge' };
  if (key.v18_min_age < expected.minAge) return { ok: false, rule: 6, why: 'age' };
  if (!(payload.iat - 60 <= nowSec && nowSec <= payload.expiresAt + 60) || payload.expiresAt - payload.iat > 300) {
    return { ok: false, rule: 7, why: 'time' };
  }
  if (seenTicketIds.has(payload.ticketId)) return { ok: false, rule: 8, why: 'replay' };
  seenTicketIds.add(payload.ticketId);
  return { ok: true, payload };
}
