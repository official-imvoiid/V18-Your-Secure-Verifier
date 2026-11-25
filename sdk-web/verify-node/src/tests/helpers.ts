// Test helpers: real RFC 9474 blind signing with @cloudflare/blindrsa-ts, plus a mock V18 JWKS server.
import * as crypto from 'node:crypto';
import * as http from 'node:http';
import { AddressInfo } from 'node:net';
import { RSABSSA } from '@cloudflare/blindrsa-ts';

export const ORIGIN = 'https://example-site.test';
export const NOW = 1_762_700_000; // fixed test clock, epoch seconds

export const suite = RSABSSA.SHA384.PSS.Randomized();

export interface TestKey {
  kid: string;
  pair: CryptoKeyPair;
  jwk: Record<string, unknown>;
  nodePrivate: crypto.KeyObject;
}

export async function makeKey(
  kid: string,
  meta: { minAge?: number; nbf?: number; exp?: number; alg?: string; omit?: string[] } = {}
): Promise<TestKey> {
  const pair = await suite.generateKey({ modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) });
  const pub = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as any;
  const jwk: Record<string, unknown> = {
    kid,
    kty: 'RSA',
    n: pub.n,
    e: pub.e,
    use: 'sig',
    alg: meta.alg ?? 'RSABSSA-SHA384-PSS-Randomized',
    v18_min_age: meta.minAge ?? 18,
    nbf: meta.nbf ?? NOW - 86_400,
    exp: meta.exp ?? NOW + 6 * 86_400,
  };
  for (const k of meta.omit ?? []) delete jwk[k];
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  const nodePrivate = crypto.createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
  return { kid, pair, jwk, nodePrivate };
}

export function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function newTicketId(): string {
  return b64u(crypto.randomBytes(16));
}

export function payload(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    ticketId: newTicketId(),
    origin: ORIGIN,
    challenge: 'a'.repeat(64),
    minAge: 18,
    iat: NOW,
    expiresAt: NOW + 300,
    ...over,
  };
}

/** The real client flow: prepare, blind, (server) blind-sign, finalize. */
export async function blindTicket(key: TestKey, body: Record<string, unknown> | Uint8Array): Promise<string> {
  const msg = body instanceof Uint8Array ? body : new TextEncoder().encode(JSON.stringify(body));
  const prepared = suite.prepare(msg);
  const { blindedMsg, inv } = await suite.blind(key.pair.publicKey, prepared);
  const blindSig = await suite.blindSign(key.pair.privateKey, blindedMsg);
  const sig = await suite.finalize(key.pair.publicKey, prepared, blindSig, inv);
  return `${key.kid}.${b64u(prepared)}.${b64u(sig)}`;
}

/** A plain RSA-PSS signature over 32 random bytes + body (same bytes a blind flow gives). For odd cases. */
export function directTicket(
  key: TestKey,
  body: Record<string, unknown> | Uint8Array,
  opts: { saltLength?: number; kid?: string; hash?: string } = {}
): string {
  const msg = body instanceof Uint8Array ? body : Buffer.from(JSON.stringify(body), 'utf8');
  const prepared = Buffer.concat([crypto.randomBytes(32), msg]);
  const sig = crypto.sign(opts.hash ?? 'sha384', prepared, {
    key: key.nodePrivate,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: opts.saltLength ?? 48,
  });
  return `${opts.kid ?? key.kid}.${b64u(prepared)}.${b64u(sig)}`;
}

/** A tiny stand-in for the V18 server's GET /v1/keys. */
export async function mockJwksServer(initial: { keys: unknown[] }) {
  let jwks: any = initial;
  let status = 200;
  let hits = 0;
  const server = http.createServer((req, res) => {
    if (req.url === '/v1/keys') {
      hits++;
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(status === 200 ? JSON.stringify(jwks) : JSON.stringify({ error: 'down', code: 'DOWN' }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    get hits() {
      return hits;
    },
    setJwks(next: any) {
      jwks = next;
    },
    setStatus(s: number) {
      status = s;
    },
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
