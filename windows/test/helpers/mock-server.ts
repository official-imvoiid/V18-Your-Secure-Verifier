// A small in-process V18 server that follows PROTOCOL.md protocol v1, for tests only.
// It checks challenges, device signatures over the exact signing strings, card state, and
// RFC 9474 blind signing with @cloudflare/blindrsa-ts. It is NOT the real server (server/).

import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { createHash, createPublicKey, randomBytes, verify, webcrypto } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';

const anonAadhaarHash = (signal: string): string => (createRequire(import.meta.url)('@anon-aadhaar/core') as { hash(m: string): string }).hash(signal);

type Jwk = Record<string, string>;
interface CardRec {
  cardId: string;
  jwk: Jwk;
  alg: string;
  method: string;
  validUntil: string;
  status: 'active' | 'revoked';
}

function b64u(b: Uint8Array): string {
  return Buffer.from(b).toString('base64url');
}

function thumbprint(jwk: Jwk): string {
  const c = jwk.kty === 'RSA' ? `{"e":"${jwk.e}","kty":"RSA","n":"${jwk.n}"}` : `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
  return createHash('sha256').update(c).digest('base64url');
}

function checkSig(jwk: Jwk, alg: string, data: string, sigB64: string): boolean {
  try {
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    const sig = Buffer.from(sigB64, 'base64url');
    if (alg === 'RS256' && jwk.kty === 'RSA') return verify('sha256', Buffer.from(data), key, sig);
    if (alg === 'ES256' && jwk.kty === 'EC') {
      return verify('sha256', Buffer.from(data), { key, dsaEncoding: sig.length === 64 ? 'ieee-p1363' : 'der' }, sig);
    }
  } catch {
    /* fall through */
  }
  return false;
}

export interface MockServer {
  url: string; // base URL with /v1
  origin: string;
  devMode: boolean;
  issuerJwk: Jwk & { kid: string };
  cards: Map<string, CardRec>;
  links: Map<string, { jwk: Jwk; alg: string; status: 'waiting' | 'approved' | 'expired'; card?: CardRec; delivered: boolean; expiresAt: number }>;
  sessions: Map<string, { origin: string; challenge: string; minAge: number; status: string; ticket?: string }>;
  calls: string[];
  /** Anon Aadhaar proofs the mock accepted (it checks the binding, not the zero-knowledge maths). */
  aadhaarProofs: unknown[];
  /** Break the next artifact download after this many bytes (to test resuming). */
  breakNextDownloadAt: number | null;
  /** Simulate the phone approving a device link (3.9 step 2-3). */
  approveLink(linkId: string): void;
  createSession(origin: string, challenge: string, minAge?: number): { sessionId: string; deepLink: string };
  close(): Promise<void>;
}

export const MOCK_NULLIFIER_SEED = '180018001800180018';

export async function startMockServer(
  opts: {
    devMode?: boolean;
    port?: number;
    artifacts?: Record<string, Buffer>;
    aadhaar?: 'ready' | 'not_configured';
    /** GET /v1/catalog answers with this (filtered by ?platform= the strict way: methods for other platforms are dropped). */
    catalog?: unknown;
    /** Birth date the mock login provider reports (YYYY-MM-DD). Default: an adult. */
    connectorBirthDate?: string;
    /** Make connect/start answer with this authUrl instead (to test refusals). */
    connectAuthUrl?: string;
  } = {},
): Promise<MockServer> {
  const suite = RSABSSA.SHA384.PSS.Randomized();
  const kp = await suite.generateKey({ modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) });
  const pub = (await webcrypto.subtle.exportKey('jwk', kp.publicKey as webcrypto.CryptoKey)) as Jwk;
  const now = Math.floor(Date.now() / 1000);
  const kid = 'v18-age18-20261109';
  const issuerJwk = { kid, kty: 'RSA', n: pub.n, e: pub.e };
  const challenges = new Map<string, number>();
  const cards = new Map<string, CardRec>();
  const links: MockServer['links'] = new Map();
  const sessions: MockServer['sessions'] = new Map();
  const calls: string[] = [];
  const devMode = opts.devMode ?? true;
  const aadhaarProofs: unknown[] = [];
  const nullifierUse = new Map<string, number>();
  const state = { breakNextDownloadAt: null as number | null };
  const artifacts = opts.artifacts ?? {};
  const aadhaar = opts.aadhaar ?? (Object.keys(artifacts).length ? 'ready' : 'not_configured');
  const connects = new Map<string, { id: string; jwk: Jwk; alg: string; status: string; card?: CardRec }>();

  const takeChallenge = (c: unknown) => {
    if (typeof c !== 'string' || !challenges.has(c) || challenges.get(c)! < Date.now()) return false;
    challenges.delete(c);
    return true;
  };

  const newCard = (jwk: Jwk, alg: string, method: string, days: number): CardRec => {
    const rec: CardRec = { cardId: 'card_' + b64u(randomBytes(16)), jwk, alg, method, validUntil: new Date(Date.now() + days * 86400000).toISOString(), status: 'active' };
    cards.set(rec.cardId, rec);
    return rec;
  };
  const cardJson = (c: CardRec) => ({ cardId: c.cardId, method: c.method, assuranceLevel: c.method, minAgeCertified: 18, validUntil: c.validUntil });

  let base = '';
  const baseOrigin = () => base.replace(/\/v1$/, '');
  const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    const fail = (status: number, code: string, error = code) => send(status, { error, code });
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    let body: Record<string, any> = {};
    try {
      body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
    } catch {
      return fail(400, 'BAD_JSON');
    }
    const url = new URL(req.url ?? '/', 'http://x');
    const path = url.pathname.replace(/^\/v1/, '');
    calls.push(`${req.method} ${path}`);
    let m: RegExpExecArray | null;

    if (req.method === 'GET' && path === '/health') {
      return send(200, { status: 'ok', devMode, methods: { test_dev: devMode ? 'ready' : 'disabled', anon_aadhaar: aadhaar }, aadhaarNullifierSeed: MOCK_NULLIFIER_SEED });
    }
    if (req.method === 'GET' && path === '/catalog') {
      if (!opts.catalog) return fail(404, 'NOT_FOUND');
      const platform = url.searchParams.get('platform');
      const cat = JSON.parse(JSON.stringify(opts.catalog)) as { countries: { methods: { platforms: string[] }[] }[] };
      if (platform) for (const c of cat.countries) c.methods = c.methods.filter((m) => m.platforms.includes(platform));
      return send(200, cat);
    }
    if ((m = /^\/connect\/([a-z0-9_]+)\/start$/.exec(path)) && req.method === 'POST') {
      const { challenge, devicePublicKey, deviceSignature } = body;
      if (!takeChallenge(challenge)) return fail(401, 'CHALLENGE_INVALID');
      const { alg, ...jwk } = devicePublicKey ?? {};
      if (!checkSig(jwk, alg, `v18-card-issue\n${challenge}\n${thumbprint(jwk)}`, deviceSignature?.sig)) return fail(401, 'BAD_DEVICE_SIGNATURE');
      const state = b64u(randomBytes(24));
      connects.set(state, { id: m[1], jwk, alg, status: 'waiting' });
      const authUrl = opts.connectAuthUrl ?? `${baseOrigin()}/mock-provider/${m[1]}/authorize?state=${state}&client_id=v18-test`;
      return send(201, { authUrl, state, expiresIn: 600 });
    }
    if ((m = /^\/connect\/session\/([^/]+)$/.exec(path)) && req.method === 'GET') {
      const c = connects.get(m[1]);
      if (!c) return fail(404, 'NOT_FOUND');
      return send(200, { status: c.status, card: c.card ? cardJson(c.card) : undefined });
    }
    if ((m = /^\/connect\/([a-z0-9_]+)\/callback$/.exec(path)) && req.method === 'GET') {
      // The provider sent the browser back. The real server reads the birth date here, decides
      // "18+", keeps nothing else, and issues the card bound to the device key.
      const state = url.searchParams.get('state') ?? '';
      const c = connects.get(state);
      if (!c || c.id !== m[1]) return fail(400, 'BAD_STATE');
      const birth = opts.connectorBirthDate ?? '1990-01-01';
      const adult = new Date().getUTCFullYear() - Number(birth.slice(0, 4)) > 18;
      let to: string;
      if (adult) {
        c.card = newCard(c.jwk, c.alg, `connector:${c.id}`, 180);
        c.status = 'ok';
        to = `v18://connect?status=ok&cardId=${c.card.cardId}&state=${state}`;
      } else {
        c.status = 'under_age';
        to = `v18://connect?status=under_age&state=${state}`;
      }
      res.writeHead(302, { location: to });
      return res.end();
    }
    if (req.method === 'GET' && (m = /^\/mock-provider\/([a-z0-9_]+)\/authorize$/.exec(url.pathname))) {
      // TEST ONLY: a provider that "signs the person in" at once and sends them back.
      res.writeHead(302, { location: `${base}/connect/${m[1]}/callback?state=${encodeURIComponent(url.searchParams.get('state') ?? '')}&code=test-code` });
      return res.end();
    }
    if (req.method === 'GET' && path === '/artifacts/manifest') {
      if (!Object.keys(artifacts).length) return fail(404, 'NOT_FOUND');
      return send(
        200,
        Object.entries(artifacts).map(([name, b]) => ({ name, sha256: createHash('sha256').update(b).digest('hex'), bytes: b.length, url: `/v1/artifacts/${name}` })),
      );
    }
    if ((m = /^\/artifacts\/([^/]+)$/.exec(path)) && req.method === 'GET') {
      const file = artifacts[decodeURIComponent(m[1])];
      if (!file) return fail(404, 'NOT_FOUND');
      const range = /^bytes=(\d+)-$/.exec(String(req.headers.range ?? ''));
      const start = range ? Number(range[1]) : 0;
      const part = file.subarray(start);
      res.writeHead(range ? 206 : 200, { 'content-type': 'application/octet-stream', 'content-length': String(part.length) });
      const cut = state.breakNextDownloadAt;
      if (cut !== null && cut < part.length) {
        state.breakNextDownloadAt = null;
        res.write(part.subarray(0, cut));
        setTimeout(() => res.destroy(), 20);
        return;
      }
      return res.end(part);
    }
    if (req.method === 'GET' && path === '/keys') {
      return send(200, { keys: [{ ...issuerJwk, use: 'sig', alg: 'RSABSSA-SHA384-PSS-Randomized', v18_min_age: 18, nbf: now - 3600, exp: now + 7 * 86400 }] });
    }
    if (req.method === 'POST' && path === '/challenge') {
      const c = randomBytes(32).toString('hex');
      challenges.set(c, Date.now() + 300000);
      return send(200, { challenge: c, expiresAt: new Date(Date.now() + 300000).toISOString() });
    }
    if (req.method === 'POST' && path === '/card/issue') {
      const { method, challenge, devicePublicKey, deviceSignature, proof } = body;
      if (!takeChallenge(challenge)) return fail(400, 'CHALLENGE_INVALID');
      const { alg, ...jwk } = devicePublicKey ?? {};
      if (!checkSig(jwk, alg, `v18-card-issue\n${challenge}\n${thumbprint(jwk)}`, deviceSignature?.sig) || deviceSignature?.alg !== alg) {
        return fail(401, 'BAD_DEVICE_SIGNATURE');
      }
      if (method === 'anon_aadhaar') {
        // The mock checks what the app controls: the proof is bound to this challenge and key,
        // uses the server's seed, and reveals only 18+. The real server also checks the Groth16 maths.
        const p = proof?.proof ?? {};
        const signal = '0x' + createHash('sha256').update(`${challenge}|${thumbprint(jwk)}`).digest('hex');
        // The fake proof builder echoes the signal; a real proof carries Anon Aadhaar's hash(signal).
        if (p.signalHash !== signal && p.signalHash !== anonAadhaarHash(signal)) return fail(400, 'PROOF_INVALID', 'signal mismatch');
        if (p.nullifierSeed !== MOCK_NULLIFIER_SEED) return fail(400, 'PROOF_INVALID', 'wrong nullifier seed');
        if (p.gender !== '0' || p.pincode !== '0' || p.state !== '0') return fail(400, 'PROOF_INVALID', 'reveals too much');
        if (p.ageAbove18 !== '1') return fail(403, 'UNDER_AGE', 'under 18');
        const used = nullifierUse.get(p.nullifier) ?? 0;
        if (used >= 3) return fail(409, 'NULLIFIER_OVERUSED', 'too many cards');
        nullifierUse.set(p.nullifier, used + 1);
        aadhaarProofs.push(proof);
        return send(201, cardJson(newCard(jwk, alg, 'anon_aadhaar', 180)));
      }
      if (method !== 'test_dev') return fail(501, 'METHOD_NOT_READY');
      if (!devMode) return fail(501, 'METHOD_DISABLED');
      const year = Number(String(proof?.birthDate ?? '').slice(0, 4));
      if (!year || new Date().getUTCFullYear() - year < 18) return fail(403, 'UNDER_AGE', 'The test subject is under 18');
      return send(201, cardJson(newCard(jwk, alg, 'test_dev', 30)));
    }
    if ((m = /^\/card\/([^/]+)\/status$/.exec(path)) && req.method === 'GET') {
      const c = cards.get(m[1]);
      if (!c) return fail(404, 'CARD_NOT_FOUND');
      return send(200, { status: c.status, validUntil: c.validUntil });
    }
    if ((m = /^\/card\/([^/]+)$/.exec(path)) && req.method === 'DELETE' && m[1] !== 'link') {
      const c = cards.get(m[1]);
      if (!c || c.status !== 'active') return fail(404, 'CARD_NOT_FOUND');
      if (!takeChallenge(body.challenge)) return fail(400, 'CHALLENGE_INVALID');
      if (!checkSig(c.jwk, c.alg, `v18-card-delete\n${c.cardId}\n${body.challenge}`, body.deviceSignature?.sig)) return fail(401, 'CARD_REQUIRED');
      c.status = 'revoked';
      return send(200, { status: 'revoked' });
    }
    if (req.method === 'POST' && path === '/card/link/start') {
      const { challenge, devicePublicKey, deviceSignature } = body;
      if (!takeChallenge(challenge)) return fail(400, 'CHALLENGE_INVALID');
      const { alg, ...jwk } = devicePublicKey ?? {};
      if (!checkSig(jwk, alg, `v18-card-issue\n${challenge}\n${thumbprint(jwk)}`, deviceSignature?.sig)) return fail(401, 'BAD_DEVICE_SIGNATURE');
      const linkId = 'lnk_' + b64u(randomBytes(16));
      links.set(linkId, { jwk, alg, status: 'waiting', delivered: false, expiresAt: Date.now() + 120000 });
      return send(201, { linkId, deepLink: `v18://link?id=${linkId}&server=${encodeURIComponent(base)}`, expiresIn: 120 });
    }
    if ((m = /^\/card\/link\/([^/]+)$/.exec(path)) && req.method === 'GET') {
      const l = links.get(m[1]);
      if (!l) return fail(404, 'LINK_NOT_FOUND');
      if (l.status === 'waiting' && Date.now() > l.expiresAt) l.status = 'expired';
      if (l.status === 'approved' && !l.delivered) {
        l.delivered = true;
        return send(200, { status: 'approved', card: cardJson(l.card!) });
      }
      return send(200, { status: l.status });
    }
    if (req.method === 'POST' && path === '/ticket/blind-sign') {
      const { cardId, challenge, keyId, blindedMessage, deviceSignature } = body;
      const c = cards.get(cardId);
      if (!c || c.status !== 'active' || Date.parse(c.validUntil) < Date.now()) return fail(401, 'CARD_REQUIRED');
      if (!takeChallenge(challenge)) return fail(400, 'CHALLENGE_INVALID');
      if (!checkSig(c.jwk, c.alg, `v18-ticket-request\n${cardId}\n${challenge}\n${keyId}\n${blindedMessage}`, deviceSignature?.sig)) {
        return fail(401, 'CARD_REQUIRED');
      }
      if (keyId !== kid) return fail(400, 'UNKNOWN_KEY');
      const blindSig = await suite.blindSign(kp.privateKey as CryptoKey, Buffer.from(blindedMessage, 'base64url'));
      return send(200, { blindSignature: b64u(blindSig), keyId: kid, algorithm: 'RSABSSA-SHA384-PSS-Randomized' });
    }
    if ((m = /^\/pairing\/([^/]+)$/.exec(path)) && req.method === 'GET') {
      const s = sessions.get(m[1]);
      if (!s) return fail(404, 'SESSION_NOT_FOUND');
      const out = { sessionId: m[1], status: s.status, origin: s.origin, challenge: s.challenge, minAge: s.minAge, ticket: s.ticket, expiresIn: 100 };
      if (s.ticket) s.ticket = undefined; // returned once
      return send(200, out);
    }
    if ((m = /^\/pairing\/([^/]+)\/(connect|submit|cancel)$/.exec(path)) && req.method === 'POST') {
      const s = sessions.get(m[1]);
      if (!s) return fail(404, 'SESSION_NOT_FOUND');
      if (m[2] === 'connect') {
        if (s.status !== 'waiting') return fail(409, 'BAD_STATE');
        s.status = 'connected';
        return send(200, { status: s.status });
      }
      if (m[2] === 'submit') {
        if (s.status !== 'waiting' && s.status !== 'connected') return fail(409, 'BAD_STATE');
        s.status = 'approved';
        s.ticket = body.ticket;
        return send(200, { status: s.status });
      }
      s.status = 'cancelled';
      return send(200, { status: s.status });
    }
    return fail(404, 'NOT_FOUND');
  });
  await new Promise<void>((r) => server.listen(opts.port ?? 0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  const origin = `http://127.0.0.1:${port}`;
  base = origin + '/v1';

  return {
    url: base,
    origin,
    devMode,
    issuerJwk,
    cards,
    links,
    sessions,
    calls,
    aadhaarProofs,
    get breakNextDownloadAt() {
      return state.breakNextDownloadAt;
    },
    set breakNextDownloadAt(v: number | null) {
      state.breakNextDownloadAt = v;
    },
    approveLink(linkId: string) {
      const l = links.get(linkId);
      if (!l) throw new Error('no such link');
      l.card = newCard(l.jwk, l.alg, 'device_link', 30);
      l.status = 'approved';
    },
    createSession(o: string, challenge: string, minAge = 18) {
      const sessionId = 'pair_' + b64u(randomBytes(16));
      sessions.set(sessionId, { origin: o, challenge, minAge, status: 'waiting' });
      return {
        sessionId,
        deepLink: `v18://verify?session=${sessionId}&origin=${encodeURIComponent(o)}&challenge=${encodeURIComponent(challenge)}&minAge=${minAge}&server=${encodeURIComponent(base)}`,
      };
    },
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
