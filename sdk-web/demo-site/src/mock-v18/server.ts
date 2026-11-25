/**
 * MOCK V18 SERVER. TEST ONLY. NOT THE REAL V18 SERVER (that lives in server/).
 *
 * A small stand-in that follows PROTOCOL.md so the web SDK's own tests run without the real
 * server. It is strict on purpose: it checks every device signature and signing
 * string, consumes every challenge, and refuses tickets without a card (401 CARD_REQUIRED).
 * It always runs in dev mode (test_dev only) and keeps everything in memory.
 * It also does phone wallet IDs (PROTOCOL.md 4c.5, `mdoc_wallet`) for real, but trusts only a
 * TEST IACA (made at start-up unless the caller passes its own).
 *
 *   npm run mock-v18      (port 8080 by default; V18_MOCK_PORT to change)
 */
import * as crypto from 'node:crypto';
import * as http from 'node:http';
import express, { Request, Response } from 'express';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { WalletCheckError, WalletRequestState, buildWalletRequest, verifyWalletAnswer } from './wallet.js';
import { createTestIssuer, TestIssuer } from '../wallet-test/test-iaca.js';

const ALG = 'RSABSSA-SHA384-PSS-Randomized';
const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');
const fromB64u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

export interface MockV18 {
  url: string;
  server: http.Server;
  close(): Promise<void>;
  stats: { cardsIssued: number; ticketsSigned: number; walletAnswersAccepted: number; refusals: Record<string, number> };
  /** Change which key is "current" (tests key rotation in clients). */
  keyId: string;
  /** The TEST issuer whose IACA this mock trusts for wallet answers (when it made its own). */
  walletIssuer: TestIssuer | null;
}

export interface MockV18Options {
  /** IACA certificates (PEM) to trust for wallet answers. Default: a TEST IACA made at start-up. */
  trustedIacaPems?: string[];
}

function ecThumbprint(jwk: any): string {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

function verifyEs256(jwk: any, text: string, sigB64: string): boolean {
  try {
    const key = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
    const sig = Buffer.from(sigB64, 'base64url');
    const dsaEncoding = sig.length === 64 ? 'ieee-p1363' : 'der';
    return crypto.verify('sha256', Buffer.from(text, 'utf8'), { key, dsaEncoding }, sig);
  } catch {
    return false;
  }
}

function ageOn(birth: string, now = new Date()): number {
  const [y, m, d] = birth.split('-').map(Number);
  let age = now.getUTCFullYear() - y;
  if (now.getUTCMonth() + 1 < m || (now.getUTCMonth() + 1 === m && now.getUTCDate() < d)) age--;
  return age;
}

export async function startMockV18(port = 0, host = '127.0.0.1', options: MockV18Options = {}): Promise<MockV18> {
  const suite = RSABSSA.SHA384.PSS.Randomized();
  const pair = await suite.generateKey({ modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) });
  const pub: any = await crypto.webcrypto.subtle.exportKey('jwk', pair.publicKey as any);
  const today = new Date();
  const ymd = `${today.getUTCFullYear()}${String(today.getUTCMonth() + 1).padStart(2, '0')}${String(today.getUTCDate()).padStart(2, '0')}`;
  const nbf = Math.floor(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()) / 1000);
  // "mock" in the key ID so a site never confuses a cached mock key with a real V18 key of the same date.
  const keyId = `v18mock-age18-${ymd}`;
  const jwk = { kid: keyId, kty: 'RSA', n: pub.n, e: pub.e, use: 'sig', alg: ALG, v18_min_age: 18, nbf, exp: nbf + 7 * 86400 };

  const challenges = new Map<string, number>();
  const cards = new Map<string, { jwk: any; status: 'active' | 'revoked'; validUntil: number; nullifier: string; minAge: number }>();
  const pairings = new Map<string, { origin: string; challenge: string; minAge: number; status: string; ticket?: string; delivered: boolean; expiresAt: number; submitted: boolean; wallet?: WalletRequestState }>();
  const stats = { cardsIssued: 0, ticketsSigned: 0, walletAnswersAccepted: 0, refusals: {} as Record<string, number> };
  const walletIssuer = options.trustedIacaPems ? null : await createTestIssuer({ label: 'V18 MOCK TEST IACA (test only)' });
  const trustedIacaPems = options.trustedIacaPems ?? [walletIssuer!.iacaPem];

  const app = express();
  app.use(express.json({ limit: '64kb' }));
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    next();
  });

  const err = (res: Response, status: number, code: string, error: string) => {
    stats.refusals[code] = (stats.refusals[code] ?? 0) + 1;
    res.status(status).json({ error, code });
  };
  const takeChallenge = (c: unknown): boolean => {
    if (typeof c !== 'string') return false;
    const exp = challenges.get(c);
    challenges.delete(c);
    return exp !== undefined && exp > Date.now();
  };

  const r = express.Router();
  r.get('/health', (_req, res) =>
    res.json({
      status: 'ok',
      service: 'v18-mock-server (TEST ONLY)',
      version: 'mock',
      devMode: true,
      methods: { test_dev: 'ready', mdoc_wallet: 'ready' },
    })
  );
  r.get('/keys', (_req, res) => res.json({ keys: [jwk] }));
  r.post('/challenge', (_req, res) => {
    const challenge = crypto.randomBytes(32).toString('hex');
    challenges.set(challenge, Date.now() + 300_000);
    res.json({ challenge, expiresAt: new Date(Date.now() + 300_000).toISOString() });
  });

  r.post('/card/issue', (req, res) => {
    const { method, challenge, devicePublicKey, deviceSignature, proof } = req.body ?? {};
    if (method !== 'test_dev') return err(res, 501, 'METHOD_NOT_READY', 'The mock only knows test_dev');
    if (!takeChallenge(challenge)) return err(res, 400, 'CHALLENGE_INVALID', 'Unknown, used or expired challenge');
    if (devicePublicKey?.kty !== 'EC' || devicePublicKey?.crv !== 'P-256' || devicePublicKey?.alg !== 'ES256' || deviceSignature?.alg !== 'ES256')
      return err(res, 400, 'BAD_DEVICE_KEY', 'Device key must be ES256 P-256');
    const thumb = ecThumbprint(devicePublicKey);
    if (!verifyEs256(devicePublicKey, `v18-card-issue\n${challenge}\n${thumb}`, deviceSignature.sig))
      return err(res, 401, 'BAD_DEVICE_SIGNATURE', 'Proof of possession failed');
    if (typeof proof?.testSubjectId !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(proof?.birthDate ?? ''))
      return err(res, 400, 'BAD_PROOF', 'test_dev needs testSubjectId and birthDate');
    if (ageOn(proof.birthDate) < 18) return err(res, 403, 'UNDER_AGE', 'The test birth date is under 18');
    const nullifier = crypto.createHash('sha256').update(`mock|${proof.testSubjectId}`).digest('hex');
    const active = [...cards.values()].filter((c) => c.nullifier === nullifier && c.status === 'active').length;
    if (active >= 3) return err(res, 409, 'NULLIFIER_OVERUSED', 'Too many active cards for this ID');
    const cardId = `card_${b64u(crypto.randomBytes(16))}`;
    const validUntil = Date.now() + 30 * 86400_000;
    cards.set(cardId, { jwk: devicePublicKey, status: 'active', validUntil, nullifier, minAge: 18 });
    stats.cardsIssued++;
    res.status(201).json({ cardId, method: 'test_dev', assuranceLevel: 'test', minAgeCertified: 18, validUntil: new Date(validUntil).toISOString() });
  });

  r.get('/card/:id/status', (req, res) => {
    const c = cards.get(req.params.id);
    if (!c) return err(res, 404, 'CARD_NOT_FOUND', 'No such card');
    const status = c.status === 'revoked' ? 'revoked' : c.validUntil < Date.now() ? 'expired' : 'active';
    res.json({ status, validUntil: new Date(c.validUntil).toISOString() });
  });

  r.delete('/card/:id', (req, res) => {
    const c = cards.get(req.params.id);
    const { challenge, deviceSignature } = req.body ?? {};
    if (!c) return err(res, 404, 'CARD_NOT_FOUND', 'No such card');
    if (!takeChallenge(challenge)) return err(res, 400, 'CHALLENGE_INVALID', 'Unknown, used or expired challenge');
    if (!verifyEs256(c.jwk, `v18-card-delete\n${req.params.id}\n${challenge}`, deviceSignature?.sig ?? ''))
      return err(res, 401, 'BAD_DEVICE_SIGNATURE', 'Device signature failed');
    c.status = 'revoked';
    res.json({ ok: true });
  });

  r.post('/ticket/blind-sign', async (req: Request, res: Response) => {
    const { cardId, challenge, keyId: kid, blindedMessage, deviceSignature } = req.body ?? {};
    const card = typeof cardId === 'string' ? cards.get(cardId) : undefined;
    if (!card || typeof deviceSignature?.sig !== 'string') return err(res, 401, 'CARD_REQUIRED', 'A valid card and device signature are required');
    if (!takeChallenge(challenge)) return err(res, 400, 'CHALLENGE_INVALID', 'Unknown, used or expired challenge');
    if (card.status !== 'active' || card.validUntil < Date.now()) return err(res, 401, 'CARD_REQUIRED', 'Card is not active');
    if (!verifyEs256(card.jwk, `v18-ticket-request\n${cardId}\n${challenge}\n${kid}\n${blindedMessage}`, deviceSignature.sig))
      return err(res, 401, 'CARD_REQUIRED', 'Device signature failed');
    if (kid !== jwk.kid) return err(res, 400, 'KEY_NOT_CURRENT', 'keyId is not the current key');
    if (jwk.v18_min_age > card.minAge) return err(res, 403, 'AGE_NOT_CERTIFIED', 'Card does not certify this age');
    try {
      const blindSig = await suite.blindSign(pair.privateKey, fromB64u(blindedMessage));
      stats.ticketsSigned++;
      res.json({ blindSignature: b64u(blindSig), keyId: jwk.kid, algorithm: ALG });
    } catch (e: any) {
      err(res, 400, 'BAD_BLINDED_MESSAGE', e.message);
    }
  });

  r.post('/pairing/session', (req, res) => {
    const { origin, challenge, minAge, ttlSeconds } = req.body ?? {};
    if (typeof origin !== 'string' || typeof challenge !== 'string') return err(res, 400, 'BAD_REQUEST', 'origin and challenge are required');
    const hdr = req.get('origin');
    if (hdr && hdr !== origin) return err(res, 403, 'ORIGIN_MISMATCH', 'Origin header does not match origin');
    const sessionId = `pair_${b64u(crypto.randomBytes(16))}`;
    const ttl = Math.min(Math.max(Number(ttlSeconds) || 120, 30), 300);
    const expiresAt = Date.now() + ttl * 1000;
    pairings.set(sessionId, { origin, challenge, minAge: Number(minAge) || 18, status: 'waiting', delivered: false, expiresAt, submitted: false });
    const base = `${req.protocol}://${req.get('host')}`;
    const deepLink = `v18://verify?session=${sessionId}&origin=${encodeURIComponent(origin)}&challenge=${encodeURIComponent(challenge)}&minAge=${Number(minAge) || 18}&server=${encodeURIComponent(base)}`;
    res.status(201).json({ sessionId, deepLink, qrData: deepLink, expiresAt: new Date(expiresAt).toISOString(), expiresIn: ttl, pollUrl: `/v1/pairing/${sessionId}` });
  });

  const live = (id: string) => {
    const p = pairings.get(id);
    if (p && p.expiresAt < Date.now() && p.status !== 'approved') p.status = 'expired';
    return p;
  };
  r.get('/pairing/:id', (req, res) => {
    const p = live(req.params.id);
    if (!p) return err(res, 404, 'PAIRING_NOT_FOUND', 'No such session');
    const body: any = { status: p.status, origin: p.origin, minAge: p.minAge };
    if (p.ticket && !p.delivered) {
      body.ticket = p.ticket;
      p.delivered = true;
      p.ticket = undefined; // returned once, then cleared
    }
    res.json(body);
  });
  r.post('/pairing/:id/connect', (req, res) => {
    const p = live(req.params.id);
    if (!p || p.status === 'expired' || p.status === 'cancelled') return err(res, 410, 'PAIRING_GONE', 'Session expired or cancelled');
    if (p.status === 'waiting') p.status = 'connected';
    res.json({ ok: true, origin: p.origin, challenge: p.challenge, minAge: p.minAge });
  });
  r.post('/pairing/:id/submit', (req, res) => {
    const p = live(req.params.id);
    if (!p || p.status === 'expired' || p.status === 'cancelled') return err(res, 410, 'PAIRING_GONE', 'Session expired or cancelled');
    if (p.submitted) return err(res, 409, 'ALREADY_SUBMITTED', 'A ticket was already submitted');
    if (typeof req.body?.ticket !== 'string') return err(res, 400, 'BAD_REQUEST', 'ticket is required');
    p.submitted = true;
    p.ticket = req.body.ticket;
    p.status = 'approved';
    res.json({ ok: true });
  });
  // ---- Phone wallet IDs (PROTOCOL.md 4c.5) ------------------------------------------------

  /** A normal ticket (PROTOCOL.md 3.6), made and signed here because the wallet answer was checked here. */
  async function makeTicket(p: { origin: string; challenge: string; minAge: number }): Promise<string> {
    const iat = Math.floor(Date.now() / 1000);
    const msg = JSON.stringify({ v: 1, ticketId: b64u(crypto.randomBytes(16)), origin: p.origin, challenge: p.challenge, minAge: p.minAge, iat, expiresAt: iat + 300 });
    const prepared = Buffer.concat([crypto.randomBytes(32), Buffer.from(msg, 'utf8')]);
    const sig = await crypto.webcrypto.subtle.sign({ name: 'RSA-PSS', saltLength: 48 }, pair.privateKey as any, prepared);
    stats.ticketsSigned++;
    return `${jwk.kid}.${b64u(prepared)}.${b64u(new Uint8Array(sig))}`;
  }

  const walletSession = (req: Request, res: Response) => {
    const id = req.body?.sessionId;
    const p = typeof id === 'string' ? live(id) : undefined;
    if (!p) {
      err(res, 404, 'SESSION_NOT_FOUND', 'Pairing session not found or expired');
      return null;
    }
    const hdr = req.get('origin');
    if (hdr && hdr !== p.origin) {
      err(res, 403, 'ORIGIN_MISMATCH', 'The Origin header does not match the session origin');
      return null;
    }
    if (p.status === 'expired') {
      err(res, 410, 'SESSION_EXPIRED', 'This request has expired');
      return null;
    }
    if (p.status !== 'waiting') {
      err(res, 409, 'WRONG_STATE', `The session is ${p.status}`);
      return null;
    }
    return p;
  };

  r.post('/wallet/request', (req, res) => {
    const p = walletSession(req, res);
    if (!p) return;
    if (p.minAge !== 18) return err(res, 400, 'MIN_AGE_UNSUPPORTED', 'Phone wallet IDs can only show 18+');
    const { request, state } = buildWalletRequest();
    p.wallet = state;
    res.json({ sessionId: req.body.sessionId, digital: { requests: [request] }, expiresAt: new Date(p.expiresAt).toISOString() });
  });

  r.post('/wallet/verify', async (req, res) => {
    const p = walletSession(req, res);
    if (!p) return;
    const state = p.wallet;
    if (!state) return err(res, 409, 'WALLET_NO_REQUEST', 'Ask for a wallet request first');
    if (state.used) return err(res, 409, 'WALLET_REQUEST_USED', 'This wallet request was already answered');
    state.used = true; // one answer per request, right or wrong
    try {
      await verifyWalletAnswer(state, p.origin, req.body?.response, trustedIacaPems);
    } catch (e: any) {
      if (e instanceof WalletCheckError) return err(res, e.status, e.code, e.message);
      return err(res, 400, 'WALLET_INVALID', 'The wallet answer could not be checked');
    }
    if (p.status !== 'waiting') return err(res, 409, 'WRONG_STATE', `The session is ${p.status}`);
    p.ticket = await makeTicket(p);
    p.submitted = true;
    p.status = 'approved';
    stats.walletAnswersAccepted++;
    res.json({ status: 'approved' });
  });

  r.post('/pairing/:id/cancel', (req, res) => {
    const p = pairings.get(req.params.id);
    if (!p) return err(res, 404, 'PAIRING_NOT_FOUND', 'No such session');
    if (p.status !== 'approved') p.status = 'cancelled';
    res.json({ ok: true });
  });

  app.use('/v1', r);

  const server = await new Promise<http.Server>((resolve) => {
    const s = app.listen(port, host, () => resolve(s));
  });
  const addr = server.address() as any;
  return {
    url: `http://${host === '0.0.0.0' ? 'localhost' : host}:${addr.port}`,
    server,
    stats,
    keyId,
    walletIssuer,
    close: () => new Promise<void>((res) => server.close(() => res())),
  };
}

if (require.main === module) {
  const port = process.env.V18_MOCK_PORT ? parseInt(process.env.V18_MOCK_PORT, 10) : 8080;
  startMockV18(port, 'localhost').then((m) => {
    console.log('====================================================');
    console.log('  MOCK V18 SERVER (TEST ONLY, NOT THE REAL SERVER)');
    console.log(`  ${m.url}/v1   devMode: true   key: ${m.keyId}`);
    console.log('  Phone wallet IDs: trusts only a TEST IACA made at start-up.');
    console.log('  In-memory. Restarting forgets every card.');
    console.log('====================================================');
  });
}
