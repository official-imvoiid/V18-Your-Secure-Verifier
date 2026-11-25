// Client for the V18 server, protocol version 1 (PROTOCOL.md 3). Runs only in the main process.
// It never logs request or response bodies.

import type { DeviceJwk } from './jwk.js';
import type { DeviceAlg, DeviceSignature } from './signing.js';

export class ApiError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

/** The server could not be reached at all (no internet, server down, timeout). */
export class OfflineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OfflineError';
  }
}

export interface Health {
  devMode: boolean;
  [k: string]: unknown;
}
export interface IssuerJwk {
  kid: string;
  kty: 'RSA';
  n: string;
  e: string;
  alg?: string;
  use?: string;
  v18_min_age?: number;
  nbf?: number;
  exp?: number;
}
export interface Challenge {
  challenge: string;
  expiresAt: string;
}
export interface Card {
  cardId: string;
  method: string;
  assuranceLevel?: string;
  minAgeCertified: number;
  validUntil: string;
}
export interface CardStatus {
  status: 'active' | 'revoked' | 'expired';
  validUntil?: string;
}
export interface LinkStart {
  linkId: string;
  deepLink: string;
  expiresIn: number;
}
export interface LinkPoll {
  status: 'waiting' | 'approved' | 'expired';
  card?: Card;
}
export interface BlindSignResult {
  blindSignature: string;
  keyId: string;
  algorithm: string;
}
export interface PairingSession {
  sessionId: string;
  status: string;
  origin: string;
  challenge: string;
  minAge: number;
  expiresIn?: number;
  [k: string]: unknown;
}

export type DevicePublicKey = DeviceJwk & { alg: DeviceAlg };

export interface ConnectStart {
  authUrl: string;
  state: string | null;
  expiresIn: number;
}
export interface ConnectSession {
  /** waiting, ok, under_age, failed, expired, cancelled (and close variants, see engine). */
  status: string;
  card?: Card;
  code?: string;
  error?: string;
  /** The server hands the card out once; later answers say this instead. */
  cardDelivered?: boolean;
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}
function str(v: unknown, what: string): string {
  if (typeof v !== 'string' || v.length === 0) throw new ApiError(502, 'BAD_RESPONSE', `server sent a bad ${what}`);
  return v;
}

function parseCard(v: unknown): Card {
  if (!isObj(v)) throw new ApiError(502, 'BAD_RESPONSE', 'server sent a bad card');
  const validUntil = str(v.validUntil, 'validUntil');
  if (Number.isNaN(Date.parse(validUntil))) throw new ApiError(502, 'BAD_RESPONSE', 'server sent a bad validUntil');
  return {
    cardId: str(v.cardId, 'cardId'),
    method: str(v.method, 'method'),
    assuranceLevel: typeof v.assuranceLevel === 'string' ? v.assuranceLevel : undefined,
    minAgeCertified: typeof v.minAgeCertified === 'number' ? v.minAgeCertified : 18,
    validUntil,
  };
}

export class V18Api {
  private readonly base: string;

  constructor(baseUrl: string, private readonly fetchImpl: FetchLike = (u, i) => fetch(u, i), private readonly timeoutMs = 15000) {
    this.base = baseUrl.replace(/\/+$/, '');
  }

  get baseUrl(): string {
    return this.base;
  }

  private async call(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown): Promise<unknown> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
    let res: Response;
    try {
      res = await this.fetchImpl(this.base + path, {
        method,
        headers: body === undefined ? { accept: 'application/json' } : { 'content-type': 'application/json', accept: 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: ctl.signal,
        redirect: 'error',
      });
    } catch (err) {
      throw new OfflineError(ctl.signal.aborted ? 'the server took too long to answer' : 'could not reach the server');
    } finally {
      clearTimeout(timer);
    }
    let data: unknown = null;
    const text = await res.text().catch(() => '');
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }
    }
    if (!res.ok) {
      const code = isObj(data) && typeof data.code === 'string' ? data.code : `HTTP_${res.status}`;
      const msg = isObj(data) && typeof data.error === 'string' ? data.error : `server answered ${res.status}`;
      throw new ApiError(res.status, code, msg);
    }
    return data;
  }

  async health(): Promise<Health> {
    const d = await this.call('GET', '/health');
    if (!isObj(d)) throw new ApiError(502, 'BAD_RESPONSE', 'bad health answer');
    return { ...d, devMode: d.devMode === true };
  }

  async keys(): Promise<IssuerJwk[]> {
    const d = await this.call('GET', '/keys');
    if (!isObj(d) || !Array.isArray(d.keys)) throw new ApiError(502, 'BAD_RESPONSE', 'bad JWKS');
    return d.keys.filter((k): k is IssuerJwk => isObj(k) && typeof k.kid === 'string' && k.kty === 'RSA' && typeof k.n === 'string' && typeof k.e === 'string');
  }

  async challenge(): Promise<Challenge> {
    const d = await this.call('POST', '/challenge', {});
    if (!isObj(d) || typeof d.challenge !== 'string' || !/^[0-9a-f]{64}$/i.test(d.challenge)) {
      throw new ApiError(502, 'BAD_RESPONSE', 'bad challenge');
    }
    return { challenge: d.challenge, expiresAt: String(d.expiresAt ?? '') };
  }

  async issueCard(body: {
    method: 'test_dev' | 'anon_aadhaar' | 'passport_zk';
    challenge: string;
    devicePublicKey: DevicePublicKey;
    deviceSignature: DeviceSignature;
    proof: unknown;
  }): Promise<Card> {
    return parseCard(await this.call('POST', '/card/issue', body));
  }

  async deleteCard(cardId: string, body: { challenge: string; deviceSignature: DeviceSignature }): Promise<void> {
    await this.call('DELETE', `/card/${encodeURIComponent(cardId)}`, body);
  }

  async cardStatus(cardId: string): Promise<CardStatus> {
    const d = await this.call('GET', `/card/${encodeURIComponent(cardId)}/status`);
    if (!isObj(d) || (d.status !== 'active' && d.status !== 'revoked' && d.status !== 'expired')) {
      throw new ApiError(502, 'BAD_RESPONSE', 'bad card status');
    }
    return { status: d.status, validUntil: typeof d.validUntil === 'string' ? d.validUntil : undefined };
  }

  async linkStart(body: { devicePublicKey: DevicePublicKey; challenge: string; deviceSignature: DeviceSignature }): Promise<LinkStart> {
    const d = await this.call('POST', '/card/link/start', body);
    if (!isObj(d)) throw new ApiError(502, 'BAD_RESPONSE', 'bad link answer');
    return { linkId: str(d.linkId, 'linkId'), deepLink: str(d.deepLink, 'deepLink'), expiresIn: typeof d.expiresIn === 'number' ? d.expiresIn : 120 };
  }

  async linkPoll(linkId: string): Promise<LinkPoll> {
    const d = await this.call('GET', `/card/link/${encodeURIComponent(linkId)}`);
    if (!isObj(d) || (d.status !== 'waiting' && d.status !== 'approved' && d.status !== 'expired')) {
      throw new ApiError(502, 'BAD_RESPONSE', 'bad link status');
    }
    return { status: d.status, card: d.card === undefined || d.card === null ? undefined : parseCard(d.card) };
  }

  async blindSign(body: { cardId: string; challenge: string; keyId: string; blindedMessage: string; deviceSignature: DeviceSignature }): Promise<BlindSignResult> {
    const d = await this.call('POST', '/ticket/blind-sign', body);
    if (!isObj(d)) throw new ApiError(502, 'BAD_RESPONSE', 'bad blind-sign answer');
    return { blindSignature: str(d.blindSignature, 'blindSignature'), keyId: str(d.keyId, 'keyId'), algorithm: str(d.algorithm, 'algorithm') };
  }

  /** GET /catalog (4d.2). The answer is checked by shared/catalog.ts. */
  async catalog(platform?: 'windows' | 'android'): Promise<unknown> {
    return this.call('GET', platform ? `/catalog?platform=${platform}` : '/catalog');
  }

  /** POST /connect/:id/start (4d.4). */
  async connectStart(id: string, body: { challenge: string; devicePublicKey: DevicePublicKey; deviceSignature: DeviceSignature }): Promise<ConnectStart> {
    const d = await this.call('POST', `/connect/${encodeURIComponent(id)}/start`, body);
    if (!isObj(d)) throw new ApiError(502, 'BAD_RESPONSE', 'bad connect answer');
    return {
      authUrl: str(d.authUrl, 'authUrl'),
      state: typeof d.state === 'string' && d.state ? d.state : null,
      expiresIn: typeof d.expiresIn === 'number' && d.expiresIn > 0 ? d.expiresIn : 600,
    };
  }

  /** GET /connect/session/:state (4d.4): the fallback when the v18://connect link doesn't arrive. */
  async connectSession(state: string): Promise<ConnectSession> {
    const d = await this.call('GET', `/connect/session/${encodeURIComponent(state)}`);
    if (!isObj(d)) throw new ApiError(502, 'BAD_RESPONSE', 'bad connect session answer');
    return {
      status: str(d.status, 'status').toLowerCase(),
      card: d.card === undefined || d.card === null ? undefined : parseCard(d.card),
      code: typeof d.code === 'string' ? d.code : undefined,
      error: typeof d.error === 'string' ? d.error : undefined,
      cardDelivered: d.cardDelivered === true,
    };
  }

  async pairingGet(sessionId: string): Promise<PairingSession> {
    const d = await this.call('GET', `/pairing/${encodeURIComponent(sessionId)}`);
    if (!isObj(d)) throw new ApiError(502, 'BAD_RESPONSE', 'bad pairing answer');
    return {
      ...d,
      sessionId: str(d.sessionId, 'sessionId'),
      status: str(d.status, 'status'),
      origin: str(d.origin, 'origin'),
      challenge: str(d.challenge, 'challenge'),
      minAge: typeof d.minAge === 'number' ? d.minAge : Number(d.minAge ?? 18),
    };
  }

  async pairingConnect(sessionId: string): Promise<void> {
    await this.call('POST', `/pairing/${encodeURIComponent(sessionId)}/connect`, {});
  }

  async pairingSubmit(sessionId: string, ticket: string): Promise<void> {
    await this.call('POST', `/pairing/${encodeURIComponent(sessionId)}/submit`, { ticket });
  }

  async pairingCancel(sessionId: string): Promise<void> {
    await this.call('POST', `/pairing/${encodeURIComponent(sessionId)}/cancel`, {});
  }
}
