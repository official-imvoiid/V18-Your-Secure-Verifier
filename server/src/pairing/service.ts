import { isWebOrigin } from '../config.js';
import { DocRepo } from '../db/state.js';
import { ApiError, badRequest } from '../errors.js';
import { RateLimiter } from '../tickets/rate-limit.js';
import { Clock, isPlainObject, randomId, systemClock } from '../util.js';
import type { WalletRequestState } from '../wallet/mdoc.js';

/**
 * QR hand-off relay (protocol 3.8): a website shows a QR, the phone (or the
 * Windows app) makes a ticket and drops it here, and the website's widget
 * picks it up by polling. A phone wallet (4c.5) can also fill the session.
 * Sessions are stored in the database (shared by all server copies) and
 * deleted a few minutes after they expire.
 */

export type PairingStatus = 'waiting' | 'connected' | 'approved' | 'expired' | 'cancelled';

export interface PairingSession {
  sessionId: string;
  origin: string;
  challenge: string;
  minAge: number;
  status: 'waiting' | 'connected' | 'approved' | 'cancelled';
  ticket?: string;
  ticketDelivered: boolean;
  createdAt: number;
  expiresAt: number;
  /** The open wallet request (one at a time), if any. */
  wallet?: WalletRequestState;
}

/** `pair_` + 16 random bytes (128 bits) in base64url. */
export const SESSION_ID_PATTERN = /^pair_[A-Za-z0-9_-]{22}$/;
/** PROTOCOL.md 4b item 15: an opaque string of 16 to 256 URL-safe (RFC 3986 unreserved) characters. */
const SITE_CHALLENGE = /^[A-Za-z0-9._~-]{16,256}$/;
const TICKET = /^[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{1,8192}\.[A-Za-z0-9_-]{1,1400}$/;
const KEEP_AFTER_EXPIRY_MS = 5 * 60_000;

export class PairingService {
  private readonly timer: NodeJS.Timeout;

  constructor(
    private readonly docs: DocRepo,
    private readonly perIp: RateLimiter,
    private readonly hashIp: (ip: string | undefined) => string,
    private readonly opts: { publicUrl: string; maxMinAge: number },
    private readonly clock: Clock = systemClock
  ) {
    this.timer = setInterval(() => {
      this.docs.prune(this.clock()).catch(() => undefined);
    }, 30_000);
    this.timer.unref();
  }

  /** POST /v1/pairing/session. Every call counts toward the per-IP limit. */
  async create(rawBody: unknown, originHeader: string | undefined, clientIp: string | undefined) {
    await this.perIp.takeOrThrow(this.hashIp(clientIp), 'Too many QR sessions from this network in the last minute. Try again soon.');
    const body = isPlainObject(rawBody) ? rawBody : {};
    const origin = body.origin;
    if (!isWebOrigin(origin)) {
      throw new ApiError(400, 'BAD_ORIGIN', 'origin must be a web origin like "https://site.example" (scheme://host[:port])');
    }
    if (originHeader !== undefined && originHeader !== origin) {
      throw new ApiError(403, 'ORIGIN_MISMATCH', 'The request Origin header does not match "origin"');
    }
    const challenge = body.challenge;
    if (typeof challenge !== 'string' || !SITE_CHALLENGE.test(challenge)) {
      throw badRequest(
        "challenge (the website's own challenge) is required: 16 to 256 URL-safe characters (A-Z a-z 0-9 - . _ ~)"
      );
    }
    const minAge = body.minAge === undefined ? 18 : Number(body.minAge);
    if (!Number.isInteger(minAge) || minAge < 1 || minAge > 99) {
      throw badRequest('minAge must be a whole number from 1 to 99');
    }
    if (minAge > this.opts.maxMinAge) {
      throw new ApiError(400, 'MIN_AGE_UNSUPPORTED', `This server has no ticket key for age ${minAge}+`);
    }
    let ttl = body.ttlSeconds === undefined ? 120 : Number(body.ttlSeconds);
    if (!Number.isFinite(ttl)) throw badRequest('ttlSeconds must be a number');
    ttl = Math.min(300, Math.max(30, Math.floor(ttl)));

    const now = this.clock();
    const session: PairingSession = {
      sessionId: randomId('pair'),
      origin,
      challenge,
      minAge,
      status: 'waiting',
      ticketDelivered: false,
      createdAt: now,
      expiresAt: now + ttl * 1000,
    };
    await this.docs.insert('pairing', session.sessionId, session, session.expiresAt + KEEP_AFTER_EXPIRY_MS);

    const deepLink =
      `v18://verify?session=${session.sessionId}` +
      `&origin=${encodeURIComponent(origin)}` +
      `&challenge=${encodeURIComponent(challenge)}` +
      `&minAge=${minAge}` +
      `&server=${encodeURIComponent(this.opts.publicUrl)}`;

    return {
      sessionId: session.sessionId,
      deepLink,
      qrData: deepLink,
      expiresAt: new Date(session.expiresAt).toISOString(),
      expiresIn: ttl,
      pollUrl: `/v1/pairing/${session.sessionId}`,
      origin,
      challenge,
      minAge,
    };
  }

  private notFound(): ApiError {
    return new ApiError(404, 'SESSION_NOT_FOUND', 'Pairing session not found or expired', { status: 'expired' });
  }

  /** The session or 404. */
  async get(sessionId: string): Promise<PairingSession> {
    const s = SESSION_ID_PATTERN.test(sessionId) ? await this.docs.get<PairingSession>('pairing', sessionId) : null;
    if (!s) throw this.notFound();
    return s;
  }

  statusOf(s: PairingSession): PairingStatus {
    if ((s.status === 'waiting' || s.status === 'connected') && this.clock() > s.expiresAt) return 'expired';
    return s.status;
  }

  /** Atomic change of one session (compare-and-set). `fn` may throw to refuse. */
  async change<R>(sessionId: string, fn: (s: PairingSession) => { value?: PairingSession; result: R }): Promise<R> {
    if (!SESSION_ID_PATTERN.test(sessionId)) throw this.notFound();
    return this.docs.update<PairingSession, R>('pairing', sessionId, (s) => {
      if (!s) throw this.notFound();
      return fn(s);
    });
  }

  /**
   * GET /v1/pairing/:id. A delivered ticket is returned ONCE, then cleared
   * (only the website's widget should poll).
   */
  async poll(sessionId: string) {
    return this.change(sessionId, (s) => {
      const status = this.statusOf(s);
      const out: Record<string, unknown> = {
        sessionId: s.sessionId,
        status,
        origin: s.origin,
        challenge: s.challenge,
        minAge: s.minAge,
        expiresAt: new Date(s.expiresAt).toISOString(),
        expiresIn: Math.max(0, Math.floor((s.expiresAt - this.clock()) / 1000)),
      };
      if (status !== 'approved') return { result: out };
      if (s.ticket) {
        out.ticket = s.ticket;
        return { value: { ...s, ticket: undefined, ticketDelivered: true }, result: out };
      }
      out.ticketDelivered = s.ticketDelivered;
      return { result: out };
    });
  }

  /** POST /v1/pairing/:id/connect (phone scanned the QR). */
  async connect(sessionId: string) {
    return this.change(sessionId, (s) => {
      const status = this.statusOf(s);
      if (status === 'expired') throw new ApiError(410, 'SESSION_EXPIRED', 'This QR code has expired');
      if (status !== 'waiting') throw new ApiError(409, 'WRONG_STATE', `Cannot connect: the session is ${status}`, { status });
      return { value: { ...s, status: 'connected' }, result: { success: true, status: 'connected' as const } };
    });
  }

  /** POST /v1/pairing/:id/submit {ticket}. Works once. */
  async submit(sessionId: string, rawBody: unknown) {
    const body = isPlainObject(rawBody) ? rawBody : {};
    const ticket = body.ticket;
    if (typeof ticket !== 'string' || !TICKET.test(ticket)) {
      // Unknown sessions still give 404 first, as before.
      await this.get(sessionId);
      throw new ApiError(400, 'BAD_TICKET', 'ticket must look like <keyId>.<base64url>.<base64url>');
    }
    return this.deliver(sessionId, ticket);
  }

  /** Puts a ticket on the session, once (used by submit and by the wallet). */
  async deliver(sessionId: string, ticket: string) {
    return this.change(sessionId, (s) => {
      const status = this.statusOf(s);
      if (status === 'approved') throw new ApiError(409, 'ALREADY_SUBMITTED', 'A ticket was already submitted for this session');
      if (status === 'expired') throw new ApiError(410, 'SESSION_EXPIRED', 'This QR code has expired');
      if (status === 'cancelled') throw new ApiError(409, 'WRONG_STATE', 'The session was cancelled', { status });
      return { value: { ...s, ticket, status: 'approved', wallet: undefined }, result: { success: true, status: 'approved' as const } };
    });
  }

  /** POST /v1/pairing/:id/cancel */
  async cancel(sessionId: string) {
    return this.change(sessionId, (s) => ({
      value: { ...s, status: 'cancelled', ticket: undefined, wallet: undefined },
      result: { success: true, status: 'cancelled' as const },
    }));
  }

  close(): void {
    clearInterval(this.timer);
  }
}
