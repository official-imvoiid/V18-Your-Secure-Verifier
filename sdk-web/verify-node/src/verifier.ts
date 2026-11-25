import * as crypto from 'node:crypto';
import { b64urlDecode, isBase64Url } from './b64.js';
import { RULES, VerifyErrorCode } from './errors.js';
import { JwksKeyStore } from './keys.js';
import { MemoryReplayCache, ReplayStore } from './replay-cache.js';

/** The signed ticket message (PROTOCOL.md 3.6). */
export interface TicketPayload {
  v: 1;
  ticketId: string;
  origin: string;
  challenge: string;
  /** What the app wrote. Informational only: authorization uses the key's v18_min_age. */
  minAge: number;
  iat: number;
  expiresAt: number;
}

/** What a website learns from a valid ticket. */
export interface VerifiedTicket {
  ticketId: string;
  origin: string;
  /** The age threshold certified by V18's signing key (its v18_min_age). */
  minAge: number;
  keyId: string;
  iat: number;
  expiresAt: number;
}

export type VerifyResult =
  | { valid: true; ticket: VerifiedTicket; payload: TicketPayload }
  | { valid: false; code: VerifyErrorCode; error: string };

/** A challenge string, or a function that checks (and should use up) the challenge in the ticket. */
export type ChallengeExpectation = string | ((challenge: string) => boolean | Promise<boolean>);

export interface VerifyOptions {
  /** The challenge your server issued for this visit. Required. */
  expectedChallenge?: ChallengeExpectation;
  /** Your site's web origin, e.g. "https://example.com". Defaults to the verifier's `origin`. */
  expectedOrigin?: string;
  /** Age your site needs. Defaults to the verifier's `minAge`, or 18. */
  minAge?: number;
}

export interface V18VerifierOptions {
  /** V18 server base URL, used to fetch the JWKS. Default "http://localhost:8080" (dev). */
  serverUrl?: string;
  /** Your site's web origin, used when verifyTicket is not given one. */
  origin?: string;
  /** Default required age. Default 18. */
  minAge?: number;
  keyStore?: JwksKeyStore;
  /** Old name for keyStore. */
  keyCache?: JwksKeyStore;
  replayCache?: ReplayStore;
  /** For tests. Returns epoch milliseconds. */
  clock?: () => number;
}

function fail(code: VerifyErrorCode, error: string): VerifyResult {
  return { valid: false, code, error };
}

function isInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v);
}

/** True if `s` is exactly a web origin such as "https://example.com" or "http://localhost:3000". */
export function isWebOrigin(s: unknown): s is string {
  if (typeof s !== 'string' || s.length === 0) return false;
  try {
    const u = new URL(s);
    return (u.protocol === 'https:' || u.protocol === 'http:') && u.origin === s;
  } catch {
    return false;
  }
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

// ignoreBOM keeps a leading BOM in the text, so JSON.parse refuses it (the Python library does the same).
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * Checks V18 tickets on your website's server. Implements every rule in PROTOCOL.md 3.7.
 * Never trust the browser alone: always call this on your server.
 */
export class V18Verifier {
  private readonly keyStore: JwksKeyStore;
  private readonly replayCache: ReplayStore;
  private readonly defaultOrigin?: string;
  private readonly defaultMinAge: number;
  private readonly clock: () => number;

  constructor(options: V18VerifierOptions = {}) {
    this.clock = options.clock ?? Date.now;
    this.keyStore =
      options.keyStore ??
      options.keyCache ??
      new JwksKeyStore({ serverUrl: options.serverUrl ?? 'http://localhost:8080', clock: this.clock });
    this.replayCache = options.replayCache ?? new MemoryReplayCache({ clock: this.clock });
    if (options.origin !== undefined && !isWebOrigin(options.origin)) {
      throw new TypeError(
        `[V18] origin must be a web origin like "https://example.com" (no path, no trailing slash). Got "${options.origin}".`
      );
    }
    this.defaultOrigin = options.origin;
    this.defaultMinAge = options.minAge ?? 18;
  }

  public getKeyStore(): JwksKeyStore {
    return this.keyStore;
  }

  /** Old name for getKeyStore. */
  public getKeyCache(): JwksKeyStore {
    return this.keyStore;
  }

  public getReplayCache(): ReplayStore {
    return this.replayCache;
  }

  /**
   * Verifies a ticket string "<keyId>.<base64url(prepared)>.<base64url(signature)>".
   * Never throws for a bad ticket: it returns `{ valid: false, code, error }`.
   */
  public async verifyTicket(ticketString: unknown, options: VerifyOptions = {}): Promise<VerifyResult> {
    // --- The website's own settings ---
    const expectedOrigin = options.expectedOrigin ?? this.defaultOrigin;
    if (!isWebOrigin(expectedOrigin)) {
      return fail(
        'CONFIG_ERROR',
        `expectedOrigin must be a web origin like "https://example.com". Got "${String(expectedOrigin)}".`
      );
    }
    const requiredAge = options.minAge ?? this.defaultMinAge;
    if (!isInt(requiredAge) || requiredAge < 1) {
      return fail('CONFIG_ERROR', `minAge must be a whole number of at least 1. Got "${String(requiredAge)}".`);
    }
    const expected = options.expectedChallenge;
    if (expected === undefined || expected === null || expected === '') {
      return fail('CHALLENGE_REQUIRED', 'No expected challenge given. Issue a challenge for each visit and pass it here.');
    }

    // --- Ticket shape ---
    if (typeof ticketString !== 'string' || ticketString.length === 0) {
      return fail('INVALID_FORMAT', 'Ticket is empty or not a string');
    }
    if (ticketString.length > RULES.MAX_TICKET_LENGTH) {
      return fail('INVALID_FORMAT', 'Ticket is too long');
    }
    const parts = ticketString.trim().split('.');
    if (parts.length !== 3) {
      return fail('INVALID_FORMAT', 'Ticket must have 3 parts: keyId.prepared.signature');
    }
    const [keyId, preparedB64, sigB64] = parts;
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(keyId) || !isBase64Url(preparedB64) || !isBase64Url(sigB64)) {
      return fail('INVALID_FORMAT', 'Ticket parts must be base64url without padding');
    }
    const prepared = b64urlDecode(preparedB64)!;
    const signature = b64urlDecode(sigB64)!;

    const nowMs = this.clock();
    const now = Math.floor(nowMs / 1000);

    // --- Rule 1: the key is in the JWKS and not too old ---
    const lookup = await this.keyStore.getKey(keyId);
    if (!lookup.key) {
      if (lookup.unavailable) {
        return fail('KEYS_UNAVAILABLE', `Could not load V18 public keys: ${lookup.reason ?? 'unknown error'}`);
      }
      return fail('UNKNOWN_KEY', `Key "${keyId}" is not in the V18 JWKS`);
    }
    const key = lookup.key;
    if (now > key.exp + RULES.KEY_EXPIRY_GRACE_SECONDS) {
      return fail('KEY_EXPIRED', `Key "${keyId}" expired at ${new Date(key.exp * 1000).toISOString()}`);
    }
    if (now < key.nbf - RULES.CLOCK_SKEW_SECONDS) {
      return fail('KEY_NOT_YET_VALID', `Key "${keyId}" is not valid until ${new Date(key.nbf * 1000).toISOString()}`);
    }

    // --- Rule 2: RSA-PSS, SHA-384, MGF1-SHA-384, salt 48, over `prepared` ---
    let sigOk = false;
    try {
      sigOk = crypto.verify(
        'sha384',
        prepared,
        { key: key.publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: RULES.PSS_SALT_LENGTH },
        signature
      );
    } catch {
      sigOk = false;
    }
    if (!sigOk) {
      return fail('INVALID_SIGNATURE', 'The V18 seal on this ticket is not valid (forged or changed)');
    }

    // --- The signed message: 32 random bytes, then UTF-8 JSON ---
    if (prepared.length <= RULES.PREPARE_PREFIX_BYTES) {
      return fail('MALFORMED_PAYLOAD', 'Signed message is too short');
    }
    let payload: any;
    try {
      payload = JSON.parse(utf8.decode(prepared.subarray(RULES.PREPARE_PREFIX_BYTES)));
    } catch {
      return fail('MALFORMED_PAYLOAD', 'Signed message is not UTF-8 JSON');
    }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return fail('MALFORMED_PAYLOAD', 'Signed message is not a JSON object');
    }

    // --- Rule 3: version ---
    if (payload.v !== 1) {
      return fail('UNSUPPORTED_VERSION', `Ticket version is ${JSON.stringify(payload.v)}, expected 1`);
    }

    const { ticketId, origin, challenge, minAge, iat, expiresAt } = payload;
    const ticketIdBytes = typeof ticketId === 'string' && ticketId.length <= 64 ? b64urlDecode(ticketId) : null;
    if (!ticketIdBytes || ticketIdBytes.length < 16) {
      return fail('MALFORMED_PAYLOAD', 'ticketId must be base64url of at least 16 random bytes');
    }
    if (typeof origin !== 'string' || typeof challenge !== 'string') {
      return fail('MALFORMED_PAYLOAD', 'origin and challenge must be strings');
    }
    if (!isInt(minAge) || !isInt(iat) || !isInt(expiresAt)) {
      return fail('MALFORMED_PAYLOAD', 'minAge, iat and expiresAt must be whole numbers');
    }

    // --- Rule 4: origin ---
    if (origin !== expectedOrigin) {
      return fail('ORIGIN_MISMATCH', `Ticket is for "${origin}", this site is "${expectedOrigin}"`);
    }

    // --- Rule 6: the KEY's threshold, never the payload's minAge ---
    if (key.minAge < requiredAge) {
      return fail(
        'AGE_INSUFFICIENT',
        `Key "${keyId}" certifies ${key.minAge}+, this site needs ${requiredAge}+`
      );
    }

    // --- Rule 7: time window ---
    const lifetime = expiresAt - iat;
    if (lifetime < 0 || lifetime > RULES.MAX_TICKET_LIFETIME_SECONDS) {
      return fail('TICKET_LIFETIME_INVALID', `Ticket lifetime is ${lifetime} seconds (allowed 0 to 300)`);
    }
    if (now < iat - RULES.CLOCK_SKEW_SECONDS) {
      return fail('TICKET_NOT_YET_VALID', 'Ticket was issued in the future (check the clocks)');
    }
    if (now > expiresAt + RULES.CLOCK_SKEW_SECONDS) {
      return fail('TICKET_EXPIRED', `Ticket expired at ${new Date(expiresAt * 1000).toISOString()}`);
    }

    // --- Rule 5: challenge (checked late, because a checker function uses the challenge up) ---
    let challengeOk: boolean;
    if (typeof expected === 'string') {
      challengeOk = safeEqual(challenge, expected);
    } else {
      try {
        challengeOk = (await expected(challenge)) === true;
      } catch {
        challengeOk = false;
      }
    }
    if (!challengeOk) {
      return fail('CHALLENGE_MISMATCH', 'Ticket was not made for the challenge this site issued for this visit');
    }

    // --- Rule 8: single use ---
    const rememberUntil = expiresAt + RULES.CLOCK_SKEW_SECONDS + 60;
    const fresh = await this.replayCache.checkAndRemember(ticketId, rememberUntil);
    if (!fresh) {
      return fail('REPLAY_DETECTED', 'This ticket was already used');
    }

    return {
      valid: true,
      ticket: { ticketId, origin, minAge: key.minAge, keyId, iat, expiresAt },
      payload: { v: 1, ticketId, origin, challenge, minAge, iat, expiresAt },
    };
  }
}
