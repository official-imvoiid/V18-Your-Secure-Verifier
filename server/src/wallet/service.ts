import { AppWalletVerifier } from '../cards/service.js';
import { ChallengeService } from '../challenge/service.js';
import { DocRepo } from '../db/state.js';
import { ApiError, badRequest } from '../errors.js';
import { PairingService } from '../pairing/service.js';
import { RateLimiter } from '../tickets/rate-limit.js';
import { TicketService } from '../tickets/service.js';
import { Clock, isPlainObject, sha256Hex } from '../util.js';
import { androidAppOrigin, newWalletRequest, verifyWalletResponse, WalletRequestState } from './mdoc.js';

const WALLET_TTL_MS = 5 * 60_000;

/**
 * Phone wallet IDs (PROTOCOL.md 4c.5 and 4d.3).
 *
 *  - Website widget (`mdoc_wallet`): POST /v1/wallet/request {sessionId} and
 *    POST /v1/wallet/verify {sessionId, response}. No card is made: the
 *    server puts an ordinary ticket on the pairing session.
 *  - V18 phone app (`mdoc_app`): POST /v1/wallet/app-request {challenge} gives
 *    the Credential Manager request (its nonce IS the server challenge); the
 *    app then calls POST /v1/card/issue {method: "mdoc_app", challenge,
 *    proof: <DigitalCredential {protocol, data}>, ...} and gets a card.
 *
 * Each request is single use: the first verify attempt uses it up.
 */
export class WalletService implements AppWalletVerifier {
  constructor(
    private readonly pairing: PairingService,
    private readonly tickets: TicketService,
    private readonly challenges: ChallengeService,
    private readonly docs: DocRepo,
    private readonly trustedIacas: string[],
    private readonly opts: { devMode: boolean; androidCertDigests: string[] },
    private readonly perIp: RateLimiter,
    private readonly hashIp: (ip: string | undefined) => string,
    private readonly clock: Clock,
    private readonly onResult?: (result: string) => void
  ) {}

  /** Wallet IDs work here (at least one trusted IACA). */
  get ready(): boolean {
    return this.trustedIacas.length > 0;
  }

  private requireReady(): void {
    if (!this.ready) throw new ApiError(503, 'METHOD_NOT_CONFIGURED', 'No wallet issuers (IACA certificates) are trusted on this server');
  }

  private checkOrigin(originHeader: string | undefined, origin: string): void {
    if (originHeader !== undefined && originHeader !== origin) {
      throw new ApiError(403, 'ORIGIN_MISMATCH', 'The request Origin header does not match the session origin');
    }
  }

  /** POST /v1/wallet/request {sessionId} (widget, any website). */
  async request(rawBody: unknown, originHeader: string | undefined, ip: string | undefined) {
    this.requireReady();
    await this.perIp.takeOrThrow(this.hashIp(ip), 'Too many wallet requests from this network. Try again soon.');
    const body = isPlainObject(rawBody) ? rawBody : {};
    if (typeof body.sessionId !== 'string') throw badRequest('Missing field: sessionId');
    const s = await this.pairing.get(body.sessionId);
    this.checkOrigin(originHeader, s.origin);
    if (s.minAge > 18) {
      throw new ApiError(400, 'MIN_AGE_UNSUPPORTED', 'Wallet IDs can prove only 18+ (age_over_18)');
    }
    const now = this.clock();
    const { state, request } = await newWalletRequest(now, Math.min(WALLET_TTL_MS, Math.max(0, s.expiresAt - now)));
    await this.pairing.change(body.sessionId, (cur) => {
      const status = this.pairing.statusOf(cur);
      if (status === 'expired') throw new ApiError(410, 'SESSION_EXPIRED', 'This session has expired');
      if (status !== 'waiting' && status !== 'connected') {
        throw new ApiError(409, 'WRONG_STATE', `The session is ${status}`, { status });
      }
      return { value: { ...cur, wallet: state }, result: null };
    });
    return { sessionId: s.sessionId, digital: { requests: [request] }, expiresAt: new Date(state.expiresAt).toISOString() };
  }

  /** POST /v1/wallet/verify {sessionId, response} (widget). Puts a ticket on the session. */
  async verify(rawBody: unknown, originHeader: string | undefined, ip: string | undefined) {
    this.requireReady();
    await this.perIp.takeOrThrow(this.hashIp(ip), 'Too many wallet answers from this network. Try again soon.');
    const body = isPlainObject(rawBody) ? rawBody : {};
    if (typeof body.sessionId !== 'string') throw badRequest('Missing field: sessionId');
    const s = await this.pairing.get(body.sessionId);
    this.checkOrigin(originHeader, s.origin);
    // Use the request up now, whatever the answer turns out to be.
    const wallet = await this.pairing.change(body.sessionId, (cur) => {
      const status = this.pairing.statusOf(cur);
      if (status === 'expired') throw new ApiError(410, 'SESSION_EXPIRED', 'This session has expired');
      if (status !== 'waiting' && status !== 'connected') {
        throw new ApiError(409, 'WRONG_STATE', `The session is ${status}`, { status });
      }
      if (!cur.wallet) throw new ApiError(409, 'WALLET_NO_REQUEST', 'Call POST /v1/wallet/request first (each request works once)');
      return { value: { ...cur, wallet: undefined }, result: cur.wallet };
    });
    try {
      await verifyWalletResponse({
        response: body.response,
        state: wallet,
        expectedOrigins: [s.origin],
        trustedIacas: this.trustedIacas,
        nowMs: this.clock(),
      });
    } catch (err) {
      this.onResult?.(err instanceof ApiError ? err.code : 'error');
      throw err;
    }
    const ticket = await this.tickets.issueDirect({ origin: s.origin, challenge: s.challenge, minAge: s.minAge });
    await this.pairing.deliver(s.sessionId, ticket);
    this.onResult?.('approved');
    return { status: 'approved' as const };
  }

  // ---- mdoc_app ---------------------------------------------------------------------

  private appOrigins(proof: Record<string, unknown>): string[] {
    if (this.opts.androidCertDigests.length > 0) return this.opts.androidCertDigests.map(androidAppOrigin);
    if (this.opts.devMode && typeof proof.origin === 'string' && /^android:apk-key-hash:[A-Za-z0-9_-]{43}$/.test(proof.origin)) {
      // TEST MODE only: without V18_ANDROID_CERT_DIGESTS the app names its own origin.
      return [proof.origin];
    }
    throw new ApiError(503, 'METHOD_NOT_CONFIGURED', 'mdoc_app needs V18_ANDROID_CERT_DIGESTS (the V18 app origin)');
  }

  /** POST /v1/wallet/app-request {challenge} (the V18 phone app). The challenge is not used up here. */
  async appRequest(rawBody: unknown, ip: string | undefined) {
    this.requireReady();
    await this.perIp.takeOrThrow(this.hashIp(ip), 'Too many wallet requests from this network. Try again soon.');
    const body = isPlainObject(rawBody) ? rawBody : {};
    if (!(await this.challenges.isOpen(body.challenge))) {
      throw new ApiError(401, 'CHALLENGE_INVALID', 'Get a fresh challenge from POST /v1/challenge first');
    }
    const challenge = body.challenge as string;
    const { state, request } = await newWalletRequest(this.clock(), WALLET_TTL_MS, challenge);
    await this.docs.put('wallet', `app_${sha256Hex(challenge)}`, state, state.expiresAt);
    return { digital: { requests: [request] }, expiresAt: new Date(state.expiresAt).toISOString() };
  }

  /** Card issue (method mdoc_app): checks the wallet answer for the request made with this challenge. */
  async verifyForCard(challenge: string, rawProof: unknown) {
    const proof = isPlainObject(rawProof) ? rawProof : {};
    const id = `app_${sha256Hex(challenge)}`;
    const state = await this.docs.get<WalletRequestState>('wallet', id);
    await this.docs.delete('wallet', id);
    if (!state) throw new ApiError(409, 'WALLET_NO_REQUEST', 'Call POST /v1/wallet/app-request with this challenge first');
    const r = await verifyWalletResponse({
      response: proof,
      state,
      expectedOrigins: this.appOrigins(proof),
      trustedIacas: this.trustedIacas,
      nowMs: this.clock(),
    });
    return { validUntilMs: r.validUntilMs, credentialKeyHash: r.credentialKeyHash, docType: r.docType };
  }
}
