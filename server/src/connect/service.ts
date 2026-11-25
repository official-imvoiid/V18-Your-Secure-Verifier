import * as crypto from 'node:crypto';
import { AttestationGate } from '../attestation/gate.js';
import { CardResponse, CardService } from '../cards/service.js';
import { ChallengeService } from '../challenge/service.js';
import { DocRepo } from '../db/state.js';
import { DeviceKey, parseDevicePublicKey } from '../device/device-keys.js';
import { ApiError } from '../errors.js';
import { NullifierStore } from '../nullifier/store.js';
import { Clock, isPlainObject } from '../util.js';

/**
 * Government and bank logins (PROTOCOL.md 4d.4), using the `@v18/connectors`
 * package in connectors/.
 *
 *  1. POST /v1/connect/:id/start: the app proves it holds a new device key
 *     and gets an authUrl (PKCE; `state` is stored with the challenge's
 *     device key).
 *  2. The provider redirects to GET or POST /v1/connect/:id/callback. The
 *     connector reads ONLY the birth date or age answer and a subject ID.
 *     The server turns the subject into
 *       nullifier = HMAC-SHA256(V18_NULLIFIER_SECRET, id + "|" + subject)
 *     and forgets it. Nothing else is ever stored or logged.
 *  3. The server redirects to v18://connect?status=ok&cardId=...&state=...;
 *     the app reads the card from GET /v1/connect/session/:state (once).
 */

/** The parts of @v18/connectors this server uses. */
export interface ConnectorLike {
  readonly id: string;
  readonly countries: readonly string[];
  readonly assurance: 'high' | 'substantial';
  readonly label: string;
  readonly callbackMethod: 'GET' | 'POST';
  buildAuthUrl(p: { state: string; nonce: string; codeVerifier: string; redirectUri: string; endUserIp?: string; idp?: string }): Promise<{
    authUrl: string;
    session?: string;
  }>;
  handleCallback(p: {
    params: Record<string, string>;
    state: string;
    nonce: string;
    codeVerifier: string;
    redirectUri: string;
    session?: string;
  }): Promise<{ over18: boolean; subject: string }>;
  /** Public keys the provider fetches (Singpass, itsme: private_key_jwt or encryption). */
  jwks?(): Promise<{ keys: Record<string, unknown>[] }>;
  /** Signed SAML service provider metadata (SPID, CIE). */
  metadata?(acsUrl: string): Promise<string>;
  /** SPID and CIE: the identity providers the person can choose from. */
  identityProviders?(): { entityId: string; name?: string }[];
}

/** BankID Sweden's animated QR text for a person on a PC (from @v18/connectors). */
export type BankIdQrFn = (session: string, nowMs: number) => string;

/** Loads the QR helper from @v18/connectors, if the package is there. */
export function loadBankIdQr(): BankIdQrFn | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return (require('@v18/connectors') as { bankIdQrData?: BankIdQrFn }).bankIdQrData ?? null;
  } catch {
    return null;
  }
}

export interface RegistryLike {
  list(): ConnectorLike[];
  get(id: string): ConnectorLike | undefined;
}

/** Loads @v18/connectors (a file: dependency). Returns null when it is not installed. */
export function loadConnectorRegistry(env: NodeJS.ProcessEnv): { registry: RegistryLike | null; error: string | null } {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const mod = require('@v18/connectors') as { createRegistry(env: NodeJS.ProcessEnv): RegistryLike };
    return { registry: mod.createRegistry(env), error: null };
  } catch (err) {
    return { registry: null, error: (err as Error).message.split('\n')[0] };
  }
}

interface ConnectSession {
  connectorId: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  /** Opaque connector data (for example a DPoP key); deleted after the callback. */
  session?: string;
  deviceKey: Pick<DeviceKey, 'alg' | 'jwk' | 'thumbprint'>;
  status: 'waiting' | 'working' | 'ok' | 'under_age' | 'error';
  code?: string;
  card?: CardResponse;
  cardDelivered?: boolean;
  expiresAt: number;
}

const TTL_MS = 10 * 60_000;
const STATE = /^[A-Za-z0-9_-]{43}$/;

export class ConnectService {
  constructor(
    private readonly registry: RegistryLike | null,
    private readonly cards: CardService,
    private readonly challenges: ChallengeService,
    private readonly gate: AttestationGate,
    private readonly docs: DocRepo,
    private readonly opts: { publicUrl: string; nullifierSecret: string | null },
    private readonly clock: Clock,
    private readonly bankIdQrData: BankIdQrFn | null = loadBankIdQr()
  ) {}

  /** GET /v1/connect/:id/jwks: V18's public keys for this provider (never private parts). */
  async jwks(id: string): Promise<{ keys: Record<string, unknown>[] }> {
    const c = this.connector(id);
    if (!c.jwks) throw new ApiError(404, 'NOT_FOUND', `The login "${id}" publishes no keys`);
    const out = await c.jwks();
    for (const k of out.keys) {
      for (const p of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) {
        if (p in k) throw new Error(`connector ${id} returned a private key part in its JWKS`);
      }
    }
    return out;
  }

  /** GET /v1/connect/:id/metadata: SAML metadata; the ACS URL is the callback (form POST). */
  async metadata(id: string): Promise<string> {
    const c = this.connector(id);
    if (!c.metadata) throw new ApiError(404, 'NOT_FOUND', `The login "${id}" has no SAML metadata`);
    return c.metadata(this.redirectUri(id));
  }

  /** GET /v1/connect/:id/identity-providers: for SPID and CIE, pass the chosen entityId as `idp` to start. */
  identityProviders(id: string): { identityProviders: { entityId: string; name?: string }[] } {
    const c = this.connector(id);
    if (!c.identityProviders) throw new ApiError(404, 'NOT_FOUND', `The login "${id}" has no identity provider list`);
    return { identityProviders: c.identityProviders().map((p) => ({ entityId: p.entityId, name: p.name })) };
  }

  /**
   * GET /v1/connect/session/:state/qr: BankID Sweden, person on a PC with BankID on the
   * phone. The text changes every second (the app redraws the QR); the secret behind it never
   * leaves the server. Only while the login is still waiting, and only for 30 seconds.
   */
  async bankIdQr(state: string): Promise<{ qrData: string; refreshMs: number }> {
    const s = STATE.test(state) ? await this.docs.get<ConnectSession>('connect', state) : null;
    if (!s || s.status !== 'waiting' || this.clock() > s.expiresAt) {
      throw new ApiError(404, 'CONNECT_SESSION_NOT_FOUND', 'No waiting login session', { status: 'expired' });
    }
    if (s.connectorId !== 'bankid_se' || !s.session || !this.bankIdQrData) {
      throw new ApiError(404, 'NOT_FOUND', 'Only BankID (Sweden) logins have a QR code');
    }
    let qrData: string;
    try {
      qrData = this.bankIdQrData(s.session, this.clock());
    } catch {
      throw new ApiError(404, 'NOT_FOUND', 'This BankID order has no QR code');
    }
    return { qrData, refreshMs: 1000 };
  }

  /** Configured connectors only (the others are hidden, 4d.4). */
  enabled(): ConnectorLike[] {
    return this.opts.nullifierSecret ? (this.registry?.list() ?? []) : [];
  }

  isEnabled(id: string): boolean {
    return this.enabled().some((c) => c.id === id);
  }

  private connector(id: string): ConnectorLike {
    const c = this.isEnabled(id) ? this.registry!.get(id) : undefined;
    if (!c) throw new ApiError(404, 'CONNECTOR_NOT_ENABLED', `The login "${id}" is not available on this server`);
    return c;
  }

  redirectUri(id: string): string {
    return `${this.opts.publicUrl}/v1/connect/${id}/callback`;
  }

  /** POST /v1/connect/:id/start {challenge, devicePublicKey, deviceSignature, keyAttestation?, idp?} */
  async start(id: string, rawBody: unknown, ip: string | undefined) {
    const connector = this.connector(id);
    const body = isPlainObject(rawBody) ? rawBody : {};
    const challenge = await this.challenges.consumeOrThrow(body.challenge);
    const deviceKey = await parseDevicePublicKey(body.devicePublicKey);
    // Same proof of possession as card issue and device link (4d.4 names no other string).
    this.cards.requireProofOfPossession(deviceKey, body.deviceSignature, challenge);
    if (body.keyAttestation !== undefined) await this.gate.check(body.keyAttestation, challenge, deviceKey.keyObject);

    const state = crypto.randomBytes(32).toString('base64url');
    const nonce = crypto.randomBytes(32).toString('base64url');
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    let started: { authUrl: string; session?: string };
    try {
      started = await connector.buildAuthUrl({
        state,
        nonce,
        codeVerifier,
        redirectUri: this.redirectUri(id),
        endUserIp: ip,
        idp: typeof body.idp === 'string' ? body.idp : undefined,
      });
    } catch (err) {
      throw new ApiError(502, 'CONNECTOR_ERROR', 'The login provider could not be started', { reason: connectorCode(err) });
    }
    const doc: ConnectSession = {
      connectorId: id,
      state,
      nonce,
      codeVerifier,
      session: started.session,
      deviceKey: { alg: deviceKey.alg, jwk: deviceKey.jwk, thumbprint: deviceKey.thumbprint },
      status: 'waiting',
      expiresAt: this.clock() + TTL_MS,
    };
    await this.docs.insert('connect', state, doc, doc.expiresAt + 5 * 60_000);
    return { authUrl: started.authUrl, state, expiresIn: TTL_MS / 1000 };
  }

  /**
   * GET or POST /v1/connect/:id/callback. Returns where to send the browser
   * (the app's v18://connect link). Never throws: every failure becomes a
   * status in the link, and nothing from the provider is logged.
   */
  async callback(id: string, params: Record<string, string>): Promise<string> {
    const state = params.state ?? params.RelayState ?? '';
    const link = (status: string, extra: Record<string, string> = {}) => {
      const q = new URLSearchParams({ status, ...(STATE.test(state) ? { state } : {}), ...extra });
      return `v18://connect?${q.toString()}`;
    };
    if (!STATE.test(state)) return link('error', { code: 'STATE_MISMATCH' });

    let claimed: ConnectSession;
    try {
      claimed = await this.docs.update<ConnectSession, ConnectSession>('connect', state, (s) => {
        if (!s || s.connectorId !== id) throw new ApiError(400, 'STATE_MISMATCH', 'unknown state');
        if (this.clock() > s.expiresAt) throw new ApiError(410, 'EXPIRED', 'expired');
        if (s.status !== 'waiting') throw new ApiError(409, 'ALREADY_USED', 'used');
        return { value: { ...s, status: 'working' }, result: s };
      });
    } catch (err) {
      return link('error', { code: err instanceof ApiError ? err.code : 'STATE_MISMATCH' });
    }

    const finish = async (patch: Partial<ConnectSession>) => {
      await this.docs
        .update<ConnectSession, null>('connect', state, (s) => ({ value: { ...s!, ...patch, session: undefined, nonce: '', codeVerifier: '' }, result: null }))
        .catch(() => undefined);
    };

    let result: { over18: boolean; subject: string };
    try {
      const connector = this.connector(id);
      result = await connector.handleCallback({
        params,
        state,
        nonce: claimed.nonce,
        codeVerifier: claimed.codeVerifier,
        redirectUri: this.redirectUri(id),
        session: claimed.session,
      });
    } catch (err) {
      const code = connectorCode(err);
      if (code === 'PENDING') {
        // BankID: not finished yet. Let the next callback try again.
        await this.docs.update<ConnectSession, null>('connect', state, (s) => ({ value: { ...s!, status: 'waiting' }, result: null })).catch(() => undefined);
        return link('pending');
      }
      await finish({ status: 'error', code });
      return link('error', { code });
    }

    if (result.over18 !== true) {
      await finish({ status: 'under_age', code: 'UNDER_AGE' });
      return link('under_age');
    }
    if (!this.opts.nullifierSecret || typeof result.subject !== 'string' || result.subject.length === 0) {
      await finish({ status: 'error', code: 'INVALID_RESPONSE' });
      return link('error', { code: 'INVALID_RESPONSE' });
    }
    const hmac = crypto.createHmac('sha256', this.opts.nullifierSecret).update(`${id}|${result.subject}`).digest('hex');
    // `result` (and so the subject) is not used after this line.
    const method = `connector:${id}` as const;
    try {
      const connector = this.connector(id);
      const card = await this.cards.createCard({
        method,
        deviceKey: claimed.deviceKey,
        nullifierHash: NullifierStore.hashFor(method, hmac),
        assuranceLevel: connector.assurance,
        minAgeCertified: 18,
        validUntilMs: this.clock() + 180 * 86_400_000,
      });
      await finish({ status: 'ok', card });
      return link('ok', { cardId: card.cardId });
    } catch (err) {
      const code = err instanceof ApiError ? err.code : 'INTERNAL';
      await finish({ status: 'error', code });
      return link('error', { code });
    }
  }

  /** GET /v1/connect/session/:state (the app). The card is returned ONCE. */
  async poll(state: string) {
    if (!STATE.test(state)) throw new ApiError(404, 'CONNECT_SESSION_NOT_FOUND', 'No such login session', { status: 'expired' });
    return this.docs.update<ConnectSession, Record<string, unknown>>('connect', state, (s) => {
      if (!s) throw new ApiError(404, 'CONNECT_SESSION_NOT_FOUND', 'No such login session', { status: 'expired' });
      if (s.status === 'ok') {
        if (s.card) return { value: { ...s, card: undefined, cardDelivered: true }, result: { status: 'ok', card: s.card } };
        return { result: { status: 'ok', cardDelivered: true } };
      }
      if (s.status === 'under_age' || s.status === 'error') return { result: { status: s.status, code: s.code } };
      if (this.clock() > s.expiresAt) return { result: { status: 'expired' } };
      return { result: { status: 'waiting', expiresIn: Math.max(0, Math.floor((s.expiresAt - this.clock()) / 1000)) } };
    });
  }
}

/** A ConnectorError's fixed code, or a generic one. Never the message of an unknown error. */
function connectorCode(err: unknown): string {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === 'string' && /^[A-Z_]{3,40}$/.test(code) ? code : 'PROVIDER_ERROR';
}
