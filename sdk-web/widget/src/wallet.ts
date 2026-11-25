/**
 * Phone wallet IDs through the browser (PROTOCOL.md 4c.5, method `mdoc_wallet`).
 *
 * The browser's Digital Credentials API (`navigator.credentials.get({ digital: { requests } })`)
 * asks an ID in the visitor's phone wallet (a mobile driving licence or an EU PID) for ONE fact:
 * `age_over_18`. The V18 server builds that request and checks the wallet's answer:
 *
 *   POST /v1/wallet/request {sessionId}            -> { digital: { requests: [{protocol, data}] } }
 *   navigator.credentials.get({ digital: ... })    -> DigitalCredential { protocol, data }
 *   POST /v1/wallet/verify {sessionId, response}   -> V18 puts a normal ticket on the pairing session
 *
 * The widget is a pass-through: it never reads or changes the request or the answer.
 */
import { normalizeServerUrl, readError } from './util.js';

/** Protocols V18 can use (OpenID4VP 1.0 Appendix A, and ISO/IEC 18013-7 Annex C). */
export const WALLET_PROTOCOLS = ['openid4vp-v1-unsigned', 'openid4vp-v1-signed', 'openid4vp-v1-multisigned', 'org-iso-mdoc'] as const;

export interface DigitalCredentialRequest {
  protocol: string;
  data: unknown;
}

/** What the widget sends to V18: exactly the browser's DigitalCredential fields. */
export interface WalletAnswer {
  protocol: string;
  data: unknown;
}

/** The part of `navigator.credentials` the widget uses. Tests pass a fake. */
export interface CredentialsLike {
  get(options: any): Promise<any>;
}

/**
 * True only if this browser can ask a phone wallet: the `DigitalCredential` class,
 * `navigator.credentials.get`, a secure (HTTPS) page, and, where the browser can say so,
 * support for at least one protocol V18 uses. When this is false the widget does not show the
 * wallet option at all.
 */
export function detectWalletSupport(win: any = typeof window !== 'undefined' ? window : undefined): boolean {
  if (!win) return false;
  const DC = win.DigitalCredential;
  if (typeof DC !== 'function') return false;
  if (typeof win.navigator?.credentials?.get !== 'function') return false;
  if (win.isSecureContext === false) return false;
  if (typeof DC.userAgentAllowsProtocol === 'function') {
    try {
      return WALLET_PROTOCOLS.some((p) => DC.userAgentAllowsProtocol(p) === true);
    } catch {
      return false;
    }
  }
  return true;
}

export class WalletError extends Error {
  constructor(message: string, public readonly code: string, public readonly status?: number) {
    super(message);
    this.name = 'WalletError';
  }
}

/**
 * Reads the request from V18's reply. Accepts `{digital: {requests}}` (the protocol shape), a
 * top-level `requests` array, or one `{protocol, data}`.
 */
export function readWalletRequests(reply: any): DigitalCredentialRequest[] {
  const list = Array.isArray(reply?.digital?.requests)
    ? reply.digital.requests
    : Array.isArray(reply?.requests)
      ? reply.requests
      : reply && typeof reply.protocol === 'string'
        ? [{ protocol: reply.protocol, data: reply.data }]
        : null;
  if (!list || list.length === 0) throw new WalletError('V18 sent no wallet request', 'BAD_REPLY');
  const out: DigitalCredentialRequest[] = [];
  for (const r of list) {
    if (!r || typeof r.protocol !== 'string' || r.protocol.length === 0 || r.data === undefined || r.data === null) {
      throw new WalletError('V18 sent a wallet request the widget cannot read', 'BAD_REPLY');
    }
    out.push({ protocol: r.protocol, data: r.data });
  }
  return out;
}

/** Turns the browser's DigitalCredential into plain JSON, without changing `data`. */
export function walletAnswerFrom(credential: any): WalletAnswer {
  if (!credential || typeof credential.protocol !== 'string' || credential.data === undefined || credential.data === null) {
    throw new WalletError('The browser gave back no wallet answer', 'WALLET_NO_ANSWER');
  }
  return { protocol: credential.protocol, data: credential.data };
}

/**
 * Sorts an error from `navigator.credentials.get` into what the visitor should see.
 * Browsers use NotAllowedError for "the person said no or closed the dialog" (and, on purpose,
 * also for "no matching ID", so sites cannot probe the wallet). AbortError means it was stopped.
 */
export function walletErrorFromBrowser(e: any): WalletError {
  const name = e?.name;
  if (name === 'NotAllowedError' || name === 'AbortError') {
    return new WalletError('The wallet did not share anything. You may have closed it, or it has no matching ID.', 'WALLET_CANCELLED');
  }
  if (name === 'NotSupportedError') return new WalletError('This browser cannot use this kind of wallet request', 'WALLET_NOT_SUPPORTED');
  if (name === 'SecurityError') return new WalletError('The browser blocked the wallet request on this page', 'WALLET_BLOCKED');
  return new WalletError(`The browser could not ask the wallet (${e?.message ?? e})`, 'WALLET_FAILED');
}

export class WalletClient {
  public readonly serverUrl: string;
  private readonly fetchFn: typeof fetch;

  constructor(serverUrl: string, fetchFn?: typeof fetch) {
    this.serverUrl = normalizeServerUrl(serverUrl);
    this.fetchFn = fetchFn ?? ((...a: Parameters<typeof fetch>) => globalThis.fetch(...a));
  }

  private async post(path: string, body: unknown): Promise<any> {
    let res: Response;
    try {
      res = await this.fetchFn(`${this.serverUrl}/v1${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (e: any) {
      throw new WalletError(`Could not reach V18 (${e?.message ?? e})`, 'NETWORK');
    }
    if (!res.ok) {
      const { error, code } = await readError(res);
      throw new WalletError(error, code ?? `HTTP_${res.status}`, res.status);
    }
    return res.json().catch(() => ({}));
  }

  /** POST /v1/wallet/request {sessionId}: the request to hand to the browser. */
  public async request(sessionId: string): Promise<DigitalCredentialRequest[]> {
    return readWalletRequests(await this.post('/wallet/request', { sessionId }));
  }

  /** POST /v1/wallet/verify {sessionId, response}: V18 checks the answer and puts a ticket on the session. */
  public async verify(sessionId: string, response: WalletAnswer): Promise<void> {
    await this.post('/wallet/verify', { sessionId, response });
  }
}
