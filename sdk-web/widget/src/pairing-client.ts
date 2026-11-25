/**
 * Talks to the V18 server's QR hand-off endpoints (PROTOCOL.md 3.8):
 *   POST /v1/pairing/session {origin, challenge, minAge, ttlSeconds}
 *   GET  /v1/pairing/:id                (poll; a delivered ticket comes back once)
 *   POST /v1/pairing/:id/cancel
 * The phone or the Windows app does /connect and /submit.
 */
import { normalizeServerUrl, readError } from './util.js';

export type PairingStatus = 'waiting' | 'connected' | 'approved' | 'expired' | 'cancelled';

export interface PairingSession {
  sessionId: string;
  deepLink: string;
  qrData: string;
  expiresAt?: string;
  expiresIn: number;
  pollUrl?: string;
}

export interface PairingEvents {
  onStatus?: (status: PairingStatus) => void;
  onTicket?: (ticket: string) => void;
  onTick?: (secondsLeft: number, totalSeconds: number) => void;
  onExpired?: (reason: 'timeout' | 'expired' | 'cancelled') => void;
  onConnectionLost?: (error: Error) => void;
}

export class PairingError extends Error {
  constructor(message: string, public readonly code?: string, public readonly status?: number) {
    super(message);
    this.name = 'PairingError';
  }
}

export interface PairingClientOptions {
  fetch?: typeof fetch;
  /** How often to poll. Default 1000 ms. */
  pollMs?: number;
  /** After this many failed polls in a row, report a lost connection. Default 8. */
  maxPollFailures?: number;
  now?: () => number;
}

export class PairingClient {
  public readonly serverUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly pollMs: number;
  private readonly maxPollFailures: number;
  private readonly now: () => number;

  private session: PairingSession | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private tickTimer: ReturnType<typeof setInterval> | null = null;
  private status: PairingStatus | null = null;
  private failures = 0;
  private polling = false;
  private finished = true;

  constructor(serverUrl: string, options: PairingClientOptions = {}) {
    this.serverUrl = normalizeServerUrl(serverUrl);
    this.fetchFn = options.fetch ?? ((...a: Parameters<typeof fetch>) => globalThis.fetch(...a));
    this.pollMs = options.pollMs ?? 1000;
    this.maxPollFailures = options.maxPollFailures ?? 8;
    this.now = options.now ?? Date.now;
  }

  /** Creates a hand-off session. Throws PairingError if the server refuses or cannot be reached. */
  public async create(opts: { origin: string; challenge: string; minAge: number; ttlSeconds?: number }): Promise<PairingSession> {
    let res: Response;
    try {
      res = await this.fetchFn(`${this.serverUrl}/v1/pairing/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          origin: opts.origin,
          challenge: opts.challenge,
          minAge: opts.minAge,
          ttlSeconds: opts.ttlSeconds ?? 120,
        }),
      });
    } catch (e: any) {
      throw new PairingError(`Could not reach V18 (${e?.message ?? e})`, 'NETWORK');
    }
    if (!res.ok) {
      const { error, code } = await readError(res);
      throw new PairingError(error, code, res.status);
    }
    const data: any = await res.json();
    if (!data || typeof data.sessionId !== 'string' || data.sessionId.length < 16) {
      throw new PairingError('V18 sent a pairing reply without a proper session ID', 'BAD_REPLY');
    }
    const expiresIn = Number.isFinite(data.expiresIn) && data.expiresIn > 0 ? Math.floor(data.expiresIn) : 120;
    return {
      sessionId: data.sessionId,
      deepLink: typeof data.deepLink === 'string' ? data.deepLink : '',
      qrData: typeof data.qrData === 'string' ? data.qrData : typeof data.deepLink === 'string' ? data.deepLink : '',
      expiresAt: data.expiresAt,
      expiresIn,
      pollUrl: data.pollUrl,
    };
  }

  /** Starts the countdown and polling for this session. */
  public watch(session: PairingSession, events: PairingEvents): void {
    this.stop();
    this.session = session;
    this.status = 'waiting';
    this.failures = 0;
    this.finished = false;

    const start = this.now();
    const total = session.expiresIn;
    const left = () => Math.max(0, Math.ceil(total - (this.now() - start) / 1000));

    events.onTick?.(left(), total);
    this.tickTimer = setInterval(() => {
      const l = left();
      events.onTick?.(l, total);
      if (l <= 0) this.finish(() => events.onExpired?.('timeout'));
    }, 1000);

    this.pollTimer = setInterval(() => void this.pollOnce(events), this.pollMs);
  }

  private async pollOnce(events: PairingEvents): Promise<void> {
    if (this.polling || this.finished || !this.session) return;
    this.polling = true;
    const id = this.session.sessionId;
    try {
      const res = await this.fetchFn(`${this.serverUrl}/v1/pairing/${encodeURIComponent(id)}`, {
        headers: { accept: 'application/json' },
        cache: 'no-store',
      });
      if (this.finished || this.session?.sessionId !== id) return;
      if (res.status === 404 || res.status === 410) {
        this.finish(() => events.onExpired?.('expired'));
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: any = await res.json();
      this.failures = 0;

      if (typeof data?.ticket === 'string' && data.ticket.length > 0) {
        const ticket = data.ticket;
        this.finish(() => events.onTicket?.(ticket));
        return;
      }
      const status = data?.status as PairingStatus;
      if (status === 'expired' || status === 'cancelled') {
        this.finish(() => events.onExpired?.(status));
        return;
      }
      if ((status === 'waiting' || status === 'connected' || status === 'approved') && status !== this.status) {
        this.status = status;
        events.onStatus?.(status);
      }
    } catch (e: any) {
      if (this.finished) return;
      this.failures++;
      if (this.failures >= this.maxPollFailures) {
        const err = e instanceof Error ? e : new Error(String(e));
        this.finish(() => events.onConnectionLost?.(err));
      }
    } finally {
      this.polling = false;
    }
  }

  private finish(then: () => void): void {
    if (this.finished) return;
    this.finished = true;
    this.clearTimers();
    then();
  }

  private clearTimers(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.tickTimer) clearInterval(this.tickTimer);
    this.pollTimer = this.tickTimer = null;
  }

  /** Stops watching. Does not tell the server. */
  public stop(): void {
    this.finished = true;
    this.clearTimers();
  }

  /** Stops watching and tells the server to cancel the session (best effort). */
  public async cancel(): Promise<void> {
    const s = this.session;
    const wasActive = !this.finished;
    this.stop();
    this.session = null;
    if (!s || !wasActive) return;
    try {
      await this.fetchFn(`${this.serverUrl}/v1/pairing/${encodeURIComponent(s.sessionId)}/cancel`, { method: 'POST' });
    } catch {
      /* the session expires by itself anyway */
    }
  }

  /** Cancels a session this client is not watching (for example one created after the user left). */
  public async cancelById(sessionId: string): Promise<void> {
    try {
      await this.fetchFn(`${this.serverUrl}/v1/pairing/${encodeURIComponent(sessionId)}/cancel`, { method: 'POST' });
    } catch {
      /* it expires by itself */
    }
  }

  public getSession(): PairingSession | null {
    return this.session;
  }

  public isActive(): boolean {
    return !this.finished;
  }
}
