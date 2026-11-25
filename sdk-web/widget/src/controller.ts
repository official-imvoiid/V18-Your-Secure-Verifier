/**
 * The widget's brain: a small state machine with no DOM code, so it can be tested in Node.
 * `modal.ts` draws whatever state this holds.
 */
import { PairingClient, PairingError, PairingSession, PairingStatus } from './pairing-client.js';
import { ensureVerifyDeepLink } from './deeplink.js';
import {
  CredentialsLike,
  DigitalCredentialRequest,
  WalletClient,
  WalletError,
  walletAnswerFrom,
  walletErrorFromBrowser,
} from './wallet.js';
import { displayHost, isUsableChallenge, normalizeServerUrl, readError } from './util.js';

export type Method = 'phone' | 'windows' | 'wallet';

export type View =
  | 'choose'
  | 'starting' // getting a challenge and a hand-off session (and, for a wallet, V18's request)
  | 'qr_waiting' // QR shown, waiting for the phone
  | 'connected' // phone connected, waiting for approval
  | 'win_waiting' // v18:// link opened, waiting for the Windows app
  | 'win_help' // "Don't have the app?"
  | 'wallet_ready' // wallet request ready; one more click, because browsers open wallets only right after a click
  | 'wallet_waiting' // the browser's wallet dialog is open
  | 'wallet_checking' // V18 is checking the wallet's answer
  | 'wallet_failed' // the wallet shared nothing, or V18 did not accept its answer
  | 'approved' // ticket on its way
  | 'done'
  | 'expired'
  | 'retry' // could not reach V18, or lost the connection
  | 'site_refused' // the website's server did not accept the ticket
  | 'how';

/**
 * A developer tool a page can register (the demo site's "Browser test wallet (dev only)").
 * It must run the REAL protocol flow and submit a real ticket to the pairing session.
 * The widget only shows its button when the V18 server reports devMode.
 */
export interface TestWallet {
  label?: string;
  simulatePhone(session: {
    serverUrl: string;
    sessionId: string;
    origin: string;
    challenge: string;
    minAge: number;
    onProgress?: (message: string) => void;
  }): Promise<void>;
}

export interface WidgetState {
  view: View;
  method: Method | null;
  origin: string;
  host: string;
  minAge: number;
  serverUrl: string;
  devMode: boolean | null;
  qrData: string | null;
  deepLink: string | null;
  secondsLeft: number;
  totalSeconds: number;
  progress: 'getting' | 'giving';
  error: string | null;
  errorCode: string | null;
  /** This browser has the Digital Credentials API (see detectWalletSupport). */
  walletSupport: boolean;
  /** The V18 server says phone wallet IDs work (`GET /v1/health` methods.mdoc_wallet === "ready"). */
  walletServer: boolean;
  windowsAppOpened: boolean;
  windowsHelpHint: boolean;
  usesVerifyUrl: boolean;
  testWallet: { available: boolean; label: string; busy: boolean; message: string | null; failed: boolean };
}

export interface ControllerConfig {
  origin: string;
  minAge: number;
  serverUrl: string;
  /** A challenge the site already put in the page. */
  challenge?: string;
  /** Where to get a fresh challenge from the site's server (POST, same-origin cookies). */
  challengeUrl?: string;
  /** Where to send the ticket on the site's server (POST {ticket}). If unset, the site handles it in onSuccess. */
  verifyUrl?: string;
  /** Result of detectWalletSupport(window). */
  walletSupport: boolean;
  /** How long to wait for a sign that the Windows app opened before showing the help hint. */
  windowsHelpDelayMs?: number;
  onSuccess?: (ticket: string, siteResponse: unknown) => void;
  onError?: (error: Error) => void;
}

export interface ControllerDeps {
  fetch: typeof fetch;
  pairing: PairingClient;
  openDeepLink: (link: string) => void;
  getTestWallet: () => TestWallet | null;
  /** `navigator.credentials` (the Digital Credentials API). Null or missing when the browser has none. */
  credentials?: CredentialsLike | null;
  /** Does the page have "transient user activation" (a recent click)? Browsers need one to open a wallet. */
  hasUserActivation?: () => boolean;
  /** Talks to /v1/wallet/*. Default: a WalletClient on the same server, using `fetch`. */
  wallet?: WalletClient;
}

export const DEFAULT_CHALLENGE_URL = '/v18/challenge';

type Listener = (state: WidgetState, reason: 'view' | 'tick' | 'detail') => void;

export class WidgetController {
  public state: WidgetState;
  private listeners = new Set<Listener>();
  private runId = 0;
  private session: PairingSession | null = null;
  private challenge: string | null = null;
  private helpTimer: ReturnType<typeof setTimeout> | null = null;
  private ticket: string | null = null;
  private siteResponse: unknown = null;
  private walletRequests: DigitalCredentialRequest[] | null = null;
  private walletAbort: AbortController | null = null;
  private readonly walletClient: WalletClient;

  constructor(private readonly cfg: ControllerConfig, private readonly deps: ControllerDeps) {
    this.walletClient = deps.wallet ?? new WalletClient(cfg.serverUrl, deps.fetch);
    const tw = deps.getTestWallet();
    this.state = {
      view: 'choose',
      method: null,
      origin: cfg.origin,
      host: displayHost(cfg.origin),
      minAge: cfg.minAge,
      serverUrl: normalizeServerUrl(cfg.serverUrl),
      devMode: null,
      qrData: null,
      deepLink: null,
      secondsLeft: 120,
      totalSeconds: 120,
      progress: 'getting',
      error: null,
      errorCode: null,
      walletSupport: cfg.walletSupport === true && !!deps.credentials,
      walletServer: false,
      windowsAppOpened: false,
      windowsHelpHint: false,
      usesVerifyUrl: !!cfg.verifyUrl,
      testWallet: { available: !!tw, label: tw?.label ?? 'Browser test wallet', busy: false, message: null, failed: false },
    };
  }

  public subscribe(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private set(patch: Partial<WidgetState>, reason: 'view' | 'tick' | 'detail' = 'view'): void {
    this.state = { ...this.state, ...patch };
    for (const l of this.listeners) l(this.state, reason);
  }

  /** The ticket and the site's reply, once the check is done. */
  public result(): { ticket: string | null; siteResponse: unknown } {
    return { ticket: this.ticket, siteResponse: this.siteResponse };
  }

  // ------------------------------------------------------------------ server info

  /**
   * Reads GET /v1/health. `devMode: true` turns on the TEST MODE banner (PROTOCOL.md 3.1), and
   * `methods.mdoc_wallet === "ready"` lets the widget offer phone wallet IDs.
   */
  public async loadServerInfo(): Promise<void> {
    try {
      const res = await this.deps.fetch(`${this.state.serverUrl}/v1/health`, { headers: { accept: 'application/json' } });
      if (!res.ok) return;
      const data: any = await res.json();
      this.set({ devMode: data?.devMode === true, walletServer: data?.methods?.mdoc_wallet === 'ready' }, 'detail');
    } catch {
      /* unknown: no banner, no test wallet, no wallet option */
    }
  }

  // ------------------------------------------------------------------ choices

  public choosePhone(): Promise<void> {
    return this.startHandoff('phone');
  }

  public chooseWindows(): Promise<void> {
    return this.startHandoff('windows');
  }

  /** Is "Use a phone wallet ID" offered? Only when the browser AND the V18 server support it. */
  public walletOffered(): boolean {
    return this.state.walletSupport && this.state.walletServer;
  }

  public chooseWallet(): Promise<void> {
    if (!this.walletOffered()) return Promise.resolve();
    return this.startHandoff('wallet');
  }

  /** "How it works" explainer. */
  public showHow(): void {
    this.stopSession();
    this.set({ view: 'how', method: null, error: null });
  }

  /** "Choose another way" / Cancel: stops any hand-off and goes back to the list. */
  public back(): void {
    this.stopSession();
    this.set({ view: 'choose', method: null, error: null, errorCode: null });
  }

  /** "Get a new code" / "Try again": a new challenge and a new session. */
  public retry(): Promise<void> {
    return this.startHandoff(this.state.method ?? 'phone');
  }

  public showWindowsHelp(): void {
    if (this.state.method !== 'windows') return;
    this.set({ view: 'win_help' });
  }

  public backToWindowsWaiting(): void {
    if (this.state.method !== 'windows' || !this.session) return;
    this.set({ view: 'win_waiting' });
  }

  /** Tries the v18:// link again. */
  public reopenWindowsApp(): void {
    if (this.state.method !== 'windows' || !this.state.deepLink) return;
    this.set({ view: 'win_waiting', windowsHelpHint: false });
    this.deps.openDeepLink(this.state.deepLink);
    this.scheduleHelpHint();
  }

  /** The page lost focus soon after we opened the link: probably the Windows app opened. A hint only. */
  public noteAppMayHaveOpened(): void {
    if (this.state.method === 'windows' && this.state.view === 'win_waiting' && !this.state.windowsAppOpened) {
      this.set({ windowsAppOpened: true, windowsHelpHint: false }, 'detail');
    }
  }

  // ------------------------------------------------------------------ hand-off

  private async getChallenge(): Promise<string> {
    if (this.cfg.challenge !== undefined) {
      if (!isUsableChallenge(this.cfg.challenge)) throw new PairingError('The website gave a challenge V18 cannot use', 'BAD_CHALLENGE');
      return this.cfg.challenge;
    }
    const url = this.cfg.challengeUrl ?? DEFAULT_CHALLENGE_URL;
    let res: Response;
    try {
      res = await this.deps.fetch(url, { method: 'POST', credentials: 'same-origin', headers: { accept: 'application/json' } });
    } catch (e: any) {
      throw new PairingError(`Could not reach this website's server (${e?.message ?? e})`, 'SITE_UNREACHABLE');
    }
    if (!res.ok) {
      const { error } = await readError(res);
      throw new PairingError(`This website could not start an age check: ${error}`, 'SITE_CHALLENGE_FAILED');
    }
    const data: any = await res.json().catch(() => null);
    if (!isUsableChallenge(data?.challenge)) {
      throw new PairingError('This website sent no usable challenge', 'SITE_CHALLENGE_FAILED');
    }
    return data.challenge;
  }

  private async startHandoff(method: Method): Promise<void> {
    this.stopSession();
    const run = ++this.runId;
    this.set({
      view: 'starting',
      method,
      error: null,
      errorCode: null,
      qrData: null,
      deepLink: null,
      progress: 'getting',
      windowsAppOpened: false,
      windowsHelpHint: false,
      testWallet: { ...this.state.testWallet, available: !!this.deps.getTestWallet(), busy: false, message: null, failed: false },
    });

    let session: PairingSession;
    let challenge: string;
    try {
      challenge = await this.getChallenge();
      if (run !== this.runId) return;
      session = await this.deps.pairing.create({ origin: this.state.origin, challenge, minAge: this.state.minAge, ttlSeconds: 120 });
    } catch (e: any) {
      if (run !== this.runId) return;
      this.set({ view: 'retry', error: e?.message ?? String(e), errorCode: e?.code ?? null });
      this.cfg.onError?.(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    if (run !== this.runId) {
      void this.deps.pairing.cancelById(session.sessionId);
      return;
    }

    this.session = session;
    this.challenge = challenge;
    const parts = {
      sessionId: session.sessionId,
      origin: this.state.origin,
      challenge,
      minAge: this.state.minAge,
      serverUrl: this.state.serverUrl,
    };
    const wallet = method === 'wallet';
    const deepLink = wallet ? null : ensureVerifyDeepLink(session.deepLink, parts);
    const qrData = wallet ? null : ensureVerifyDeepLink(session.qrData || session.deepLink, parts);

    this.set({
      view: method === 'phone' ? 'qr_waiting' : method === 'windows' ? 'win_waiting' : 'starting',
      deepLink,
      qrData,
      secondsLeft: session.expiresIn,
      totalSeconds: session.expiresIn,
    });

    this.deps.pairing.watch(session, {
      onTick: (left, total) => {
        if (run === this.runId) this.set({ secondsLeft: left, totalSeconds: total }, 'tick');
      },
      onStatus: (status: PairingStatus) => {
        if (run !== this.runId) return;
        if (wallet) {
          // V18 marks the session approved once it accepted the wallet's answer; the ticket follows.
          if (status === 'approved' && this.state.view === 'wallet_checking') this.set({ view: 'approved', progress: 'getting' });
          return;
        }
        if (status === 'connected') {
          if (method === 'phone') this.set({ view: 'connected' });
          else this.set({ view: 'win_waiting', windowsAppOpened: true, windowsHelpHint: false });
        } else if (status === 'approved') {
          this.set({ view: 'approved', progress: 'getting' });
        }
      },
      onTicket: (ticket) => {
        if (run === this.runId) void this.deliver(ticket, run);
      },
      onExpired: () => {
        if (run !== this.runId) return;
        this.clearHelpTimer();
        this.abortWallet();
        this.set({ view: 'expired', secondsLeft: 0 });
      },
      onConnectionLost: (err) => {
        if (run !== this.runId) return;
        this.clearHelpTimer();
        this.abortWallet();
        this.set({ view: 'retry', error: err.message, errorCode: 'CONNECTION_LOST' });
      },
    });

    if (method === 'windows' && deepLink) {
      this.deps.openDeepLink(deepLink);
      this.scheduleHelpHint();
    }
    if (wallet) await this.prepareWallet(session, run);
  }

  private scheduleHelpHint(): void {
    this.clearHelpTimer();
    this.helpTimer = setTimeout(() => {
      if (this.state.view === 'win_waiting' && !this.state.windowsAppOpened) this.set({ windowsHelpHint: true }, 'detail');
    }, this.cfg.windowsHelpDelayMs ?? 6000);
  }

  private clearHelpTimer(): void {
    if (this.helpTimer) clearTimeout(this.helpTimer);
    this.helpTimer = null;
  }

  // ------------------------------------------------------------------ phone wallet (PROTOCOL.md 4c.5)

  /** Gets V18's wallet request for this session, then opens the wallet (or asks for one more click). */
  private async prepareWallet(session: PairingSession, run: number): Promise<void> {
    let requests: DigitalCredentialRequest[];
    try {
      requests = await this.walletClient.request(session.sessionId);
    } catch (e: any) {
      this.walletFailed(e, run, 'request');
      return;
    }
    if (run !== this.runId) return;
    this.walletRequests = requests;
    // Browsers open a wallet only right after a click. If that moment has passed, ask for a click.
    const activated = this.deps.hasUserActivation ? this.deps.hasUserActivation() : true;
    if (activated) void this.openWallet();
    else this.set({ view: 'wallet_ready' });
  }

  /**
   * Hands V18's request to the browser, then sends the answer to V18. Safe to call straight from a
   * click handler: nothing here waits before navigator.credentials.get is called.
   */
  public async openWallet(): Promise<void> {
    const session = this.session;
    const requests = this.walletRequests;
    const credentials = this.deps.credentials;
    if (this.state.method !== 'wallet' || !session || !requests || !credentials) return;
    if (this.state.view !== 'starting' && this.state.view !== 'wallet_ready') return;
    const run = this.runId;
    const abort = typeof AbortController !== 'undefined' ? new AbortController() : null;
    this.walletAbort = abort;
    let pending: Promise<any>;
    try {
      pending = Promise.resolve(
        credentials.get({ mediation: 'required', digital: { requests }, ...(abort ? { signal: abort.signal } : {}) })
      );
    } catch (e) {
      pending = Promise.reject(e);
    }
    this.set({ view: 'wallet_waiting' });

    let answer;
    try {
      answer = walletAnswerFrom(await pending);
    } catch (e: any) {
      // Expiry or a lost connection stops the wallet too; keep that screen instead.
      if (run !== this.runId || this.currentView() !== 'wallet_waiting') return;
      this.walletFailed(e instanceof WalletError ? e : walletErrorFromBrowser(e), run, 'browser');
      return;
    } finally {
      if (this.walletAbort === abort) this.walletAbort = null;
    }
    if (run !== this.runId || this.currentView() !== 'wallet_waiting') return;

    this.set({ view: 'wallet_checking' });
    try {
      await this.walletClient.verify(session.sessionId, answer);
    } catch (e: any) {
      if (run !== this.runId || this.currentView() !== 'wallet_checking') return;
      this.walletFailed(e, run, 'verify');
      return;
    }
    if (run !== this.runId) return;
    // The ticket comes through the normal poll (it may already be on its way).
    if (this.currentView() === 'wallet_checking') this.set({ view: 'approved', progress: 'getting' });
  }

  /** Reads the view afresh (it can change while we wait for the browser or the network). */
  private currentView(): View {
    return this.state.view;
  }

  private walletFailed(e: any, run: number, step: 'request' | 'browser' | 'verify'): void {
    if (run !== this.runId) return;
    const code: string = typeof e?.code === 'string' ? e.code : 'WALLET_FAILED';
    const message: string = e?.message ?? String(e);
    // This session is no use any more: stop polling and tell V18 (best effort).
    this.walletRequests = null;
    if (this.deps.pairing.isActive()) void this.deps.pairing.cancel();
    this.session = null;
    if (code === 'NETWORK' || /^HTTP_5/.test(code) || (step === 'request' && e?.status >= 500)) {
      this.set({ view: 'retry', error: message, errorCode: code });
    } else if (code === 'SESSION_NOT_FOUND' || code === 'SESSION_EXPIRED' || e?.status === 410) {
      this.set({ view: 'expired', secondsLeft: 0 });
    } else {
      this.set({ view: 'wallet_failed', error: message, errorCode: code });
    }
    this.cfg.onError?.(e instanceof Error ? e : new Error(message));
  }

  private abortWallet(): void {
    const a = this.walletAbort;
    this.walletAbort = null;
    try {
      a?.abort();
    } catch {
      /* already finished */
    }
  }

  // ------------------------------------------------------------------ giving the ticket to the site

  /** Gives the ticket to the website's server (if it has a verify URL). */
  private async deliver(ticket: string, run: number): Promise<void> {
    this.clearHelpTimer();
    this.ticket = ticket;
    this.set({ view: 'approved', progress: 'giving' });

    let siteResponse: unknown = null;
    if (this.cfg.verifyUrl) {
      try {
        const res = await this.deps.fetch(this.cfg.verifyUrl, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', accept: 'application/json' },
          body: JSON.stringify({ ticket }),
        });
        if (run !== this.runId) return;
        siteResponse = await res.json().catch(() => null);
        if (!res.ok) {
          const r: any = siteResponse;
          this.set({
            view: 'site_refused',
            error: typeof r?.error === 'string' ? r.error : `HTTP ${res.status}`,
            errorCode: typeof r?.code === 'string' ? r.code : null,
          });
          this.cfg.onError?.(new Error(`Website refused the ticket: ${r?.code ?? res.status}`));
          return;
        }
      } catch (e: any) {
        if (run !== this.runId) return;
        this.set({ view: 'site_refused', error: `Could not reach this website's server (${e?.message ?? e})`, errorCode: 'SITE_UNREACHABLE' });
        return;
      }
    }
    this.siteResponse = siteResponse;
    this.set({ view: 'done' });
    this.cfg.onSuccess?.(ticket, siteResponse);
  }

  // ------------------------------------------------------------------ dev-only test wallet

  /** Shows the test-wallet button? Only with a registered test wallet AND a server in dev mode. */
  public canSimulate(): boolean {
    return this.state.devMode === true && !!this.deps.getTestWallet() && !!this.session &&
      (this.state.view === 'qr_waiting' || this.state.view === 'win_waiting' || this.state.view === 'win_help');
  }

  /** Runs the registered test wallet against the current session. It must submit a real ticket. */
  public async simulateWithTestWallet(): Promise<void> {
    const tw = this.deps.getTestWallet();
    const session = this.session;
    if (!tw || !session || !this.challenge || this.state.devMode !== true || this.state.testWallet.busy || !this.canSimulate()) return;
    const run = this.runId;
    const tws = (patch: Partial<WidgetState['testWallet']>) =>
      this.set({ testWallet: { ...this.state.testWallet, ...patch } }, 'detail');
    tws({ busy: true, failed: false, message: 'Starting the test wallet…' });
    try {
      await tw.simulatePhone({
        serverUrl: this.state.serverUrl,
        sessionId: session.sessionId,
        origin: this.state.origin,
        challenge: this.challenge,
        minAge: this.state.minAge,
        onProgress: (m) => {
          if (run === this.runId) tws({ message: m });
        },
      });
      if (run === this.runId) tws({ busy: false, message: 'The test wallet sent a ticket. Waiting for V18 to pass it on…' });
    } catch (e: any) {
      if (run === this.runId) tws({ busy: false, failed: true, message: `Test wallet failed: ${e?.message ?? e}` });
    }
  }

  // ------------------------------------------------------------------ lifecycle

  private stopSession(): void {
    this.runId++;
    this.clearHelpTimer();
    this.abortWallet();
    this.walletRequests = null;
    if (this.deps.pairing.isActive()) void this.deps.pairing.cancel();
    else this.deps.pairing.stop();
    this.session = null;
    this.challenge = null;
  }

  /** Call when the widget closes. Cancels any open hand-off on the server. */
  public dispose(): void {
    this.stopSession();
    this.listeners.clear();
  }
}
