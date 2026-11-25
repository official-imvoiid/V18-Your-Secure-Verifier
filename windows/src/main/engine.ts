// V18 for Windows: the flows. Electron-free, so tests can drive it with a mock server.
//
// Main process only. Everything secret (challenges, blinding factors, tickets, signatures) stays
// in local variables inside one flow and is never stored, logged or sent to a window.

import { b64urlEncode } from '../shared/b64url.js';
import { defaultServer } from '../shared/allowlist.js';
import { ApiError, OfflineError, V18Api, type Card } from '../shared/api.js';
import { DeepLinkError, parseDeepLink, type DeepLink } from '../shared/deeplink.js';
import { devicePublicKeyBody, jwkThumbprint } from '../shared/jwk.js';
import { displayOrigin } from '../shared/origin.js';
import { cardDeleteString, cardIssueString, signingBytes, ticketRequestString } from '../shared/signing.js';
import { sanitizeState, serializeState, type StoredCard, type StoredSettings, type StoredState } from '../shared/storage.js';
import { blindTicket, buildTicketPayload, finalizeTicket, pickTicketKey } from '../shared/ticket.js';
import { aadhaarSignal } from '../shared/aadhaar-signal.js';
import { mergeCatalogs, parseCatalog, pcMethods } from '../shared/catalog.js';
import { readAadhaarFile, type AcceptedQr } from './aadhaar.js';
import { ArtifactError, type ArtifactStore } from './artifacts.js';
import { aliasFor, DeviceKeyError, newKeyName, splitAlias, type DeviceKeyProvider } from './keys.js';
import { ProverError, runProver, type SpawnProver } from './prover-host.js';
import { NAV_SCREENS, type AadhaarView, type AskStage, type AskView, type CardView, type MainScreen, type ViewState, type WorkStep, type WorkView } from './view.js';

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface EngineDeps {
  debug: boolean;
  store: { load(): unknown; save(json: string): void };
  hello: DeviceKeyProvider;
  /** Only set when the app runs with the explicit TEST flag. */
  testKeys: DeviceKeyProvider | null;
  fetchImpl?: FetchLike;
  now?: () => number;
  ageConsent?: () => Promise<{ child: string; minor: string }>;
  makeQr(text: string): Promise<string>;
  onChange(view: ViewState): void;
  /** Called when a site starts asking (the app opens its dialog and a notification). */
  onAsk?(ask: AskView): void;
  linkPollMs?: number;
  /** Automated tests only (mock server on a random port). The Electron app never sets this. */
  extraServerOrigins?: readonly string[];
  /** Debug builds only: use this server instead of the saved one (smoke tests). */
  serverOverride?: string;
  /** Folder with the bundled assets (the Aadhaar seal certificates are in its aadhaar/ folder). */
  assetsDir?: string;
  /** Anon Aadhaar circuit files: download, check and cache (PROTOCOL 4c.1). */
  artifacts?: ArtifactStore;
  /** Starts the proof builder process (an Electron utility process in the app). */
  spawnProver?: SpawnProver;
  proveTimeoutMs?: number;
  /** "Start V18 when I sign in to Windows". Missing when this build can't change it. */
  loginItem?: { get(): boolean; set(on: boolean): void };
  /** Opens a web page in the system browser (login connectors, 4d.4). */
  openExternal?: (url: string) => Promise<void>;
  /** This PC's region from Windows (for example "IN"), to pre-select the country. */
  localeCountry?: string | null;
}

/** An Aadhaar QR that passed the checks is kept in memory for at most this long. */
const QR_KEEP_MS = 10 * 60 * 1000;

const METHOD_LABELS: Record<string, string> = {
  test_dev: 'TEST card (dev issuer)',
  anon_aadhaar: 'Aadhaar Secure QR',
  passport_attested: 'Passport (read by your phone)',
  emrtd_attested: 'Passport or ID card (read by your phone)',
  philsys_qr_attested: 'PhilSys ID (read by your phone)',
  mynumber_attested: 'My Number Card (read by your phone)',
  mdoc_app: 'Wallet ID (on your phone)',
  face_estimate: 'Face estimate (on your phone)',
  passport_zk: 'Passport chip',
  device_link: 'From your phone',
};

export function methodLabel(method: string, connectorLabels?: Map<string, string>): string {
  if (method.startsWith('connector:')) return connectorLabels?.get(method) ?? `Login (${method.slice('connector:'.length).replace(/_/g, ' ')})`;
  return METHOD_LABELS[method] ?? method.replace(/_/g, ' ');
}

function dateLabel(iso: string): string {
  return new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

function isUnderAge(err: unknown): boolean {
  if (!(err instanceof ApiError)) return false;
  return /UNDER|TOO_YOUNG|AGE_NOT_MET/.test(err.code) || /under 18|under-18|under age/i.test(err.message);
}

/** Plain words for the codes the server gives when a login doesn't finish (docs/server/API.md 16). */
function connectErrorText(label: string, code?: string, error?: string): string {
  switch (code) {
    case 'NULLIFIER_OVERUSED':
      return `This ${label} account already has too many age cards. Delete one on another device first, then try again.`;
    case 'MISSING_BIRTHDATE':
      return `${label} didn't share your date of birth, so V18 couldn't check your age. Try again and allow it.`;
    case 'EXPIRED':
      return 'The sign-in took too long. Try again.';
    case 'ALREADY_USED':
    case 'STATE_MISMATCH':
      return "This sign-in was already used or didn't match. Try again from V18.";
    case 'PROVIDER_ERROR':
    case 'INVALID_RESPONSE':
      return `${label} refused or cancelled the sign-in, or sent something V18 couldn't read. Nothing was saved.`;
    case 'DEVICE_KEY_IN_USE':
      return 'This PC key already has a card. Try again (V18 makes a new key each time).';
    default:
      return error ? `${error}${code ? ` (${code})` : ''}` : `The sign-in was cancelled or refused${code ? ` (${code})` : ''}. Nothing was saved.`;
  }
}

export class V18Engine {
  private state: StoredState;
  private view: Omit<ViewState, 'settings' | 'card' | 'serverUrl' | 'testKey' | 'debugBuild' | 'startWithWindows' | 'lastProofSeconds'>;
  private cardView: CardView | null = null;
  private askCounter = 0;
  private askLink: Extract<DeepLink, { kind: 'verify' }> | null = null;
  private askRaw: string | null = null;
  private askCloseTimer: ReturnType<typeof setTimeout> | null = null;
  private linkFlow: { token: number; keyName: string | null; provider: DeviceKeyProvider; timer: ReturnType<typeof setTimeout> | null } | null = null;
  private linkToken = 0;
  /** The Aadhaar QR text between "read" and "build". Main-process memory only, never saved or shown. */
  private pendingQr: AcceptedQr | null = null;
  private pendingQrTimer: ReturnType<typeof setTimeout> | null = null;
  private aadhaarFlow: { token: number; ctl: AbortController } | null = null;
  private aadhaarToken = 0;
  private lastProofSeconds: number | null = null;
  private loginOn: boolean | null = null;
  private catalogLoading: Promise<void> | null = null;
  /** "connector:singpass" -> "Singpass (Myinfo)", from the catalog. */
  private readonly connectorLabels = new Map<string, string>();
  private connectFlow: {
    token: number;
    provider: DeviceKeyProvider;
    name: string | null;
    state: string | null;
    api: V18Api;
    label: string;
    connectorId: string;
    timer: ReturnType<typeof setTimeout> | null;
    expiresAt: number;
    authUrl: string | null;
    polling?: boolean;
  } | null = null;
  private connectToken = 0;
  private readonly now: () => number;

  constructor(private readonly deps: EngineDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.state = sanitizeState(this.safeLoad(), this.storeOpts());
    if (deps.serverOverride) this.state.serverUrl = sanitizeState({ ...this.state, serverUrl: deps.serverOverride }, this.storeOpts()).serverUrl;
    this.view = {
      screen: this.state.settings.firstRunDone ? 'home' : 'welcome',
      testMode: null,
      serverReachable: null,
      aadhaarReady: null,
      proofFilesCached: false,
      hello: { ok: false, code: 'CHECKING' },
      childAccount: 'unknown',
      link: null,
      connect: null,
      catalog: { status: 'loading', countries: [] },
      localeCountry: deps.localeCountry && /^[A-Z]{2}$/.test(deps.localeCountry) ? deps.localeCountry : null,
      work: null,
      error: null,
      aadhaar: null,
      notice: null,
      busy: false,
      ask: null,
    };
    this.rebuildCardView();
  }

  // ------------------------------------------------------------------ state helpers

  private storeOpts() {
    return { debug: this.deps.debug, defaultServerUrl: defaultServer(this.deps.debug), extraServerOrigins: this.deps.extraServerOrigins };
  }

  private safeLoad(): unknown {
    try {
      return this.deps.store.load();
    } catch {
      return null;
    }
  }

  private persist(): void {
    this.state = sanitizeState(this.state, this.storeOpts());
    this.deps.store.save(serializeState(this.state, this.storeOpts()));
  }

  private api(baseUrl = this.state.serverUrl): V18Api {
    return new V18Api(baseUrl, this.deps.fetchImpl);
  }

  /** The key provider for NEW keys. TEST software keys only with the explicit flag. */
  private newKeyProvider(): DeviceKeyProvider {
    return this.deps.testKeys ?? this.deps.hello;
  }

  private providerFor(alias: string): { provider: DeviceKeyProvider; name: string } | null {
    const a = splitAlias(alias);
    if (!a) return null;
    if (a.kind === 'hello') return { provider: this.deps.hello, name: a.name };
    if (a.kind === 'test-software' && this.deps.testKeys) return { provider: this.deps.testKeys, name: a.name };
    return null;
  }

  private rebuildCardView(): void {
    const c = this.state.card;
    if (!c) {
      this.cardView = null;
      return;
    }
    const msLeft = Date.parse(c.validUntil) - this.now();
    this.cardView = {
      method: c.method,
      methodLabel: methodLabel(c.method, this.connectorLabels),
      validUntil: c.validUntil,
      validUntilLabel: dateLabel(c.validUntil),
      daysLeft: Math.max(0, Math.ceil(msLeft / 86400000)),
      expired: msLeft <= 0,
      protection: this.cardView?.protection ?? null,
      testKey: c.keyAlias.startsWith('test-software:'),
    };
  }

  getView(): ViewState {
    return {
      ...this.view,
      debugBuild: this.deps.debug,
      testKey: this.deps.testKeys !== null,
      startWithWindows: this.loginOn,
      lastProofSeconds: this.lastProofSeconds,
      serverUrl: this.state.serverUrl,
      settings: { ...this.state.settings },
      card: this.cardView ? { ...this.cardView } : null,
    };
  }

  getSettings(): StoredSettings {
    return { ...this.state.settings };
  }

  private emit(): void {
    this.rebuildCardView();
    this.deps.onChange(this.getView());
  }

  private setScreen(screen: MainScreen): void {
    this.view.screen = screen;
    if (screen !== 'card-working') this.view.work = null;
    if (screen !== 'card-qr') this.view.aadhaar = null;
    // The Aadhaar QR is dropped as soon as the user leaves the Aadhaar screens.
    if (screen !== 'card-qr' && screen !== 'card-working') this.dropQr();
  }

  // ------------------------------------------------------------------ start-up

  async init(): Promise<void> {
    try {
      this.loginOn = this.deps.loginItem ? this.deps.loginItem.get() : null;
    } catch {
      this.loginOn = null;
    }
    this.view.proofFilesCached = this.deps.artifacts?.isCached() ?? false;
    this.emit();
    const [hello] = await Promise.all([this.newKeyProvider().check(), this.refreshServer(false), this.checkChildAccount(), this.loadCatalog(false)]);
    this.view.hello = hello.ok ? { ok: true } : { ok: false, code: hello.code, detail: hello.detail };
    await this.checkCard();
    this.emit();
  }

  async refreshServer(emit = true): Promise<void> {
    try {
      const h = await this.api().health();
      this.view.testMode = h.devMode;
      this.view.serverReachable = true;
      const m = h.methods && typeof h.methods === 'object' ? (h.methods as Record<string, unknown>).anon_aadhaar : undefined;
      this.view.aadhaarReady = typeof m === 'string' ? m === 'ready' : null;
    } catch {
      this.view.serverReachable = false;
    }
    if (emit) this.emit();
  }

  private async checkChildAccount(): Promise<void> {
    if (!this.deps.ageConsent) return;
    try {
      const a = await this.deps.ageConsent();
      if (a.child === 'included' || a.minor === 'included') this.view.childAccount = 'yes';
      else if (a.child === 'not_included' && a.minor === 'not_included') this.view.childAccount = 'no';
      else this.view.childAccount = 'unknown';
    } catch {
      this.view.childAccount = 'unknown';
    }
  }

  /** Ask the server whether the saved card still works, and check its key is still there. */
  private async checkCard(): Promise<void> {
    try {
      await this.checkCardInner();
    } finally {
      // The card may have been removed or changed: never leave a stale card picture behind.
      this.rebuildCardView();
    }
  }

  private async checkCardInner(): Promise<void> {
    const card = this.state.card;
    if (!card) return;
    const p = this.providerFor(card.keyAlias);
    if (!p) {
      this.view.notice = 'Your saved card used a TEST key, and TEST keys are forgotten when V18 closes. The card was removed from this PC.';
      this.state.card = null;
      this.persist();
      return;
    }
    try {
      await p.provider.publicKey(p.name);
    } catch (err) {
      if (err instanceof DeviceKeyError && err.code === 'KEY_NOT_FOUND') {
        this.view.notice = "The Windows Hello key for your card is gone (this happens after a Windows Hello reset). The card was removed from this PC. You can make a new one.";
        this.state.card = null;
        this.persist();
        return;
      }
    }
    void p.provider.protection(p.name).then((prot) => {
      if (this.cardView && this.state.card?.keyAlias === card.keyAlias) {
        this.cardView.protection = prot;
        this.emit();
      }
    });
    try {
      const s = await this.api().cardStatus(card.cardId);
      if (s.status === 'revoked') {
        await p.provider.remove(p.name).catch(() => undefined);
        this.state.card = null;
        this.persist();
        this.view.notice = 'Your age card was turned off on the V18 server, so it was removed from this PC.';
      } else if (s.validUntil && s.validUntil !== card.validUntil && !Number.isNaN(Date.parse(s.validUntil))) {
        this.state.card = { ...card, validUntil: s.validUntil };
        this.persist();
      }
    } catch {
      // Offline or the server does not know this endpoint yet: keep the card as it is.
    }
  }

  // ------------------------------------------------------------------ navigation and settings

  firstRun(sharedPc: boolean): void {
    this.state.settings.firstRunDone = true;
    this.state.settings.sharedPc = sharedPc;
    if (sharedPc) this.state.card = null;
    this.persist();
    this.setScreen('home');
    this.emit();
  }

  go(screen: string): void {
    if (!(NAV_SCREENS as readonly string[]).includes(screen)) return;
    let target = screen as MainScreen;
    if (this.state.settings.sharedPc && target.startsWith('card-')) target = 'home';
    if (this.view.screen === 'card-phone') this.cancelLink();
    if (this.aadhaarFlow) this.aadhaarCancel(false);
    if (this.connectFlow) this.cancelConnect();
    if (target === 'card-country' && this.view.catalog.status !== 'ok') void this.loadCatalog();
    this.view.notice = null;
    this.view.error = null;
    this.setScreen(target);
    if (target === 'card-qr') this.view.aadhaar = { stage: 'pick' };
    this.emit();
  }

  dismissNotice(): void {
    this.view.notice = null;
    this.emit();
  }

  async setSettings(patch: { notify?: unknown; sharedPc?: unknown; startWithWindows?: unknown }): Promise<void> {
    if (typeof patch.notify === 'boolean') this.state.settings.notify = patch.notify;
    if (typeof patch.startWithWindows === 'boolean' && this.deps.loginItem) {
      try {
        this.deps.loginItem.set(patch.startWithWindows);
        this.loginOn = this.deps.loginItem.get();
      } catch {
        this.view.notice = "Windows didn't let V18 change this setting.";
      }
    }
    if (typeof patch.sharedPc === 'boolean' && patch.sharedPc !== this.state.settings.sharedPc) {
      if (patch.sharedPc && this.state.card) {
        // Shared-PC mode keeps no card at all. Revoke on the server if we can, and always remove locally.
        const serverOk = await this.removeCard({ bestEffort: true });
        this.view.notice = serverOk
          ? 'Shared PC mode is on. Your age card was deleted from this PC and turned off on the V18 server.'
          : "Shared PC mode is on. Your age card was deleted from this PC. V18's server couldn't be told, so the card stays counted there until it expires.";
      }
      this.state.settings.sharedPc = patch.sharedPc;
    }
    this.persist();
    this.emit();
  }

  // ------------------------------------------------------------------ keys

  private async ensureKeysUsable(): Promise<boolean> {
    const check = await this.newKeyProvider().check();
    this.view.hello = check.ok ? { ok: true } : { ok: false, code: check.code, detail: check.detail };
    if (!check.ok) {
      this.view.error = { title: "We couldn't check this PC's security", detail: check.detail, code: check.code };
      this.setScreen('err-integrity');
      this.emit();
      return false;
    }
    return true;
  }

  private async signWith(provider: DeviceKeyProvider, name: string, signingString: string) {
    const { alg, sig } = await provider.sign(name, signingBytes(signingString));
    return { alg, sig: b64urlEncode(sig) };
  }

  private saveCard(card: Card, alias: string): void {
    const stored: StoredCard = { cardId: card.cardId, method: card.method, validUntil: card.validUntil, keyAlias: alias };
    this.state.card = stored;
    this.persist();
    this.cardView = null;
    void this.checkCard().then(() => this.emit());
  }

  private showError(screen: MainScreen, title: string, detail: string, code?: string): void {
    this.view.error = { title, detail, code };
    this.setScreen(screen);
  }

  private flowError(err: unknown, context: 'card' | 'delete'): void {
    if (err instanceof OfflineError) {
      this.showError('err-offline', "You're offline", context === 'card' ? 'V18 needs the internet to make an age card.' : 'V18 needs the internet to delete your card on the server.');
    } else if (err instanceof DeviceKeyError) {
      if (err.code === 'USER_CANCELED') {
        this.setScreen(context === 'card' ? 'card-methods' : 'settings');
        this.view.notice = 'Windows Hello was cancelled. Nothing was saved or sent.';
      } else if (err.code === 'KEY_NOT_FOUND' || err.code === 'SELF_CHECK_FAILED' || err.code === 'HELLO_ERROR') {
        this.showError('err-general', 'Windows Hello had a problem', err.message, err.code);
      } else {
        this.showError('err-integrity', "We couldn't check this PC's security", err.message, err.code);
      }
    } else if (isUnderAge(err)) {
      this.showError('err-under18', 'This is for adults (18+)', "The ID shows you're under 18, so no age card was made.");
    } else if (err instanceof ApiError) {
      if (err.code === 'METHOD_DISABLED' || err.code === 'METHOD_NOT_READY') {
        this.showError('err-general', "This way isn't available", `The V18 server says: ${err.message}`, err.code);
      } else if (err.code === 'NULLIFIER_OVERUSED') {
        this.showError('err-general', 'This ID already has too many age cards', 'Delete an age card on another device first, then try again.', err.code);
      } else if (err.code === 'PROOF_INVALID' || err.code === 'INVALID_PROOF' || err.code === 'BAD_SEAL') {
        this.showError('err-seal', "This ID's seal didn't check out", err.message, err.code);
      } else {
        this.showError('err-general', 'Something went wrong', `The V18 server said: ${err.message} (${err.code})`, err.code);
      }
    } else {
      this.showError('err-general', 'Something went wrong', err instanceof Error ? err.message : String(err));
    }
  }

  // ------------------------------------------------------------------ get a card: phone hand-off (device link, 3.9)

  async startLink(forLabel?: string): Promise<void> {
    if (this.state.settings.sharedPc) return this.go('home');
    if (this.connectFlow) this.cancelConnect();
    const label = typeof forLabel === 'string' && forLabel.length <= 80 ? forLabel : this.view.link?.forLabel;
    if (!(await this.ensureKeysUsable())) return;
    const token = ++this.linkToken;
    const provider = this.newKeyProvider();
    const reuse = this.linkFlow && this.linkFlow.provider === provider ? this.linkFlow.keyName : null;
    if (this.linkFlow?.timer) clearTimeout(this.linkFlow.timer);
    this.linkFlow = { token, keyName: reuse, provider, timer: null };
    this.setScreen('card-phone');
    this.view.link = { forLabel: label, status: 'hello', message: reuse ? 'Approve with Windows Hello to make a new code.' : 'Approve with Windows Hello. This makes a key for your age card, locked in this PC.' };
    this.emit();
    try {
      let name = reuse;
      if (!name) {
        name = newKeyName();
        await provider.create(name);
        if (this.linkFlow?.token !== token) return void provider.remove(name);
        this.linkFlow.keyName = name;
      }
      const jwk = await provider.publicKey(name);
      const api = this.api();
      const { challenge } = await api.challenge();
      const deviceSignature = await this.signWith(provider, name, cardIssueString(challenge, jwkThumbprint(jwk)));
      if (this.linkFlow?.token !== token) return;
      const start = await api.linkStart({ devicePublicKey: devicePublicKeyBody(jwk), challenge, deviceSignature });
      let deepLink = `v18://link?id=${encodeURIComponent(start.linkId)}&server=${encodeURIComponent(this.state.serverUrl)}`;
      try {
        const parsed = parseDeepLink(start.deepLink, { debug: this.deps.debug, defaultServer: this.state.serverUrl, extraServerOrigins: this.deps.extraServerOrigins });
        if (parsed.kind === 'link' && parsed.linkId === start.linkId) deepLink = start.deepLink;
      } catch {
        // The server's link is not in the expected shape; use the one built above.
      }
      const qr = await this.deps.makeQr(deepLink);
      if (this.linkFlow?.token !== token) return;
      const expiresAt = this.now() + Math.max(10, Math.min(start.expiresIn, 600)) * 1000;
      this.view.link = { forLabel: label, status: 'waiting', qr, expiresAt };
      this.emit();
      this.pollLink(token, api, start.linkId, name, provider, expiresAt);
    } catch (err) {
      if (this.linkFlow?.token !== token) return;
      const keyName = this.linkFlow.keyName;
      this.linkFlow = null;
      this.view.link = null;
      if (keyName) await provider.remove(keyName).catch(() => undefined);
      this.flowError(err, 'card');
      this.emit();
    }
  }

  private pollLink(token: number, api: V18Api, linkId: string, name: string, provider: DeviceKeyProvider, expiresAt: number): void {
    const tick = async () => {
      if (this.linkFlow?.token !== token) return;
      if (this.now() > expiresAt) {
        this.view.link = { forLabel: this.view.link?.forLabel, status: 'expired' };
        this.linkFlow.timer = null;
        this.emit();
        return;
      }
      try {
        const r = await api.linkPoll(linkId);
        if (this.linkFlow?.token !== token) return;
        if (r.status === 'approved' && r.card) {
          this.linkFlow = null;
          this.view.link = null;
          this.saveCard(r.card, aliasFor(provider, name));
          this.setScreen('card-saved');
          this.emit();
          return;
        }
        if (r.status === 'expired') {
          this.view.link = { status: 'expired' };
          this.linkFlow.timer = null;
          this.emit();
          return;
        }
      } catch (err) {
        if (!(err instanceof OfflineError) && err instanceof ApiError && err.status === 404) {
          this.view.link = { status: 'expired' };
          if (this.linkFlow) this.linkFlow.timer = null;
          this.emit();
          return;
        }
        // Offline for a moment: keep trying until the code runs out.
      }
      if (this.linkFlow?.token === token) this.linkFlow.timer = setTimeout(tick, this.deps.linkPollMs ?? 2000);
    };
    if (this.linkFlow) this.linkFlow.timer = setTimeout(tick, this.deps.linkPollMs ?? 2000);
  }

  cancelLink(): void {
    const f = this.linkFlow;
    this.linkFlow = null;
    this.linkToken++;
    this.view.link = null;
    if (f?.timer) clearTimeout(f.timer);
    if (f?.keyName) void f.provider.remove(f.keyName).catch(() => undefined);
  }

  // ------------------------------------------------------------------ country catalog (4d.2)

  /**
   * Load the country list from the server. Asked twice (platform=windows and platform=android)
   * and joined, so the PC can list phone-only IDs as "with your phone" whichever way the server
   * filters by platform.
   */
  async loadCatalog(emit = true): Promise<void> {
    if (this.catalogLoading) return this.catalogLoading;
    this.catalogLoading = (async () => {
      if (this.view.catalog.status !== 'ok') this.view.catalog = { status: 'loading', countries: [] };
      if (emit) this.emit();
      try {
        const api = this.api();
        const [pc, phone] = await Promise.all([api.catalog('windows'), api.catalog('android').catch(() => ({ countries: [] }))]);
        const countries = mergeCatalogs(parseCatalog(pc), parseCatalog(phone))
          .map((c) => ({ code: c.code, name: c.name, region: c.region, methods: pcMethods(c) }))
          .filter((c) => c.methods.length > 0);
        this.view.catalog = { status: 'ok', countries };
        this.connectorLabels.clear();
        for (const c of countries) for (const m of c.methods) if (m.kind === 'connector') this.connectorLabels.set(m.method, m.label);
      } catch (err) {
        this.view.catalog = {
          status: err instanceof OfflineError ? 'offline' : 'error',
          countries: [],
          message: err instanceof OfflineError ? "V18 couldn't reach its server." : "The V18 server didn't send a list of IDs.",
        };
      } finally {
        this.catalogLoading = null;
      }
      if (emit) this.emit();
    })();
    return this.catalogLoading;
  }

  // ------------------------------------------------------------------ get a card: government or bank login (4d.4)

  /**
   * Start a login connector: make a Windows Hello key, sign the request, ask the server for the
   * provider's login page, and open it in the system browser. The server reads only the birth date
   * (or an "over 18" answer), decides, keeps nothing else, and issues a card bound to this PC's key.
   */
  async startConnector(connectorId: string): Promise<void> {
    if (this.state.settings.sharedPc) return this.go('home');
    const method = `connector:${connectorId}`;
    const offered = this.view.catalog.countries.some((c) => c.methods.some((m) => m.kind === 'connector' && m.connectorId === connectorId));
    if (!/^[a-z0-9_]{2,40}$/.test(connectorId) || !offered || !this.deps.openExternal) return;
    const label = this.connectorLabels.get(method) ?? connectorId;
    if (!(await this.ensureKeysUsable())) return;
    this.cancelConnect();
    const token = ++this.connectToken;
    const provider = this.newKeyProvider();
    const api = this.api();
    const flow: NonNullable<V18Engine['connectFlow']> = { token, provider, name: null, state: null, api, label, connectorId, timer: null, expiresAt: 0, authUrl: null };
    this.connectFlow = flow;
    const live = () => this.connectFlow?.token === token;
    this.setScreen('card-connect');
    this.view.connect = { label, connectorId, status: 'hello' };
    this.emit();
    try {
      flow.name = newKeyName();
      const jwk = await provider.create(flow.name);
      if (!live()) return void provider.remove(flow.name).catch(() => undefined);
      this.view.connect = { label, connectorId, status: 'starting' };
      this.emit();
      const { challenge } = await api.challenge();
      // PROTOCOL 4d.4 names no signing string for connect/start; V18 uses the issue-card proof of
      // possession (as link/start does). See docs/windows/WALKTHROUGH.md, "Design notes".
      const deviceSignature = await this.signWith(provider, flow.name, cardIssueString(challenge, jwkThumbprint(jwk)));
      if (!live()) throw new DeviceKeyError('USER_CANCELED', 'cancelled');
      const start = await api.connectStart(connectorId, { challenge, devicePublicKey: devicePublicKeyBody(jwk), deviceSignature });
      const authUrl = this.checkAuthUrl(start.authUrl);
      const state = start.state ?? new URL(authUrl).searchParams.get('state');
      if (!state || !/^[A-Za-z0-9._~-]{8,512}$/.test(state)) throw new ApiError(502, 'BAD_RESPONSE', "The server's login answer has no usable state.");
      flow.state = state;
      flow.authUrl = authUrl;
      flow.expiresAt = this.now() + Math.max(30, Math.min(start.expiresIn, 1800)) * 1000;
      this.view.connect = { label, connectorId, status: 'browser', expiresAt: flow.expiresAt };
      this.emit();
      await this.deps.openExternal(authUrl);
      this.scheduleConnectPoll(token, this.deps.linkPollMs ?? 2000);
    } catch (err) {
      if (!live()) return;
      this.connectFlow = null;
      this.view.connect = null;
      if (flow.name) await provider.remove(flow.name).catch(() => undefined);
      this.flowError(err, 'card');
      this.emit();
    }
  }

  /** The provider's login page must be https (plain http only for a test provider on this PC, debug builds). */
  private checkAuthUrl(raw: string): string {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      throw new ApiError(502, 'BAD_RESPONSE', "The server's login link isn't a web address.");
    }
    const loopback = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
    if (u.username || u.password || !(u.protocol === 'https:' || (this.deps.debug && u.protocol === 'http:' && loopback))) {
      throw new ApiError(502, 'BAD_RESPONSE', "The server's login link isn't a safe web address, so V18 didn't open it.");
    }
    return u.href;
  }

  /** Open the provider's login page again (for example after the browser tab was closed). */
  async connectReopen(): Promise<void> {
    const f = this.connectFlow;
    if (f?.authUrl && this.deps.openExternal) await this.deps.openExternal(f.authUrl);
  }

  private scheduleConnectPoll(token: number, ms: number): void {
    const f = this.connectFlow;
    if (!f || f.token !== token) return;
    if (f.timer) clearTimeout(f.timer);
    f.timer = setTimeout(() => void this.pollConnect(token), ms);
  }

  private async pollConnect(token: number): Promise<void> {
    const f = this.connectFlow;
    if (!f || f.token !== token || !f.state || !f.name) return;
    if (f.polling) return;
    f.polling = true;
    let again = true;
    try {
      if (this.now() > f.expiresAt) {
        again = false;
        return this.connectEnd(token, 'expired');
      }
      const s = await f.api.connectSession(f.state);
      if (this.connectFlow?.token !== token) return;
      const st = s.status;
      if ((st === 'ok' || st === 'approved' || st === 'done' || st === 'complete' || st === 'completed') && s.card) {
        again = false;
        const alias = aliasFor(f.provider, f.name);
        this.connectFlow = null;
        this.view.connect = null;
        this.saveCard(s.card, alias);
        this.setScreen('card-saved');
        this.emit();
        return;
      }
      if (st === 'under_age' || s.code === 'UNDER_AGE') {
        again = false;
        return this.connectEnd(token, 'under18');
      }
      if (st === 'expired') {
        again = false;
        return this.connectEnd(token, 'expired');
      }
      if (st === 'ok' && s.cardDelivered) {
        // The card was handed out to an earlier request whose answer never arrived. It is bound to
        // this PC's key, but V18 doesn't know its ID, so start again.
        again = false;
        return this.connectEnd(token, 'failed', 'The card was sent, but its answer got lost on the way. Nothing was saved here; please try again.');
      }
      if (st === 'failed' || st === 'error' || st === 'cancelled' || st === 'canceled' || st === 'denied' || st === 'rejected') {
        again = false;
        return this.connectEnd(token, 'failed', connectErrorText(f.label, s.code, s.error));
      }
      // waiting / pending / started: keep asking.
    } catch (err) {
      if (err instanceof ApiError && (err.status === 404 || err.status === 410)) {
        again = false;
        return this.connectEnd(token, 'expired');
      }
      // Offline for a moment: keep trying until the login runs out.
    } finally {
      const cur = this.connectFlow;
      if (cur && cur.token === token) {
        cur.polling = false;
        if (again) this.scheduleConnectPoll(token, this.deps.linkPollMs ?? 2000);
      }
    }
  }

  private connectEnd(token: number, how: 'expired' | 'under18' | 'failed', detail?: string): void {
    const f = this.connectFlow;
    if (!f || f.token !== token) return;
    if (f.timer) clearTimeout(f.timer);
    if (f.name) void f.provider.remove(f.name).catch(() => undefined);
    const label = f.label;
    const connectorId = f.connectorId;
    this.connectFlow = null;
    if (how === 'expired') {
      this.setScreen('card-connect');
      this.view.connect = { label, connectorId, status: 'expired' };
    } else if (how === 'under18') {
      this.view.connect = null;
      this.showError('err-under18', 'This is for adults (18+)', `${label} says you're under 18, so no age card was made.`);
    } else {
      this.view.connect = null;
      this.showError('err-general', `The ${label} sign-in didn't finish`, detail ?? 'The sign-in was cancelled or refused. Nothing was saved.', 'CONNECT_FAILED');
    }
    this.emit();
  }

  /** A v18://connect link arrived (the browser came back). Ask the server; never trust the link alone. */
  private async connectLinkArrived(link: Extract<DeepLink, { kind: 'connect' }>): Promise<void> {
    const f = this.connectFlow;
    if (!f || !f.state || (link.state && link.state !== f.state)) {
      this.view.notice = 'A sign-in page tried to give V18 an age card, but V18 wasn\'t waiting for one. Nothing was changed.';
      this.emit();
      return;
    }
    await this.pollConnect(f.token);
  }

  cancelConnect(): void {
    const f = this.connectFlow;
    this.connectFlow = null;
    this.connectToken++;
    this.view.connect = null;
    if (f?.timer) clearTimeout(f.timer);
    if (f?.name) void f.provider.remove(f.name).catch(() => undefined);
  }

  // ------------------------------------------------------------------ get a card: TEST issuer (dev servers only)

  async issueTestDev(kind: 'adult' | 'under18'): Promise<void> {
    if (this.state.settings.sharedPc) return this.go('home');
    await this.refreshServer(false);
    if (this.view.testMode !== true) {
      this.showError(
        'err-general',
        'TEST cards need a TEST MODE server',
        this.view.serverReachable === false
          ? "V18 couldn't reach the server, so it can't check that it is in TEST MODE."
          : 'This server is not in TEST MODE, so it does not make TEST cards.',
        'METHOD_DISABLED',
      );
      return this.emit();
    }
    if (!(await this.ensureKeysUsable())) return;
    const provider = this.newKeyProvider();
    const steps = ['Make a key in Windows Hello', 'Approve the request with Windows Hello', 'Send to the V18 TEST issuer', 'Save your age card'];
    const progress = (cur: number) => {
      const s: WorkStep[] = steps.map((label, i) => ({ label, state: i < cur ? 'done' : i === cur ? 'cur' : 'todo' }));
      this.view.work = { title: 'Making a TEST age card', text: 'TEST MODE: no ID is read. The TEST issuer pretends a made-up person is ' + (kind === 'adult' ? '18 or older.' : 'under 18.'), steps: s, test: true };
      this.view.screen = 'card-working';
      this.emit();
    };
    let name: string | null = null;
    try {
      progress(0);
      name = newKeyName();
      const jwk = await provider.create(name);
      progress(1);
      const api = this.api();
      const { challenge } = await api.challenge();
      const deviceSignature = await this.signWith(provider, name, cardIssueString(challenge, jwkThumbprint(jwk)));
      progress(2);
      const d = new Date(this.now());
      const birthDate = kind === 'adult' ? '1990-01-01' : `${d.getUTCFullYear() - 15}-01-01`;
      const card = await api.issueCard({
        method: 'test_dev',
        challenge,
        devicePublicKey: devicePublicKeyBody(jwk),
        deviceSignature,
        proof: { testSubjectId: 'test-pc-' + newKeyName().slice(9), birthDate },
      });
      progress(3);
      this.saveCard(card, aliasFor(provider, name));
      name = null;
      this.setScreen('card-saved');
    } catch (err) {
      if (name) await provider.remove(name).catch(() => undefined);
      this.flowError(err, 'card');
    }
    this.emit();
  }

  // ------------------------------------------------------------------ get a card: Aadhaar Secure QR (anon_aadhaar, 3.5 + 4b + 4c)

  setAadhaar(view: AadhaarView): void {
    this.setScreen('card-qr');
    this.view.aadhaar = view;
    this.emit();
  }

  private keepQr(qr: AcceptedQr): void {
    this.dropQr();
    this.pendingQr = qr;
    this.pendingQrTimer = setTimeout(() => {
      this.dropQr();
      if (this.view.screen === 'card-qr' && this.view.aadhaar?.stage === 'read') this.setAadhaar({ stage: 'pick' });
    }, QR_KEEP_MS);
    this.pendingQrTimer.unref?.();
  }

  private dropQr(): void {
    this.pendingQr = null;
    if (this.pendingQrTimer) clearTimeout(this.pendingQrTimer);
    this.pendingQrTimer = null;
  }

  /** Read an Aadhaar QR file the user picked (picture or .txt) and check its seal on this PC. */
  async aadhaarReadFile(file: string): Promise<void> {
    if (this.state.settings.sharedPc || this.aadhaarFlow) return;
    this.dropQr();
    await this.refreshServer(false);
    const r = await readAadhaarFile(file, { testMode: this.view.testMode === true, assetsDir: this.deps.assetsDir ?? '', now: new Date(this.now()) });
    this.setAadhaar(r.view);
    if (r.accepted) this.keepQr(r.accepted);
  }

  aadhaarReset(): void {
    if (this.aadhaarFlow) return;
    this.dropQr();
    this.setAadhaar({ stage: 'pick' });
  }

  /** Stop the Aadhaar flow (download or proof). Nothing is sent; the new key, if any, is removed. */
  aadhaarCancel(show = true): void {
    const f = this.aadhaarFlow;
    if (!f) return;
    this.aadhaarFlow = null;
    this.aadhaarToken++;
    f.ctl.abort();
    this.dropQr();
    if (show) {
      this.setAadhaar({ stage: 'pick' });
      this.view.notice = 'Stopped. Nothing was sent, and no age card was made. Proof files that finished downloading are kept for next time.';
      this.emit();
    }
  }

  /**
   * Build the Anon Aadhaar proof on this PC and turn it into an age card:
   * circuit files (download once, check SHA-256) -> Windows Hello key -> challenge -> Hello
   * signature -> proof in the proof builder process -> POST /card/issue -> save.
   */
  async aadhaarBuild(): Promise<void> {
    const qr = this.pendingQr;
    if (!qr || this.state.settings.sharedPc || this.aadhaarFlow) return;
    const artifacts = this.deps.artifacts;
    const spawnProver = this.deps.spawnProver;
    if (!artifacts || !spawnProver) {
      this.showError('err-general', "This copy of V18 can't build proofs", "The proof builder isn't part of this build.");
      return this.emit();
    }
    if (!(await this.ensureKeysUsable())) return;
    const token = ++this.aadhaarToken;
    const ctl = new AbortController();
    this.aadhaarFlow = { token, ctl };
    const live = () => this.aadhaarFlow?.token === token;
    const provider = this.newKeyProvider();
    const api = this.api();
    const needDownload = !artifacts.isCached();
    const steps = [
      needDownload ? 'Download the proof files (about 620 MB, first time only)' : 'Proof files are already on this PC',
      'Check the proof files (SHA-256)',
      'Make a key in Windows Hello',
      'Approve the request with Windows Hello',
      'Build the zero-knowledge proof on this PC',
      'Send the proof to V18',
      'Save your age card',
    ];
    let lastEmit = 0;
    const show = (cur: number, progress: WorkView['progress'] = null, since?: number, force = true) => {
      if (!live()) return;
      const st: WorkStep[] = steps.map((label, i) => ({ label, state: i < cur ? 'done' : i === cur ? 'cur' : 'todo' }));
      this.view.work = {
        title: qr.test ? 'Making a TEST age card from your Aadhaar QR' : 'Making your age card from your Aadhaar QR',
        text: qr.test
          ? 'TEST MODE: this QR has the Anon Aadhaar TEST seal. The proof is real, but only TEST servers accept it. It proves only "18+".'
          : 'Your PC builds a zero-knowledge proof from the QR. It proves only "18+". Your name, birth date and Aadhaar number never leave this PC.',
        steps: st,
        test: qr.test,
        progress,
        since,
        cancellable: cur <= 4,
      };
      this.view.screen = 'card-working';
      const t = Date.now();
      if (force || t - lastEmit > 200) {
        lastEmit = t;
        this.emit();
      }
    };
    const mb = (n: number) => `${Math.round(n / 1e6)} MB`;
    let name: string | null = null;
    let proveStart = 0;
    try {
      show(0);
      const health = await api.health();
      if (qr.test && !health.devMode) throw new ProverError('BAD_QR', 'This QR has a TEST seal, and this V18 server is not a TEST server.');
      const seed = health.aadhaarNullifierSeed;
      const m = health.methods && typeof health.methods === 'object' ? (health.methods as Record<string, unknown>).anon_aadhaar : undefined;
      if (typeof seed !== 'string' || !/^\d{1,77}$/.test(seed) || (typeof m === 'string' && m !== 'ready')) {
        throw new ApiError(503, 'METHOD_NOT_CONFIGURED', "This V18 server isn't set up for Aadhaar cards yet.");
      }
      const entries = await artifacts.manifest(api.baseUrl, ctl.signal);
      const paths = await artifacts.ensure(
        api.baseUrl,
        entries,
        (p) => {
          const pct = p.total > 0 ? (p.done / p.total) * 100 : 100;
          if (p.phase === 'download') show(0, { pct, label: 'Downloading from the V18 server', detail: `${mb(p.done)} of ${mb(p.total)}` }, undefined, false);
          else show(1, { pct, label: 'Checking each file against its pinned SHA-256', detail: `${mb(p.done)} of ${mb(p.total)}` }, undefined, false);
        },
        ctl.signal,
      );
      this.view.proofFilesCached = true;
      if (!live()) return;

      show(2);
      name = newKeyName();
      const jwk = await provider.create(name);
      if (!live()) throw new ArtifactError('CANCELLED', 'Cancelled.');
      show(3);
      const { challenge } = await api.challenge();
      const thumbprint = jwkThumbprint(jwk);
      const deviceSignature = await this.signWith(provider, name, cardIssueString(challenge, thumbprint));
      if (!live()) throw new ArtifactError('CANCELLED', 'Cancelled.');

      proveStart = this.now();
      show(4, { pct: 0, label: 'Starting the proof builder' }, proveStart);
      const result = await runProver(
        spawnProver,
        { type: 'prove', qrText: qr.qrText, certPem: qr.certPem, nullifierSeed: seed, signal: aadhaarSignal(challenge, thumbprint), wasmPath: paths.wasm, zkeyPath: paths.zkey, vkeyPath: paths.vkey },
        {
          signal: ctl.signal,
          timeoutMs: this.deps.proveTimeoutMs,
          onProgress: (stage, pct, label) => {
            // The circuit inputs and the witness are quick; the Groth16 proof is most of the time.
            const overall = stage === 'inputs' ? 1 : stage === 'witness' ? 3 : stage === 'prove' ? 5 + pct * 0.93 : 99;
            show(4, { pct: overall, label: label ?? 'Building the proof' }, proveStart);
          },
        },
      );
      // The personal data is not needed any more.
      this.dropQr();
      this.lastProofSeconds = Math.round(result.ms.total / 1000);
      if (!live()) return;

      show(5);
      const card = await api.issueCard({ method: 'anon_aadhaar', challenge, devicePublicKey: devicePublicKeyBody(jwk), deviceSignature, proof: result.proof });
      show(6);
      this.saveCard(card, aliasFor(provider, name));
      name = null;
      this.aadhaarFlow = null;
      this.setScreen('card-saved');
      this.emit();
    } catch (err) {
      if (name) await provider.remove(name).catch(() => undefined);
      if (!live()) return; // cancelled: aadhaarCancel already showed the screen
      this.aadhaarFlow = null;
      this.dropQr();
      this.aadhaarError(err, proveStart);
      this.emit();
    }
  }

  private aadhaarError(err: unknown, proveStart: number): void {
    if (err instanceof ArtifactError) {
      if (err.code === 'CANCELLED') return this.setAadhaar({ stage: 'pick' });
      const title =
        err.code === 'NO_ARTIFACTS'
          ? "This V18 server can't make Aadhaar cards yet"
          : err.code === 'DISK_FULL'
            ? 'Not enough disk space'
            : err.code === 'NOT_PINNED'
              ? "The proof files don't match this version of V18"
              : "The proof files couldn't be downloaded";
      return this.showError('err-general', title, err.message, err.code);
    }
    if (err instanceof ProverError) {
      if (err.code === 'CANCELLED') return this.setAadhaar({ stage: 'pick' });
      if (err.code === 'BAD_QR') return this.showError('err-seal', "This ID's seal didn't check out", err.message, err.code);
      return this.showError('err-general', "The proof couldn't be built on this PC", `${err.message} Nothing was sent.`, err.code);
    }
    if (err instanceof ApiError && err.code === 'CHALLENGE_INVALID' && proveStart && this.now() - proveStart > 4 * 60 * 1000) {
      return this.showError(
        'err-general',
        'The proof took too long',
        'Each try has a 5-minute window, and this PC needed longer to build the proof. Close other apps and try again, or use your phone instead.',
        err.code,
      );
    }
    if (err instanceof ApiError && err.code === 'METHOD_NOT_CONFIGURED') {
      return this.showError('err-general', "This V18 server can't make Aadhaar cards yet", err.message, err.code);
    }
    this.flowError(err, 'card');
  }

  /** Settings: free the disk space used by the Aadhaar proof files. */
  deleteProofFiles(): void {
    if (this.aadhaarFlow || !this.deps.artifacts) return;
    try {
      this.deps.artifacts.clear();
      this.view.notice = 'The Aadhaar proof files were deleted from this PC.';
    } catch {
      this.view.notice = "Some proof files couldn't be deleted. Close V18 and try again.";
    }
    this.view.proofFilesCached = this.deps.artifacts.isCached();
    this.emit();
  }

  // ------------------------------------------------------------------ delete card

  /** Returns true if the server confirmed the revoke. Always removes the card and key locally when bestEffort. */
  private async removeCard(opts: { bestEffort: boolean }): Promise<boolean> {
    const card = this.state.card;
    if (!card) return true;
    const p = this.providerFor(card.keyAlias);
    let serverOk = false;
    try {
      if (!p) throw new DeviceKeyError('KEY_NOT_FOUND', 'key not available');
      const api = this.api();
      const { challenge } = await api.challenge();
      const deviceSignature = await this.signWith(p.provider, p.name, cardDeleteString(card.cardId, challenge));
      await api.deleteCard(card.cardId, { challenge, deviceSignature });
      serverOk = true;
    } catch (err) {
      // A card the server no longer knows (or already revoked) can just be removed here.
      const gone = err instanceof ApiError && (err.status === 404 || err.status === 410 || err.code === 'CARD_REQUIRED' || err.code === 'CARD_REVOKED');
      if (gone) serverOk = true;
      else if (!opts.bestEffort) throw err;
    }
    if (p) await p.provider.remove(p.name).catch(() => undefined);
    this.state.card = null;
    this.cardView = null;
    this.persist();
    return serverOk;
  }

  async deleteCard(localOnly = false): Promise<void> {
    if (!this.state.card) return;
    this.view.busy = true;
    this.emit();
    try {
      if (localOnly) {
        await this.removeCard({ bestEffort: true });
        this.view.notice = "Your age card was deleted from this PC. V18's server wasn't told, so it stays counted there until it expires.";
      } else {
        await this.removeCard({ bestEffort: false });
        this.view.notice = 'Your age card was deleted from this PC and turned off on the V18 server.';
      }
      this.setScreen('home');
    } catch (err) {
      if (err instanceof OfflineError) {
        this.showError('err-offline', "You're offline", "V18 needs the internet to turn your card off on the server. You can still delete it from this PC only.", 'OFFLINE_DELETE');
      } else {
        this.flowError(err, 'delete');
      }
    } finally {
      this.view.busy = false;
    }
    this.emit();
  }

  // ------------------------------------------------------------------ site asks (3.8): v18://verify

  private setAsk(stage: AskStage, extra: Partial<AskView> = {}): void {
    if (this.askCloseTimer) {
      clearTimeout(this.askCloseTimer);
      this.askCloseTimer = null;
    }
    const link = this.askLink;
    const base: AskView = this.view.ask ?? { id: this.askCounter, stage, origin: null, host: null, minAge: 18 };
    this.view.ask = {
      id: base.id,
      stage,
      origin: link?.origin ?? base.origin,
      host: link ? displayOrigin(link.origin) : base.host,
      minAge: link?.minAge ?? base.minAge,
      cardLine: this.cardView ? `${this.cardView.methodLabel}, valid until ${this.cardView.validUntilLabel}` : undefined,
      ...extra,
    };
    this.emit();
  }

  async handleDeepLink(raw: string): Promise<void> {
    let pre: DeepLink | null = null;
    try {
      pre = parseDeepLink(raw, { debug: this.deps.debug, defaultServer: this.state.serverUrl, extraServerOrigins: this.deps.extraServerOrigins });
    } catch {
      pre = null;
    }
    if (pre?.kind === 'connect') return this.connectLinkArrived(pre);
    this.askRaw = raw;
    this.askCounter++;
    this.view.ask = { id: this.askCounter, stage: 'loading', origin: null, host: null, minAge: 18 };
    let link: DeepLink;
    try {
      link = parseDeepLink(raw, { debug: this.deps.debug, defaultServer: this.state.serverUrl, extraServerOrigins: this.deps.extraServerOrigins });
    } catch (err) {
      this.askLink = null;
      const msg = err instanceof DeepLinkError && err.code === 'SERVER_NOT_ALLOWED'
        ? 'This request points to a server V18 does not trust, so it was stopped. Nothing was shared.'
        : "This request isn't in the right shape, so it was stopped. Nothing was shared.";
      this.setAsk('error', { message: msg });
      this.deps.onAsk?.(this.view.ask!);
      return;
    }
    if (link.kind !== 'verify') {
      this.askLink = null;
      this.setAsk('error', { message: 'This is a code for your phone. Scan it with V18 on your phone instead.' });
      this.deps.onAsk?.(this.view.ask!);
      return;
    }
    this.askLink = link;
    this.setAsk('loading');
    this.deps.onAsk?.(this.view.ask!);
    await this.checkAsk();
  }

  private async checkAsk(): Promise<void> {
    const link = this.askLink;
    if (!link) return;
    // The server's copy of the request is the truth: it checked the site's Origin header.
    try {
      const s = await this.api(link.server).pairingGet(link.sessionId);
      if (s.status !== 'waiting' && s.status !== 'connected') {
        return this.setAsk('error', { message: 'This request has already finished or run out of time. Go back to the site and try again.' });
      }
      if (s.origin !== link.origin || s.challenge !== link.challenge || s.minAge !== link.minAge) {
        return this.setAsk('error', { message: "This request doesn't match what the site asked the V18 server for, so it was stopped. Nothing was shared." });
      }
    } catch (err) {
      if (err instanceof OfflineError) return this.setAsk('offline');
      return this.setAsk('error', { message: 'This request has already finished or run out of time. Go back to the site and try again.' });
    }
    if (this.view.childAccount === 'yes') return this.setAsk('child');
    if (this.state.settings.sharedPc) return this.setAsk('shared');
    if (!this.cardView) return this.setAsk('nocard');
    if (this.cardView.expired) return this.setAsk('expired');
    if (link.minAge > 18) {
      return this.setAsk('error', { message: `This site asks for ${link.minAge}+. Your age card proves 18+ only.` });
    }
    if (link.server !== this.state.serverUrl) {
      return this.setAsk('error', { message: 'This site uses a different V18 server from the one that made your age card.' });
    }
    if (!this.providerFor(this.state.card!.keyAlias)) {
      return this.setAsk('error', { message: 'Your age card used a TEST key that is no longer here. Make a new card.' });
    }
    this.setAsk('confirm');
  }

  async askRetry(): Promise<void> {
    if (this.askRaw && (this.view.ask?.stage === 'offline' || this.view.ask?.stage === 'loading')) {
      this.setAsk('loading');
      await this.checkAsk();
    } else if (this.askLink) {
      this.setAsk('loading');
      await this.checkAsk();
    }
  }

  async askApprove(): Promise<void> {
    const link = this.askLink;
    const card = this.state.card;
    if (!link || !card || this.view.ask?.stage !== 'confirm') return;
    const p = this.providerFor(card.keyAlias);
    if (!p) return this.setAsk('error', { message: 'Your age card key is not available.' });
    this.setAsk('hello');
    try {
      const api = this.api(link.server);
      const keys = await api.keys();
      const key = pickTicketKey(keys, link.minAge, Math.floor(this.now() / 1000));
      if (!key) throw new ApiError(503, 'NO_TICKET_KEY', 'The V18 server has no current 18+ ticket key.');
      const payload = buildTicketPayload({ origin: link.origin, challenge: link.challenge, minAge: link.minAge, nowMs: this.now() });
      const blinded = await blindTicket(key, payload);
      const { challenge } = await api.challenge();
      const deviceSignature = await this.signWith(p.provider, p.name, ticketRequestString(card.cardId, challenge, key.kid, blinded.blindedMessage));
      this.setAsk('working');
      const res = await api.blindSign({ cardId: card.cardId, challenge, keyId: key.kid, blindedMessage: blinded.blindedMessage, deviceSignature });
      if (res.keyId !== key.kid) throw new ApiError(502, 'BAD_RESPONSE', 'The server signed with a different key.');
      const ticket = await finalizeTicket(blinded, res.blindSignature);
      await api.pairingConnect(link.sessionId).catch(() => undefined);
      await api.pairingSubmit(link.sessionId, ticket);
      this.askLink = null;
      this.setAsk('sent', { closeAt: this.now() + 5000 });
      this.askCloseTimer = setTimeout(() => this.askClose(), 5000);
    } catch (err) {
      if (err instanceof OfflineError) return this.setAsk('offline');
      if (err instanceof DeviceKeyError) {
        if (err.code === 'USER_CANCELED') return this.setAsk('confirm', { message: 'Windows Hello was cancelled. Nothing was sent.' });
        if (err.code === 'HELLO_NOT_SET_UP' || err.code === 'ADDON_MISSING' || err.code === 'DEVICE_LOCKED') return this.setAsk('integrity', { message: err.message });
        return this.setAsk('error', { message: err.message });
      }
      if (err instanceof ApiError && (err.code === 'CARD_REQUIRED' || err.code === 'CARD_EXPIRED' || err.code === 'CARD_REVOKED')) {
        await this.checkCard();
        return this.setAsk(this.cardView ? 'expired' : 'nocard', { message: "Your age card doesn't work any more." });
      }
      if (err instanceof ApiError && (err.code === 'RATE_LIMITED' || err.status === 429)) {
        return this.setAsk('error', { message: 'Too many tickets in the last hour. Wait a while, then try again.' });
      }
      const detail = err instanceof ApiError ? `${err.message} (${err.code})` : err instanceof Error ? err.message : String(err);
      return this.setAsk('error', { message: `No ticket was sent. ${detail}` });
    }
  }

  /** Show a QR so the phone can answer this same request (phone hand-off, nothing kept on the PC). */
  async askUsePhone(): Promise<void> {
    const link = this.askLink;
    if (!link) return;
    const deepLink =
      `v18://verify?session=${encodeURIComponent(link.sessionId)}&origin=${encodeURIComponent(link.origin)}` +
      `&challenge=${encodeURIComponent(link.challenge)}&minAge=${link.minAge}&server=${encodeURIComponent(link.server)}`;
    const qr = await this.deps.makeQr(deepLink);
    this.setAsk('phone', { qr });
  }

  askBackToConfirm(): void {
    if (this.askLink && this.view.ask?.stage === 'phone') void this.checkAsk();
  }

  askClose(): void {
    if (this.askCloseTimer) clearTimeout(this.askCloseTimer);
    this.askCloseTimer = null;
    this.askLink = null;
    this.askRaw = null;
    this.view.ask = null;
    this.emit();
  }

  /** From the ask dialog: go to the main window to make or renew a card. */
  askGetCard(): void {
    this.askClose();
    this.go(this.state.settings.sharedPc ? 'home' : 'card-methods');
  }

  shutdown(): void {
    this.cancelLink();
    this.cancelConnect();
    this.aadhaarCancel(false);
    if (this.askCloseTimer) clearTimeout(this.askCloseTimer);
  }
}

