import { WIDGET_CSS } from './styles.js';
import { ICONS } from './icons.js';
import { PairingClient } from './pairing-client.js';
import { openDeepLink } from './deeplink.js';
import { detectWalletSupport } from './wallet.js';
import { TestWallet, WidgetController, WidgetState } from './controller.js';
import { announcement, renderView, testModeBanner } from './views.js';
import { formatClock } from './util.js';

/**
 * Used only when the page sets no `data-v18-server`. This is the production placeholder from
 * PROTOCOL.md 4c.7 until V18 has its own domain, so every site should set `data-v18-server`.
 * For local development use `data-v18-server="http://localhost:8080"`.
 */
export const DEFAULT_SERVER_URL = 'https://api.v18.example';

export interface WidgetOptions {
  /** Age the site needs. Default 18. */
  minAge?: number;
  /** V18 server base URL, for example "https://api.v18.example" or "http://localhost:8080" (dev). */
  serverUrl?: string;
  /** A challenge your server already put in the page. */
  challenge?: string;
  /** Your server's challenge endpoint (POST, returns {challenge}). Default "/v18/challenge". */
  challengeUrl?: string;
  /** Your server's verify endpoint (POST {ticket}). If unset, you send the ticket yourself in onSuccess. */
  verifyUrl?: string;
  theme?: 'auto' | 'light' | 'dark';
  /** Called once the ticket is ready (and, with verifyUrl, once your server accepted it). */
  onSuccess?: (ticket: string, siteResponse: unknown) => void;
  onError?: (err: Error) => void;
  /** Called when the done screen is dismissed (Continue, or after 3 seconds). */
  onContinue?: () => void;
  onClose?: () => void;
  /** Ignored: the origin always comes from the page itself (window.location.origin). */
  origin?: string;
}

let testWalletRef: TestWallet | null = null;

/** Lets a dev page register a test wallet (see TestWallet). Pass null to remove it. */
export function setTestWallet(tw: TestWallet | null): void {
  testWalletRef = tw;
}

export function getTestWallet(): TestWallet | null {
  return testWalletRef ?? ((typeof window !== 'undefined' && (window as any).V18TestWallet) || null);
}

const FOCUSABLE = 'button:not([disabled]), [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

export class V18Modal {
  private host: HTMLDivElement | null = null;
  private shadow: ShadowRoot | null = null;
  private controller: WidgetController;
  private lastView: string | null = null;
  private lastFocus: Element | null = null;
  private prevOverflow = '';
  private doneTimer: ReturnType<typeof setTimeout> | null = null;
  private announced30 = false;
  private media: MediaQueryList | null = null;
  private finished = false;
  private readonly opts: WidgetOptions;

  constructor(options: WidgetOptions = {}) {
    this.opts = options;
    const serverUrl = options.serverUrl || DEFAULT_SERVER_URL;
    const walletSupport = detectWalletSupport(window);
    this.controller = new WidgetController(
      {
        origin: window.location.origin,
        minAge: Number.isInteger(options.minAge) && options.minAge! > 0 ? options.minAge! : 18,
        serverUrl,
        challenge: options.challenge,
        challengeUrl: options.challengeUrl,
        verifyUrl: options.verifyUrl,
        walletSupport,
        onSuccess: (t, r) => options.onSuccess?.(t, r),
        onError: (e) => options.onError?.(e),
      },
      {
        fetch: (...a) => window.fetch(...a),
        pairing: new PairingClient(serverUrl),
        openDeepLink: (link) => openDeepLink(link, document),
        getTestWallet,
        credentials: walletSupport ? window.navigator.credentials : null,
        hasUserActivation: () => {
          const ua = (window.navigator as any).userActivation;
          return ua && typeof ua.isActive === 'boolean' ? ua.isActive : true;
        },
      }
    );
  }

  public getController(): WidgetController {
    return this.controller;
  }

  public open(): void {
    if (this.host) return;
    this.lastFocus = document.activeElement;
    this.host = document.createElement('div');
    this.host.setAttribute('data-v18-widget', '');
    this.shadow = this.host.attachShadow({ mode: 'open' });
    this.shadow.innerHTML = `<style>${WIDGET_CSS}</style>
      <div class="as" part="root">
        <div class="ov">
          <div class="wm" role="dialog" aria-modal="true" aria-labelledby="v18-title">
            <div class="wm-h">${ICONS.logo}<span class="h3">V18</span><span class="sm">Private age check</span>
              <button type="button" class="x" data-act="close" aria-label="Close the V18 age check">${ICONS.close}</button></div>
            <div data-slot="banner"></div>
            <div data-slot="body"></div>
            <div class="wm-f" data-slot="footer"></div>
            <div class="vh" role="status" aria-live="polite" data-slot="live"></div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(this.host);
    this.prevOverflow = document.documentElement.style.overflow;
    document.documentElement.style.overflow = 'hidden';

    this.applyTheme();
    if (this.opts.theme === 'auto' || !this.opts.theme) {
      this.media = window.matchMedia?.('(prefers-color-scheme: dark)') ?? null;
      this.media?.addEventListener?.('change', this.applyTheme);
    }
    this.shadow.addEventListener('click', this.onClick);
    this.shadow.addEventListener('keydown', this.onKeyDown as EventListener);
    window.addEventListener('blur', this.onWindowBlur);
    document.addEventListener('visibilitychange', this.onVisibility);

    this.controller.subscribe((s, reason) => this.update(s, reason));
    this.update(this.controller.state, 'view');
    void this.controller.loadServerInfo();
  }

  /** Closes the widget. Any open hand-off is cancelled on the server. */
  public close(): void {
    if (!this.host) return;
    if (this.doneTimer) clearTimeout(this.doneTimer);
    this.controller.dispose();
    this.media?.removeEventListener?.('change', this.applyTheme);
    window.removeEventListener('blur', this.onWindowBlur);
    document.removeEventListener('visibilitychange', this.onVisibility);
    this.host.remove();
    this.host = null;
    this.shadow = null;
    document.documentElement.style.overflow = this.prevOverflow;
    if (this.lastFocus instanceof HTMLElement && document.contains(this.lastFocus)) this.lastFocus.focus();
    this.opts.onClose?.();
  }

  public isOpen(): boolean {
    return !!this.host;
  }

  private applyTheme = (): void => {
    const root = this.shadow?.querySelector('.as');
    if (!root) return;
    const t = this.opts.theme ?? 'auto';
    const dark = t === 'dark' || (t === 'auto' && !!window.matchMedia?.('(prefers-color-scheme: dark)').matches);
    root.classList.toggle('dark', dark);
  };

  private $(sel: string): HTMLElement | null {
    return (this.shadow?.querySelector(sel) as HTMLElement) ?? null;
  }

  private update(s: WidgetState, reason: 'view' | 'tick' | 'detail'): void {
    if (!this.shadow) return;
    if (reason === 'tick') {
      const t = this.$('[data-timer]');
      if (t) t.textContent = formatClock(s.secondsLeft);
      const p = this.$('[data-prog]');
      if (p) p.style.width = `${s.totalSeconds ? Math.round((s.secondsLeft / s.totalSeconds) * 100) : 0}%`;
      if (s.secondsLeft === 30 && !this.announced30) {
        this.announced30 = true;
        this.say('30 seconds left.');
      }
      return;
    }

    const banner = this.$('[data-slot="banner"]')!;
    banner.innerHTML = testModeBanner(s);

    const viewChanged = s.view !== this.lastView;
    const activeAct = (this.shadow.activeElement as HTMLElement | null)?.getAttribute?.('data-act') ?? null;
    const html = renderView(s, { canSimulate: this.controller.canSimulate() });
    this.$('[data-slot="body"]')!.innerHTML = html.body;
    this.$('[data-slot="footer"]')!.innerHTML = html.footer;
    this.$('.wm')!.classList.toggle('compact', !!html.compact);
    this.$('[data-act="close"]')!.hidden = !!html.hideClose;

    if (viewChanged) {
      this.lastView = s.view;
      if (s.view === 'qr_waiting' || s.view === 'win_waiting') this.announced30 = false;
      this.say(announcement(s));
      this.$('#v18-title')?.focus();
      if (s.view === 'done') this.startDoneTimer();
    } else if (activeAct) {
      (this.$(`[data-act="${activeAct}"]`) ?? this.$('#v18-title'))?.focus();
    }
  }

  private say(text: string): void {
    const live = this.$('[data-slot="live"]');
    if (!live || !text) return;
    live.textContent = '';
    setTimeout(() => (live.textContent = text), 50);
  }

  private startDoneTimer(): void {
    if (this.doneTimer) clearTimeout(this.doneTimer);
    this.doneTimer = setTimeout(() => this.finish(), 3000);
  }

  /** Done screen dismissed: tell the page, then close. */
  private finish(): void {
    if (this.finished) return;
    this.finished = true;
    this.close();
    this.opts.onContinue?.();
  }

  private onClick = (e: Event): void => {
    const el = (e.target as HTMLElement | null)?.closest?.('[data-act]') as HTMLElement | null;
    if (!el || (el as HTMLButtonElement).disabled) return;
    const c = this.controller;
    switch (el.getAttribute('data-act')) {
      case 'close': return this.close();
      case 'phone': void c.choosePhone(); return;
      case 'windows': void c.chooseWindows(); return;
      case 'wallet': void c.chooseWallet(); return;
      case 'wallet_open': void c.openWallet(); return;
      case 'how': return c.showHow();
      case 'back': return c.back();
      case 'retry': void c.retry(); return;
      case 'help': return c.showWindowsHelp();
      case 'win_back': return c.backToWindowsWaiting();
      case 'reopen': return c.reopenWindowsApp();
      case 'simulate': void c.simulateWithTestWallet(); return;
      case 'continue': return this.finish();
    }
  };

  private onKeyDown = (e: KeyboardEvent): void => {
    if (e.key === 'Escape') {
      e.preventDefault();
      if (this.controller.state.view === 'done') this.finish();
      else this.close();
      return;
    }
    if (e.key !== 'Tab' || !this.shadow) return;
    const items = Array.from(this.shadow.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
      (el) => !el.hidden && el.offsetParent !== null
    );
    if (items.length === 0) return;
    const first = items[0];
    const last = items[items.length - 1];
    const active = this.shadow.activeElement as HTMLElement | null;
    if (e.shiftKey && (active === first || !active || !items.includes(active))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (active === last || !active || !items.includes(active))) {
      e.preventDefault();
      first.focus();
    }
  };

  private onWindowBlur = (): void => this.controller.noteAppMayHaveOpened();

  private onVisibility = (): void => {
    if (document.visibilityState === 'hidden') this.controller.noteAppMayHaveOpened();
  };
}
