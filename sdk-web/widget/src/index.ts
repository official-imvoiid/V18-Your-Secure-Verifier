/**
 * V18 web widget. The 2-line embed (the release build is release/v18-<version>.min.js, and its
 * integrity hash is in release/SRI.txt):
 *
 *   <script src="https://cdn.v18.example/v18-1.0.0.min.js" integrity="sha384-..." crossorigin="anonymous" data-v18-server="https://api.v18.example"></script>
 *   <button data-v18-min-age="18">Verify age</button>
 *
 * Your server needs two routes (see docs/web/INTEGRATION.md):
 *   POST /v18/challenge  -> {"challenge": "..."}  (a fresh challenge for this visit)
 *   POST /v18/verify     <- {"ticket": "..."}     (check it with @v18/verify or v18_verify)
 *
 * Button attributes (all optional except data-v18-min-age):
 *   data-v18-challenge="..."        a challenge your server put in the page (instead of the URL)
 *   data-v18-challenge-url="/x"     default /v18/challenge
 *   data-v18-verify-url="/y"        default /v18/verify; "none" means you handle the v18:verified event
 *   data-v18-redirect="/members"    where to go after success (default: reload the page)
 *   data-v18-server="https://..."   V18 server (or put it on the <script> tag)
 *   data-v18-theme="auto|light|dark"
 *
 * Events on the button: "v18:verified" (detail {ticket, response}; cancelable: call preventDefault()
 * to stop the redirect/reload), "v18:error" (detail {error}).
 */
import { DEFAULT_SERVER_URL, V18Modal, WidgetOptions, setTestWallet, getTestWallet } from './modal.js';
import type { TestWallet } from './controller.js';

export * from './modal.js';
export * from './controller.js';
export * from './pairing-client.js';
export * from './deeplink.js';
export * from './wallet.js';
export * from './views.js';
export * from './qr.js';

declare const __V18_VERSION__: string | undefined;
/** Set from package.json when the bundle is built (see scripts/build-release.mjs). */
export const VERSION: string = typeof __V18_VERSION__ === 'string' ? __V18_VERSION__ : '1.0.0';
const TRIGGER = '[data-v18-min-age], [data-v18-verify]';

const scriptServer: string | undefined =
  typeof document !== 'undefined'
    ? (document.currentScript as HTMLScriptElement | null)?.getAttribute('data-v18-server') ?? undefined
    : undefined;

let active: V18Modal | null = null;

function openModal(options: WidgetOptions): V18Modal {
  if (active?.isOpen()) active.close();
  active = new V18Modal({ ...options, serverUrl: options.serverUrl || scriptServer || DEFAULT_SERVER_URL });
  active.open();
  return active;
}

function fromButton(btn: HTMLElement): void {
  const attr = (n: string) => btn.getAttribute(n) ?? undefined;
  const ageAttr = attr('data-v18-min-age');
  const minAge = ageAttr && /^\d+$/.test(ageAttr) ? parseInt(ageAttr, 10) : 18;
  const verifyAttr = attr('data-v18-verify-url');
  const verifyUrl = verifyAttr === 'none' ? undefined : verifyAttr || '/v18/verify';
  const redirect = attr('data-v18-redirect');
  let allowNavigate = true;

  openModal({
    minAge,
    serverUrl: attr('data-v18-server'),
    challenge: attr('data-v18-challenge'),
    challengeUrl: attr('data-v18-challenge-url'),
    verifyUrl,
    theme: (attr('data-v18-theme') as WidgetOptions['theme']) || 'auto',
    onSuccess: (ticket, response) => {
      const ev = new CustomEvent('v18:verified', { bubbles: true, cancelable: true, detail: { ticket, response } });
      allowNavigate = btn.dispatchEvent(ev) && !!verifyUrl;
    },
    onError: (error) => {
      btn.dispatchEvent(new CustomEvent('v18:error', { bubbles: true, detail: { error } }));
    },
    onContinue: () => {
      if (!allowNavigate) return;
      if (redirect) window.location.assign(redirect);
      else window.location.reload();
    },
  });
}

export const V18 = {
  version: VERSION,

  /**
   * Opens the age check. Example:
   *   V18.verify({ minAge: 18, challengeUrl: '/v18/challenge', verifyUrl: '/v18/verify',
   *                onSuccess: (ticket, siteReply) => location.assign('/members') });
   */
  verify(options: WidgetOptions = {}): V18Modal {
    return openModal(options);
  },

  /** Same as verify(). */
  open(options: WidgetOptions = {}): V18Modal {
    return openModal(options);
  },

  close(): void {
    active?.close();
  },

  /**
   * Starts listening for clicks on [data-v18-min-age] / [data-v18-verify] elements. Runs by itself
   * when the script loads; buttons added later work too (one listener on the document).
   */
  init(): void {
    if (typeof document === 'undefined' || (document as any).__v18Bound) return;
    (document as any).__v18Bound = true;
    document.addEventListener('click', (e) => {
      const btn = (e.target as Element | null)?.closest?.(TRIGGER) as HTMLElement | null;
      if (!btn || (btn as HTMLButtonElement).disabled) return;
      e.preventDefault();
      fromButton(btn);
    });
  },

  /** DEV ONLY. Registers a test wallet; its button shows only when the V18 server is in dev mode. */
  registerTestWallet(tw: TestWallet | null): void {
    setTestWallet(tw);
  },

  hasTestWallet(): boolean {
    return !!getTestWallet();
  },
};

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  (window as any).V18 = V18;
  V18.init();
}

export default V18;
