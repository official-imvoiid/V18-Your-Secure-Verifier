// Page script for both windows (?view=main or ?view=ask). It only draws what the main process
// sends and turns button clicks into calls on window.v18. It has no network access (CSP
// connect-src 'none') and no Node.

import type { ViewState } from '../main/view.js';
import { askScreen } from './ask.js';
import { setHtml } from './html.js';
import { mainScreen, type LocalUi } from './screens.js';

interface Bridge {
  invoke(channel: string, arg?: unknown): Promise<unknown>;
  onView(cb: (v: unknown) => void): void;
}
const bridge = (window as unknown as { v18: Bridge }).v18;
const mode = new URLSearchParams(location.search).get('view') === 'ask' ? 'ask' : 'main';
const root = document.getElementById('app')!;
// The window title (taskbar, Alt+Tab, screen readers) says which window this is.
document.title = mode === 'ask' ? 'V18: a site asks' : 'V18';

const ui: LocalUi = { welcomePick: 'me', country: '', countrySearch: '', testKind: 'adult', confirmDelete: false, confirmShared: false };
let view: ViewState | null = null;

// Light or dark, following Windows.
const dark = window.matchMedia('(prefers-color-scheme: dark)');
const applyTheme = () => document.body.classList.toggle('dark', dark.matches);
dark.addEventListener('change', applyTheme);
applyTheme();

function render(): void {
  if (!view) return;
  const keepFocus = document.activeElement instanceof HTMLInputElement ? document.activeElement.id : null;
  const caret = keepFocus ? (document.activeElement as HTMLInputElement).selectionStart : null;
  setHtml(root, mode === 'ask' ? askScreen(view) : mainScreen(view, ui));
  if (keepFocus) {
    const el = document.getElementById(keepFocus) as HTMLInputElement | null;
    el?.focus();
    if (el && caret !== null) el.setSelectionRange(caret, caret);
  }
  tick();
}

/** Countdown text and bars (set through CSSOM, which the CSP allows; no inline style attributes). */
function tick(): void {
  const now = Date.now();
  root.querySelectorAll<HTMLElement>('[data-countdown]').forEach((el) => {
    const left = Math.max(0, Math.round((Number(el.dataset.countdown) - now) / 1000));
    el.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
  });
  root.querySelectorAll<HTMLElement>('[data-countbar]').forEach((el) => {
    const left = Math.max(0, Number(el.dataset.countbar) - now);
    el.style.width = `${Math.min(100, (left / 120000) * 100)}%`;
  });
  root.querySelectorAll<HTMLElement>('[data-pct]').forEach((el) => {
    el.style.width = `${Math.max(0, Math.min(100, Number(el.dataset.pct)))}%`;
  });
  root.querySelectorAll<HTMLElement>('[data-since]').forEach((el) => {
    const s = Math.max(0, Math.floor((now - Number(el.dataset.since)) / 1000));
    el.textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
  });
  root.querySelectorAll<HTMLElement>('[data-countdown-s]').forEach((el) => {
    el.textContent = String(Math.max(0, Math.ceil((Number(el.dataset.countdownS) - now) / 1000)));
  });
}
setInterval(tick, 500);

const call = (channel: string, arg?: unknown) => {
  bridge.invoke(channel, arg).catch(() => undefined);
};

root.addEventListener('click', (ev) => {
  const el = (ev.target as Element).closest<HTMLElement>('[data-act]');
  if (!el || (el as HTMLButtonElement).disabled) return;
  const act = el.dataset.act!;
  const arg = el.dataset.arg;
  switch (act) {
    case 'go':
      ui.confirmDelete = ui.confirmShared = false;
      return call('v18:go', arg);
    case 'welcome-pick':
      ui.welcomePick = arg === 'shared' ? 'shared' : 'me';
      return render();
    case 'first-run':
      return call('v18:first-run', ui.welcomePick === 'shared');
    case 'pick-country':
      ui.country = arg ?? ui.country;
      return render();
    case 'test-kind':
      ui.testKind = arg === 'under18' ? 'under18' : 'adult';
      return render();
    case 'test-card':
      return call('v18:test-card', ui.testKind);
    case 'start-link':
      return call('v18:start-link', arg || undefined);
    case 'start-connector':
      return call('v18:start-connector', arg);
    case 'cancel-connect':
      return call('v18:cancel-connect');
    case 'connect-reopen':
      return call('v18:connect-reopen');
    case 'load-catalog':
      return call('v18:load-catalog');
    case 'cancel-link':
      return call('v18:cancel-link');
    case 'aadhaar-pick':
      return call('v18:aadhaar-pick');
    case 'aadhaar-build':
      return call('v18:aadhaar-build');
    case 'aadhaar-reset':
      return call('v18:aadhaar-reset');
    case 'aadhaar-cancel':
      return call('v18:aadhaar-cancel');
    case 'delete-proof-files':
      return call('v18:delete-proof-files');
    case 'toggle-startup':
      return call('v18:settings', { startWithWindows: !view?.startWithWindows });
    case 'ask-delete':
      ui.confirmDelete = true;
      return render();
    case 'cancel-dialog':
      ui.confirmDelete = ui.confirmShared = false;
      return render();
    case 'delete-card':
      ui.confirmDelete = false;
      render();
      return call('v18:delete-card', false);
    case 'delete-local':
      return call('v18:delete-card', true);
    case 'toggle-notify':
      return call('v18:settings', { notify: !view?.settings.notify });
    case 'toggle-shared':
      if (!view) return;
      if (!view.settings.sharedPc && view.card) {
        ui.confirmShared = true;
        return render();
      }
      return call('v18:settings', { sharedPc: !view.settings.sharedPc });
    case 'shared-on':
      ui.confirmShared = false;
      render();
      return call('v18:settings', { sharedPc: true });
    case 'use-phone-always':
      return call('v18:settings', { sharedPc: true });
    case 'dismiss-notice':
      return call('v18:dismiss-notice');
    case 'refresh-server':
      return call('v18:refresh-server');
    case 'open-hello-settings':
      return call('v18:open-hello-settings');
    case 'ask-approve':
      return call('v18:ask-approve');
    case 'ask-phone':
      return call('v18:ask-phone');
    case 'ask-back':
      return call('v18:ask-back');
    case 'ask-retry':
      return call('v18:ask-retry');
    case 'ask-close':
      return call('v18:ask-close');
    case 'ask-get-card':
      return call('v18:ask-get-card');
  }
});

root.addEventListener('input', (ev) => {
  const t = ev.target as HTMLInputElement;
  if (t.id === 'country-search') {
    ui.countrySearch = t.value.slice(0, 40);
    render();
  }
});

document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape') {
    if (ui.confirmDelete || ui.confirmShared) {
      ui.confirmDelete = ui.confirmShared = false;
      render();
    } else if (mode === 'ask' && view?.ask && view.ask.stage !== 'hello' && view.ask.stage !== 'working') {
      call('v18:ask-close');
    }
  }
});

bridge.onView((v) => {
  view = v as ViewState;
  render();
});
void bridge.invoke('v18:get-view').then((v) => {
  view = v as ViewState;
  render();
});
