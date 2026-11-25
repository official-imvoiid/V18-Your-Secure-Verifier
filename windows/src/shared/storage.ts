// What the Windows app keeps on disk (PROTOCOL.md 3.10). Only:
//   card ID, method, validUntil, the device key's alias, the server URL and settings.
// Shared-PC mode keeps no card at all. Everything else is dropped before saving, so even a bug
// elsewhere cannot write a name, birth date, ticket or site history to disk.

import { normalizeServer } from './allowlist.js';

export interface StoredSettings {
  firstRunDone: boolean;
  sharedPc: boolean;
  notify: boolean;
}

export interface StoredCard {
  cardId: string;
  method: string;
  validUntil: string; // ISO date-time
  /** "<provider>:<name>", for example "hello:v18-card-3f2a…" or "test-software:v18-card-…". */
  keyAlias: string;
}

export interface StoredState {
  version: 1;
  serverUrl: string;
  settings: StoredSettings;
  card: StoredCard | null;
}

export const DEFAULT_SETTINGS: StoredSettings = { firstRunDone: false, sharedPc: false, notify: true };

// Protocol: card_<base64url 16 bytes>. Kept a little loose so a server-side format tweak doesn't wipe cards.
const CARD_ID_RE = /^card[_-][A-Za-z0-9_-]{8,64}$/;
// Plain methods ("anon_aadhaar") and login connectors ("connector:singpass", 4d.3).
const METHOD_RE = /^[a-z][a-z0-9_]{1,31}(:[a-z0-9_]{2,40})?$/;
const ALIAS_RE = /^(hello|test-software):v18-card-[A-Za-z0-9_-]{8,64}$/;

export function emptyState(defaultServerUrl: string): StoredState {
  return { version: 1, serverUrl: defaultServerUrl, settings: { ...DEFAULT_SETTINGS }, card: null };
}

function sanitizeCard(raw: unknown): StoredCard | null {
  if (!raw || typeof raw !== 'object') return null;
  const c = raw as Record<string, unknown>;
  if (typeof c.cardId !== 'string' || !CARD_ID_RE.test(c.cardId)) return null;
  if (typeof c.method !== 'string' || !METHOD_RE.test(c.method)) return null;
  if (typeof c.validUntil !== 'string' || Number.isNaN(Date.parse(c.validUntil))) return null;
  if (typeof c.keyAlias !== 'string' || !ALIAS_RE.test(c.keyAlias)) return null;
  // Rebuild the object so no extra fields survive.
  return { cardId: c.cardId, method: c.method, validUntil: new Date(c.validUntil).toISOString(), keyAlias: c.keyAlias };
}

/**
 * Keep only the allowed fields with allowed values. Unknown fields are dropped. A bad server URL
 * falls back to the default. In shared-PC mode the card is always removed.
 */
export function sanitizeState(raw: unknown, opts: { debug: boolean; defaultServerUrl: string; extraServerOrigins?: readonly string[] }): StoredState {
  const base = emptyState(opts.defaultServerUrl);
  if (!raw || typeof raw !== 'object') return base;
  const r = raw as Record<string, unknown>;
  const s = (r.settings && typeof r.settings === 'object' ? r.settings : {}) as Record<string, unknown>;
  const settings: StoredSettings = {
    firstRunDone: s.firstRunDone === true,
    sharedPc: s.sharedPc === true,
    notify: s.notify !== false,
  };
  const serverUrl = normalizeServer(r.serverUrl, opts.debug, opts.extraServerOrigins) ?? opts.defaultServerUrl;
  const card = settings.sharedPc ? null : sanitizeCard(r.card);
  return { version: 1, serverUrl, settings, card };
}

/** The exact JSON written to disk. */
export function serializeState(state: StoredState, opts: { debug: boolean; defaultServerUrl: string; extraServerOrigins?: readonly string[] }): string {
  return JSON.stringify(sanitizeState(state, opts), null, 2);
}
