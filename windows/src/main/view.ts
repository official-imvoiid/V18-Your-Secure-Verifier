// The view state the main process sends to the windows. Plain data only: no keys, no tickets,
// no challenges from the server, nothing secret.

import type { StoredSettings } from '../shared/storage.js';
import type { PcMethod } from '../shared/catalog.js';
import type { KeyProtection } from './keys.js';

export const MAIN_SCREENS = [
  'welcome',
  'home',
  'card-country',
  'card-methods',
  'card-phone',
  'card-connect',
  'card-test',
  'card-qr',
  'card-working',
  'card-saved',
  'seals',
  'settings',
  'err-integrity',
  'err-seal',
  'err-under18',
  'err-offline',
  'err-general',
  'child',
] as const;
export type MainScreen = (typeof MAIN_SCREENS)[number];

/** Screens the window may switch to by itself (the others are reached only through a flow). */
export const NAV_SCREENS: readonly MainScreen[] = [
  'home',
  'card-country',
  'card-methods',
  'card-test',
  'card-qr',
  'seals',
  'settings',
];

export type AskStage =
  | 'loading'
  | 'confirm'
  | 'nocard'
  | 'shared'
  | 'phone'
  | 'hello'
  | 'working'
  | 'sent'
  | 'offline'
  | 'expired'
  | 'under18'
  | 'child'
  | 'integrity'
  | 'error';

export interface CardView {
  method: string;
  methodLabel: string;
  validUntil: string;
  validUntilLabel: string;
  daysLeft: number;
  expired: boolean;
  protection: KeyProtection | null;
  testKey: boolean;
}

export interface LinkView {
  /** The phone method the person picked (for example "Passport (chip)"), shown in the steps. */
  forLabel?: string;
  status: 'hello' | 'waiting' | 'expired' | 'error';
  qr?: string; // data: URL of an SVG QR code
  expiresAt?: number; // ms since epoch
  message?: string;
}

export interface WorkStep {
  label: string;
  state: 'done' | 'cur' | 'todo';
}
export interface WorkView {
  title: string;
  text: string;
  steps: WorkStep[];
  test: boolean;
  /** Real progress of the current step (download bytes, or the prover's own stages). */
  progress?: { pct: number; label: string; detail?: string } | null;
  /** When the current long step started (ms since epoch), to show the time taken so far. */
  since?: number;
  /** The flow can be stopped with the Cancel button. */
  cancellable?: boolean;
}

export interface ErrorView {
  title: string;
  detail: string;
  code?: string;
}

export interface AadhaarView {
  stage: 'pick' | 'read' | 'error';
  fileName?: string;
  checks?: { label: string; ok: boolean }[];
  message?: string;
  testQr?: boolean;
}

/** A government or bank login (4d.4), done in the system browser. */
export interface ConnectView {
  label: string;
  connectorId: string;
  status: 'hello' | 'starting' | 'browser' | 'expired';
  expiresAt?: number;
  message?: string;
}

export interface CatalogCountryView {
  code: string;
  name: string;
  region: string;
  methods: PcMethod[];
}

export interface CatalogView {
  status: 'loading' | 'ok' | 'offline' | 'error';
  countries: CatalogCountryView[];
  message?: string;
}

export interface AskView {
  id: number;
  stage: AskStage;
  origin: string | null;
  host: string | null;
  minAge: number;
  cardLine?: string;
  qr?: string;
  message?: string;
  closeAt?: number;
}

export interface ViewState {
  screen: MainScreen;
  debugBuild: boolean;
  /** true when the server says it is in dev mode (shows the TEST MODE banner). null = not known yet. */
  testMode: boolean | null;
  /** true when the app was started with --v18-test-software-key. */
  testKey: boolean;
  serverUrl: string;
  serverReachable: boolean | null;
  /** The server's answer for Anon Aadhaar (GET /health methods.anon_aadhaar): true = ready, false = not set up, null = not known. */
  aadhaarReady: boolean | null;
  /** The Anon Aadhaar circuit files are already downloaded on this PC. */
  proofFilesCached: boolean;
  /** "Start V18 when I sign in to Windows": null when this build can't change it. */
  startWithWindows: boolean | null;
  /** How long the last Aadhaar proof took on this PC (seconds), shown after a card is saved. */
  lastProofSeconds: number | null;
  settings: StoredSettings;
  card: CardView | null;
  hello: { ok: boolean; code?: string; detail?: string };
  childAccount: 'yes' | 'no' | 'unknown';
  link: LinkView | null;
  connect: ConnectView | null;
  /** Countries and their IDs, from the server (GET /v1/catalog). */
  catalog: CatalogView;
  /** This PC's region from Windows (for example "IN"), to pre-select the country. Not stored. */
  localeCountry: string | null;
  work: WorkView | null;
  error: ErrorView | null;
  aadhaar: AadhaarView | null;
  notice: string | null;
  busy: boolean;
  ask: AskView | null;
}
