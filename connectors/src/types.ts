/**
 * Public types for V18 login connectors (PROTOCOL.md 4d.4).
 *
 * A connector sends the person to a government or bank login, reads ONLY the
 * birth date (or an "over 18" answer) and a stable subject ID, and returns
 * `{ over18, subject }`. Everything else the provider sends is dropped at once.
 */

export type ConnectorId =
  | 'singpass'
  | 'digilocker'
  | 'uaepass'
  | 'bankid_se'
  | 'bankid_no'
  | 'mitid'
  | 'itsme'
  | 'franceconnect'
  | 'spid'
  | 'cie'
  | 'digid'
  | 'freja';

/** `high` for eIDAS-high or national schemes, otherwise `substantial` (PROTOCOL.md 4d.4). */
export type Assurance = 'high' | 'substantial';

/** Environment variables, usually `process.env`. */
export type Env = Record<string, string | undefined>;

export interface AuthStartParams {
  /** Random, unguessable, at least 32 characters. The server binds it to the challenge and device key. */
  state: string;
  /** Random, unguessable, at least 32 characters. */
  nonce: string;
  /** PKCE code verifier: 43 to 128 characters from [A-Za-z0-9-._~]. */
  codeVerifier: string;
  /** The full callback URL, for example `https://api.v18.example/v1/connect/singpass/callback`. */
  redirectUri: string;
  /** The person's IP address as the server sees it. Required by `bankid_se` only. */
  endUserIp?: string;
  /** SPID only: the entity ID of the identity provider the person picked. */
  idp?: string;
}

export interface AuthStart {
  /** Open this in a Custom Tab (Android) or the system browser (Windows). */
  authUrl: string;
  /**
   * Opaque data the server MUST store next to `state` (server side only, never sent to the app)
   * and pass back to `handleCallback`. It never holds personal data. It can hold a short-lived
   * private key (DPoP) or an order reference, so delete it after the callback.
   */
  session?: string;
}

export interface CallbackParams {
  /** Query parameters (GET callback) or form fields (POST callback) exactly as received. */
  params: Record<string, string>;
  /** The values that were passed to `buildAuthUrl` for this `state`. */
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  /** The `session` returned by `buildAuthUrl`, if any. */
  session?: string;
}

/** The ONLY thing a connector returns. No name, no birth date, no ID number. */
export interface ConnectorResult {
  over18: boolean;
  /**
   * The provider's stable ID for this person. Use it ONLY to compute the nullifier
   * HMAC-SHA256(V18_NULLIFIER_SECRET, id + "|" + subject) and then forget it. Never store or log it.
   */
  subject: string;
}

export interface Connector {
  readonly id: ConnectorId;
  /** ISO 3166-1 alpha-2 country codes this login serves. */
  readonly countries: readonly string[];
  readonly assurance: Assurance;
  /** Plain-English name for screens, for example "Singpass (Myinfo)". */
  readonly label: string;
  /** How the provider calls the callback. SAML connectors (spid, cie) use POST. */
  readonly callbackMethod: 'GET' | 'POST';
  /** True when every environment variable this connector needs is set. */
  isConfigured(env: Env): boolean;
  buildAuthUrl(params: AuthStartParams): Promise<AuthStart>;
  /** Throws `ConnectorError` on any failure. Never includes claims in the error. */
  handleCallback(params: CallbackParams): Promise<ConnectorResult>;
  /** Public keys (JWKS) the provider must be able to fetch, for connectors that use private_key_jwt or encryption. */
  jwks?(): Promise<{ keys: Record<string, unknown>[] }>;
  /** SAML service provider metadata XML (spid, cie). Serve it at a stable URL for AgID / the CIE portal. */
  metadata?(acsUrl: string): Promise<string>;
  /** SPID (and CIE): the identity providers to choose from. Pass the chosen `entityId` as `idp` to buildAuthUrl. */
  identityProviders?(): { entityId: string; name?: string }[];
}

export type ConnectorErrorCode =
  /** The connector is missing configuration. */
  | 'NOT_CONFIGURED'
  /** The person cancelled, or the provider returned an error (only the OAuth/SAML error code is kept). */
  | 'PROVIDER_ERROR'
  /** `state` (or SAML RelayState / InResponseTo) did not match. */
  | 'STATE_MISMATCH'
  /** Bad signature, bad token, replayed code or response, wrong audience, expired, and so on. */
  | 'INVALID_RESPONSE'
  /** The provider did not give a birth date or age answer. */
  | 'MISSING_BIRTHDATE'
  /** BankID only: the person has not finished yet. Try `handleCallback` again later. */
  | 'PENDING'
  /** A start parameter is missing or wrong (for example `endUserIp` for bankid_se). */
  | 'BAD_REQUEST';

/**
 * The only error connectors throw. The message is fixed plain text and never contains
 * claims, names, birth dates or ID numbers, so the server may log `code` and `message`.
 */
export class ConnectorError extends Error {
  readonly code: ConnectorErrorCode;
  readonly connector: ConnectorId;
  /** A short provider error code such as `access_denied` or `invalid_grant`, when there is one. */
  readonly providerCode?: string;

  constructor(connector: ConnectorId, code: ConnectorErrorCode, message: string, providerCode?: string) {
    super(message);
    this.name = 'ConnectorError';
    this.code = code;
    this.connector = connector;
    if (providerCode !== undefined) this.providerCode = safeCode(providerCode);
  }

  toJSON() {
    return { name: this.name, code: this.code, connector: this.connector, providerCode: this.providerCode, message: this.message };
  }
}

/** Keep only a short, harmless error token (OAuth error codes are [a-z_]). */
function safeCode(value: string): string | undefined {
  const v = String(value).slice(0, 64);
  return /^[A-Za-z0-9_.:-]+$/.test(v) ? v : undefined;
}

export interface ConnectorOptions {
  /**
   * TESTS ONLY. Allows plain http to 127.0.0.1 / localhost providers (the local mocks).
   * Ignored for any other host.
   */
  allowInsecureLocalhost?: boolean;
  /** Clock override for tests. */
  now?: () => Date;
  /** BankID SE only: how often and how many times to poll /collect in the callback. */
  bankidPoll?: { intervalMs: number; attempts: number };
}
