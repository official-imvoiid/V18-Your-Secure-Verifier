/**
 * One OpenID Connect / OAuth 2.0 connector engine, configured per provider.
 *
 * All protocol and crypto work is done by `openid-client` (and `jose` under it):
 * discovery, PKCE (S256), state and nonce checks, ID token signature and claim checks,
 * private_key_jwt, PAR, DPoP, and decrypting JWE ID tokens and userinfo. No home-made crypto.
 */
import * as client from 'openid-client';
import { exportJWK, importJWK, type JWK } from 'jose';
import { isOver18, type BirthDate } from './age.js';
import { envValue, hasAll, isLoopback, loadPrivateKey, type LoadedPrivateKey } from './config.js';
import {
  ConnectorError,
  type Assurance,
  type AuthStart,
  type AuthStartParams,
  type CallbackParams,
  type Connector,
  type ConnectorId,
  type ConnectorOptions,
  type ConnectorResult,
  type Env,
} from './types.js';

export interface ExtractInput {
  /** Checked ID token claims (signature, iss, aud, exp, nonce already verified). */
  idToken?: Record<string, unknown>;
  /** Checked userinfo response (signature and decryption done when the provider uses JWTs). */
  userinfo?: Record<string, unknown>;
  /** The token endpoint response (some OAuth providers put the birth date here). */
  token: Record<string, unknown>;
}

export interface Extracted {
  /** A yes/no age answer from the provider, when it has one (preferred: it reveals less). */
  over18?: boolean;
  birthDate?: BirthDate;
  subject?: string;
}

export type ClientAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt';

export interface OidcSpec {
  id: ConnectorId;
  label: string;
  countries: readonly string[];
  assurance: Assurance;
  /** Env var names (after `V18_CONNECTOR_<ID>_`) that must be set for the connector to be enabled. */
  required: (env: Env) => readonly string[];
  /** Production discovery URL. `V18_CONNECTOR_<ID>_ISSUER` overrides it (test environments, brokers). */
  discoveryUrl?: string;
  /** For providers without discovery: build the metadata. `issuer` comes from env or the default. */
  staticMetadata?: (issuer: string) => client.ServerMetadata;
  /** Default issuer for `staticMetadata`. */
  defaultIssuer?: string;
  clientAuth: (env: Env) => ClientAuthMethod;
  /** Who the private_key_jwt assertion is addressed to. Default: the issuer. */
  assertionAudience?: 'issuer' | 'token_endpoint';
  /** PEM keys don't name their algorithm, so say it here. */
  signingAlg?: string;
  par?: boolean;
  dpop?: boolean;
  /** Expect and check an ID token (and the nonce in it). */
  idToken: boolean;
  /** Call the userinfo endpoint: always, never, or only when the ID token has no birth date or age answer. */
  userinfo: boolean | 'if-needed';
  /** The provider encrypts the ID token and/or userinfo to our key (needs `ENCRYPTION_KEY`). */
  encrypted?: boolean;
  clientMetadata?: Partial<client.ClientMetadata>;
  /** Extra authorization parameters: scope, acr_values, claims, provider-specific ones. */
  authParams: (env: Env, p: AuthStartParams) => Record<string, string>;
  /** Minimum length the provider demands for state and nonce. */
  minStateLength?: number;
  /** Pull the birth date or age answer and the subject out of what the provider returned. */
  extract: (input: ExtractInput, env: Env) => Extracted;
}

const DISCOVERY_TTL_MS = 60 * 60 * 1000;

interface SessionData {
  /** DPoP key pair for this one login, as JWKs. Short-lived; never reused. */
  dpop?: { privateJwk: JWK; publicJwk: JWK };
}

export function createOidcConnector(spec: OidcSpec, env: Env, options: ConnectorOptions = {}): Connector {
  const id = spec.id;
  const now = options.now ?? (() => new Date());
  let configPromise: Promise<client.Configuration> | undefined;
  let configLoadedAt = 0;
  let keysPromise: Promise<{ signing?: LoadedPrivateKey; encryption?: LoadedPrivateKey }> | undefined;

  const fail = (code: ConstructorParameters<typeof ConnectorError>[1], message: string, providerCode?: string) =>
    new ConnectorError(id, code, message, providerCode);

  function keys() {
    keysPromise ??= (async () => {
      const sig = envValue(env, id, 'SIGNING_KEY');
      const enc = envValue(env, id, 'ENCRYPTION_KEY');
      return {
        signing: sig ? await loadPrivateKey(sig, 'sig', spec.signingAlg) : undefined,
        encryption: enc ? await loadPrivateKey(enc, 'enc') : undefined,
      };
    })();
    return keysPromise;
  }

  async function buildConfig(): Promise<client.Configuration> {
    const clientId = envValue(env, id, 'CLIENT_ID');
    if (!clientId) throw fail('NOT_CONFIGURED', 'This login is not set up on this server.');
    const issuerOverride = envValue(env, id, 'ISSUER');
    const { signing, encryption } = await keys();

    const method = spec.clientAuth(env);
    let tokenEndpoint: string | undefined;
    let auth: client.ClientAuth;
    if (method === 'private_key_jwt') {
      if (!signing) throw fail('NOT_CONFIGURED', 'This login needs a signing key.');
      const audience = spec.assertionAudience ?? 'issuer';
      auth = client.PrivateKeyJwt(
        { key: signing.key, kid: signing.kid },
        audience === 'token_endpoint'
          ? {
              [client.modifyAssertion]: (_header, payload) => {
                if (tokenEndpoint) payload.aud = tokenEndpoint;
              },
            }
          : undefined,
      );
    } else {
      const secret = envValue(env, id, 'CLIENT_SECRET');
      if (!secret) throw fail('NOT_CONFIGURED', 'This login needs a client secret.');
      auth = method === 'client_secret_post' ? client.ClientSecretPost(secret) : client.ClientSecretBasic(secret);
    }

    const metadata: Partial<client.ClientMetadata> = {
      ...spec.clientMetadata,
      token_endpoint_auth_method: method,
    };

    let config: client.Configuration;
    if (spec.staticMetadata) {
      const issuer = issuerOverride ?? spec.defaultIssuer!;
      const server = spec.staticMetadata(issuer);
      config = new client.Configuration(server, clientId, metadata, auth);
      if (options.allowInsecureLocalhost && isLoopback(issuer)) client.allowInsecureRequests(config);
    } else {
      const discovery = issuerOverride ?? spec.discoveryUrl!;
      const insecure = options.allowInsecureLocalhost === true && isLoopback(discovery);
      config = await client.discovery(
        new URL(discovery),
        clientId,
        metadata,
        auth,
        insecure ? { execute: [client.allowInsecureRequests] } : undefined,
      );
    }
    tokenEndpoint = config.serverMetadata().token_endpoint;
    // Always check ID token and JWT userinfo signatures against the provider's JWKS,
    // not only TLS (openid-client skips this by default for direct server-to-server answers).
    if (config.serverMetadata().jwks_uri) client.enableNonRepudiationChecks(config);
    if (spec.encrypted) {
      if (!encryption) throw fail('NOT_CONFIGURED', 'This login needs an encryption key.');
      client.enableDecryptingResponses(config, undefined, { key: encryption.key, alg: encryption.alg, kid: encryption.kid });
    }
    return config;
  }

  function getConfig(): Promise<client.Configuration> {
    if (!configPromise || Date.now() - configLoadedAt > DISCOVERY_TTL_MS) {
      configLoadedAt = Date.now();
      configPromise = buildConfig().catch((err) => {
        configPromise = undefined;
        throw err;
      });
    }
    return configPromise;
  }

  function checkStart(p: AuthStartParams) {
    const min = Math.max(spec.minStateLength ?? 0, 16);
    if (typeof p.state !== 'string' || p.state.length < min) throw fail('BAD_REQUEST', `state must be at least ${min} characters.`);
    if (typeof p.nonce !== 'string' || p.nonce.length < min) throw fail('BAD_REQUEST', `nonce must be at least ${min} characters.`);
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(p.codeVerifier ?? '')) throw fail('BAD_REQUEST', 'codeVerifier must be 43 to 128 URL-safe characters.');
    try {
      new URL(p.redirectUri);
    } catch {
      throw fail('BAD_REQUEST', 'redirectUri must be a full URL.');
    }
  }

  async function dpopFromSession(config: client.Configuration, session?: string): Promise<client.DPoPHandle | undefined> {
    if (!spec.dpop) return undefined;
    let data: SessionData;
    try {
      data = JSON.parse(session ?? '{}') as SessionData;
    } catch {
      throw fail('INVALID_RESPONSE', 'The saved login session is damaged.');
    }
    if (!data.dpop) throw fail('INVALID_RESPONSE', 'The saved login session is missing its key.');
    const privateKey = (await importJWK(data.dpop.privateJwk, 'ES256')) as CryptoKey;
    const publicKey = (await importJWK(data.dpop.publicJwk, 'ES256', { extractable: true })) as CryptoKey;
    return client.getDPoPHandle(config, { privateKey, publicKey });
  }

  const connector: Connector = {
    id,
    label: spec.label,
    countries: spec.countries,
    assurance: spec.assurance,
    callbackMethod: 'GET',

    isConfigured(e: Env) {
      return hasAll(e, id, spec.required(e));
    },

    async buildAuthUrl(p: AuthStartParams): Promise<AuthStart> {
      checkStart(p);
      try {
        const config = await getConfig();
        const params: Record<string, string> = {
          response_type: 'code',
          redirect_uri: p.redirectUri,
          state: p.state,
          code_challenge: await client.calculatePKCECodeChallenge(p.codeVerifier),
          code_challenge_method: 'S256',
          ...spec.authParams(env, p),
        };
        if (spec.idToken) params.nonce = p.nonce;

        let session: SessionData | undefined;
        let dpop: client.DPoPHandle | undefined;
        if (spec.dpop) {
          const pair = await client.randomDPoPKeyPair('ES256', { extractable: true });
          session = { dpop: { privateJwk: await exportJWK(pair.privateKey), publicJwk: await exportJWK(pair.publicKey) } };
          dpop = client.getDPoPHandle(config, pair);
        }
        const url = spec.par
          ? await client.buildAuthorizationUrlWithPAR(config, params, dpop ? { DPoP: dpop } : undefined)
          : client.buildAuthorizationUrl(config, params);
        return { authUrl: url.href, session: session ? JSON.stringify(session) : undefined };
      } catch (err) {
        throw mapError(id, err);
      }
    },

    async handleCallback(c: CallbackParams): Promise<ConnectorResult> {
      const params = c.params ?? {};
      if (typeof params.error === 'string') {
        throw fail('PROVIDER_ERROR', 'The login was cancelled or refused by the provider.', params.error);
      }
      if (typeof params.state !== 'string' || params.state !== c.state) {
        throw fail('STATE_MISMATCH', 'The login answer does not belong to this session.');
      }
      if (typeof params.code !== 'string' || params.code === '') {
        throw fail('INVALID_RESPONSE', 'The login answer has no code.');
      }
      try {
        const config = await getConfig();
        const dpop = await dpopFromSession(config, c.session);
        const currentUrl = new URL(c.redirectUri);
        for (const [k, v] of Object.entries(params)) currentUrl.searchParams.set(k, v);

        const tokens = await client.authorizationCodeGrant(
          config,
          currentUrl,
          {
            pkceCodeVerifier: c.codeVerifier,
            expectedState: c.state,
            expectedNonce: spec.idToken ? c.nonce : undefined,
            idTokenExpected: spec.idToken,
          },
          undefined,
          dpop ? { DPoP: dpop } : undefined,
        );
        const idToken = spec.idToken ? (tokens.claims() as Record<string, unknown> | undefined) : undefined;
        const token = tokens as unknown as Record<string, unknown>;
        let extracted: Extracted | undefined;
        if (spec.userinfo === 'if-needed') {
          extracted = spec.extract({ idToken, token }, env);
          const answered = typeof extracted.over18 === 'boolean' || extracted.birthDate !== undefined;
          if (answered || !config.serverMetadata().userinfo_endpoint) return decide(id, extracted, now());
        }
        let userinfo: Record<string, unknown> | undefined;
        if (spec.userinfo) {
          const expectedSub = typeof idToken?.sub === 'string' ? idToken.sub : client.skipSubjectCheck;
          userinfo = (await client.fetchUserInfo(config, tokens.access_token, expectedSub, dpop ? { DPoP: dpop } : undefined)) as Record<
            string,
            unknown
          >;
        }
        extracted = spec.extract({ idToken, userinfo, token }, env);
        return decide(id, extracted, now());
      } catch (err) {
        throw mapError(id, err);
      }
    },

    async jwks() {
      const { signing, encryption } = await keys();
      return { keys: [signing?.publicJwk, encryption?.publicJwk].filter(Boolean) as Record<string, unknown>[] };
    },
  };
  return connector;
}

/**
 * Turns what the provider said into the only allowed result: `{ over18, subject }`.
 * A fresh object is built, so nothing else can leak through.
 */
export function decide(id: ConnectorId, extracted: Extracted, now: Date): ConnectorResult {
  const subject = typeof extracted.subject === 'string' ? extracted.subject.trim() : '';
  if (subject === '') throw new ConnectorError(id, 'INVALID_RESPONSE', 'The provider did not send a stable user ID.');
  let over18: boolean;
  if (typeof extracted.over18 === 'boolean') over18 = extracted.over18;
  else if (extracted.birthDate) over18 = isOver18(extracted.birthDate, now);
  else throw new ConnectorError(id, 'MISSING_BIRTHDATE', 'The provider did not send a birth date.');
  return { over18, subject };
}

/** Maps any library error to a ConnectorError WITHOUT copying messages or causes (they can hold claims). */
export function mapError(id: ConnectorId, err: unknown): ConnectorError {
  if (err instanceof ConnectorError) return err;
  if (err instanceof client.AuthorizationResponseError) {
    return new ConnectorError(id, 'PROVIDER_ERROR', 'The login was cancelled or refused by the provider.', err.error);
  }
  if (err instanceof client.ResponseBodyError) {
    if (err.error === 'invalid_grant') {
      return new ConnectorError(id, 'INVALID_RESPONSE', 'The login code was already used, has expired, or is not valid.', err.error);
    }
    return new ConnectorError(id, 'INVALID_RESPONSE', 'The provider refused the request.', err.error);
  }
  const code = typeof (err as { code?: unknown })?.code === 'string' ? (err as { code: string }).code : undefined;
  if (code === 'OAUTH_INVALID_RESPONSE' && /state/i.test(String((err as Error).message))) {
    return new ConnectorError(id, 'STATE_MISMATCH', 'The login answer does not belong to this session.', code);
  }
  return new ConnectorError(id, 'INVALID_RESPONSE', 'The login answer could not be checked.', code);
}

/** Small helpers for `extract` functions. */
export function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

/**
 * Client authentication for secret-based or key-based providers and brokers:
 * private_key_jwt when a signing key is set, otherwise the secret method
 * (`V18_CONNECTOR_<ID>_AUTH_METHOD` may pick client_secret_post or client_secret_basic).
 */
export function secretOrKeyAuth(id: ConnectorId, fallback: ClientAuthMethod = 'client_secret_basic') {
  return (env: Env): ClientAuthMethod => {
    if (envValue(env, id, 'SIGNING_KEY')) return 'private_key_jwt';
    const m = envValue(env, id, 'AUTH_METHOD');
    return m === 'client_secret_post' || m === 'client_secret_basic' ? m : fallback;
  };
}

export function secretOrKeyRequired(id: ConnectorId, extra: readonly string[] = []) {
  return (env: Env): readonly string[] =>
    envValue(env, id, 'SIGNING_KEY') ? ['CLIENT_ID', 'SIGNING_KEY', ...extra] : ['CLIENT_ID', 'CLIENT_SECRET', ...extra];
}
