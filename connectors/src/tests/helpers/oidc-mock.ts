/**
 * TEST ONLY: a local OpenID Connect provider built with the `oidc-provider` package.
 * Each test profile sets it up like the real provider (client auth, PAR, DPoP, encryption,
 * claim names and formats). The "person" who logs in is whatever the test puts in `account`.
 * Logins are approved automatically (no screens).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { JWK } from 'jose';
import { jwkPair } from './keys.js';

export interface MockAccount {
  /** The provider's `sub`. */
  sub: string;
  /** Claims the provider knows about this person, in the provider's own format. */
  claims: Record<string, unknown>;
}

export interface OidcMockProfile {
  /** oidc-provider `claims` setting: scope -> claim names, or claim -> null for standalone claims. */
  claims: Record<string, string[] | null>;
  scopes: string[];
  /** The client exactly as the real provider would register V18. */
  client: Record<string, unknown>;
  /** Put scope claims in the ID token too (BankID NO, MitID age_verify, Freja). */
  idTokenHasScopeClaims?: boolean;
  /** Extra authorization parameters the real provider accepts. */
  extraParams?: string[];
  /** Signing algorithm of the provider's keys (ID token, userinfo JWT). */
  signingAlg: 'ES256' | 'RS256';
  /** Path prefix, so the issuer looks like the real one (for example `/fapi`). */
  path?: string;
}

export interface OidcMock {
  issuer: string;
  discoveryUrl: string;
  account: MockAccount;
  /** Serve a JWKS with the same key IDs but different keys, so every signature check fails. */
  tamperJwks: boolean;
  /** How many interactions ran (shows the provider really ran a login). */
  logins: number;
  close(): Promise<void>;
}

export async function startOidcMock(profile: OidcMockProfile): Promise<OidcMock> {
  const { default: Provider } = await import('oidc-provider');
  const providerKey = await jwkPair(profile.signingAlg, 'mock-signing-1', 'sig');
  const decoyKey = await jwkPair(profile.signingAlg, 'mock-signing-1', 'sig');

  let server: Server | undefined;
  await new Promise<void>((resolve) => {
    server = createServer();
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const port = (server!.address() as AddressInfo).port;
  const base = `http://127.0.0.1:${port}`;
  const issuer = `${base}${profile.path ?? ''}`;

  const mock: OidcMock = {
    issuer,
    discoveryUrl: `${issuer}/.well-known/openid-configuration`,
    account: { sub: 'nobody', claims: {} },
    tamperJwks: false,
    logins: 0,
    close: () => new Promise<void>((r) => server!.close(() => r())),
  };

  const provider = new Provider(issuer, {
    clients: [profile.client as never],
    jwks: { keys: [providerKey.privateJwk as JWK & { kid: string }] } as never,
    claims: profile.claims as never,
    scopes: profile.scopes,
    conformIdTokenClaims: !profile.idTokenHasScopeClaims,
    extraParams: profile.extraParams ?? [],
    responseTypes: ['code'],
    pkce: { required: () => true },
    features: {
      devInteractions: { enabled: false },
      encryption: { enabled: true },
      jwtUserinfo: { enabled: true },
      claimsParameter: { enabled: true },
      dPoP: { enabled: true },
      pushedAuthorizationRequests: { enabled: true },
      revocation: { enabled: false },
    },
    enabledJWA: {
      idTokenEncryptionAlgValues: ['ECDH-ES+A256KW', 'RSA-OAEP', 'RSA-OAEP-256'],
      userinfoEncryptionAlgValues: ['ECDH-ES+A256KW', 'RSA-OAEP', 'RSA-OAEP-256'],
      idTokenEncryptionEncValues: ['A128CBC-HS256', 'A256CBC-HS512', 'A256GCM'],
      userinfoEncryptionEncValues: ['A128CBC-HS256', 'A256CBC-HS512', 'A256GCM'],
    },
    cookies: { keys: ['v18-mock-cookie-key-not-secret'] },
    findAccount: async (_ctx: unknown, sub: string) => ({
      accountId: sub,
      claims: async () => ({ sub, ...mock.account.claims }),
    }),
    interactions: { url: (_ctx: unknown, interaction: { uid: string }) => `${profile.path ?? ''}/interaction/${interaction.uid}` },
    issueRefreshToken: () => false,
    renderError: async (ctx: { type: string; body: unknown }, out: unknown) => {
      ctx.type = 'json';
      ctx.body = out;
    },
  } as never);
  provider.on('server_error', () => undefined);

  const callback = provider.callback();
  const prefix = profile.path ?? '';
  server!.on('request', async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = req.url ?? '/';
      if (mock.tamperJwks && req.method === 'GET' && /\/jwks$/.test(url.split('?')[0])) {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ keys: [decoyKey.publicJwk] }));
        return;
      }
      if (url.startsWith(`${prefix}/interaction/`)) {
        const details = await provider.interactionDetails(req, res);
        const prompt = details.prompt as { name: string; details: { missingOIDCScope?: string[]; missingOIDCClaims?: string[] } };
        const params = details.params as { client_id: string; scope?: string };
        let result: Record<string, unknown>;
        if (prompt.name === 'login') {
          mock.logins++;
          result = { login: { accountId: mock.account.sub } };
        } else {
          const grant = new provider.Grant({ accountId: (details.session as { accountId: string }).accountId, clientId: params.client_id });
          if (prompt.details.missingOIDCScope) grant.addOIDCScope(prompt.details.missingOIDCScope.join(' '));
          if (prompt.details.missingOIDCClaims) grant.addOIDCClaims(prompt.details.missingOIDCClaims);
          result = { consent: { grantId: await grant.save() } };
        }
        await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
        return;
      }
      if (prefix && url.startsWith(prefix)) req.url = url.slice(prefix.length) || '/';
      callback(req, res);
    } catch (err) {
      res.statusCode = 500;
      res.end(String(err));
    }
  });
  return mock;
}
