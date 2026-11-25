/**
 * TEST ONLY: a small OAuth 2.0 authorization server for the two plain-OAuth providers
 * (DigiLocker and UAE PASS). It checks what the real ones check: client credentials
 * (POST body or HTTP Basic), the exact redirect_uri, PKCE S256, and that a code works once.
 * It answers with the provider's documented field names and formats.
 */
import { createHash, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface OAuthMockOptions {
  clientId: string;
  clientSecret: string;
  clientAuth: 'post' | 'basic';
  authorizePath: string;
  tokenPath: string;
  userinfoPath?: string;
  /** Parameters the authorize request must carry (for example DigiLocker's purpose and service_name). */
  requiredAuthorizeParams?: string[];
  requirePkce: boolean;
}

export interface OAuthMock {
  base: string;
  /** Extra fields for the token response (DigiLocker puts user details here). */
  tokenExtras: Record<string, unknown>;
  /** The userinfo JSON (UAE PASS). */
  userinfo: Record<string, unknown>;
  /** Last authorize query, so tests can check what V18 sent. */
  lastAuthorize?: URLSearchParams;
  close(): Promise<void>;
}

export async function startOAuthMock(o: OAuthMockOptions): Promise<OAuthMock> {
  const codes = new Map<string, { redirectUri: string; challenge?: string; used: boolean }>();
  const tokens = new Set<string>();
  let server: Server;
  const mock: OAuthMock = {
    base: '',
    tokenExtras: {},
    userinfo: {},
    close: () => new Promise<void>((r) => server.close(() => r())),
  };

  const json = (res: import('node:http').ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
  };

  server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', mock.base);
    if (req.method === 'GET' && url.pathname === o.authorizePath) {
      const q = url.searchParams;
      mock.lastAuthorize = q;
      const redirectUri = q.get('redirect_uri');
      if (q.get('client_id') !== o.clientId || !redirectUri) return json(res, 400, { error: 'invalid_request' });
      if (q.get('response_type') !== 'code') return json(res, 400, { error: 'unsupported_response_type' });
      for (const p of o.requiredAuthorizeParams ?? []) if (!q.get(p)) return json(res, 400, { error: 'invalid_request', error_description: `missing ${p}` });
      if (o.requirePkce && (q.get('code_challenge_method') !== 'S256' || !q.get('code_challenge'))) return json(res, 400, { error: 'invalid_request' });
      const code = randomBytes(20).toString('hex');
      codes.set(code, { redirectUri, challenge: q.get('code_challenge') ?? undefined, used: false });
      const back = new URL(redirectUri);
      back.searchParams.set('code', code);
      if (q.get('state')) back.searchParams.set('state', q.get('state')!);
      res.writeHead(302, { location: back.href });
      res.end();
      return;
    }
    if (req.method === 'POST' && url.pathname === o.tokenPath) {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const f = new URLSearchParams(body);
        let id: string | null = null;
        let secret: string | null = null;
        if (o.clientAuth === 'basic') {
          const h = req.headers.authorization ?? '';
          if (h.startsWith('Basic ')) {
            const [a, b] = Buffer.from(h.slice(6), 'base64').toString('utf8').split(':');
            id = decodeURIComponent(a ?? '');
            secret = decodeURIComponent(b ?? '');
          }
        } else {
          id = f.get('client_id');
          secret = f.get('client_secret');
        }
        if (id !== o.clientId || secret !== o.clientSecret) return json(res, 401, { error: 'invalid_client' });
        if (f.get('grant_type') !== 'authorization_code') return json(res, 400, { error: 'unsupported_grant_type' });
        const entry = codes.get(f.get('code') ?? '');
        if (!entry || entry.used) return json(res, 400, { error: 'invalid_grant' });
        entry.used = true;
        if (entry.redirectUri !== f.get('redirect_uri')) return json(res, 400, { error: 'invalid_grant' });
        if (entry.challenge) {
          const v = f.get('code_verifier') ?? '';
          if (createHash('sha256').update(v).digest('base64url') !== entry.challenge) return json(res, 400, { error: 'invalid_grant' });
        }
        const accessToken = randomBytes(20).toString('hex');
        tokens.add(accessToken);
        json(res, 200, { access_token: accessToken, expires_in: 3600, token_type: 'Bearer', ...mock.tokenExtras });
      });
      return;
    }
    if (req.method === 'GET' && o.userinfoPath && url.pathname === o.userinfoPath) {
      const h = req.headers.authorization ?? '';
      if (!h.startsWith('Bearer ') || !tokens.has(h.slice(7))) return json(res, 401, { error: 'invalid_token' });
      return json(res, 200, mock.userinfo);
    }
    json(res, 404, { error: 'not_found' });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  mock.base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return mock;
}
