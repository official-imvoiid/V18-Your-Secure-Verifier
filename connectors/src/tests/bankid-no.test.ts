/**
 * BankID Norway against a local oidc-provider mock set up like BankID's OIDC provider:
 * scope `openid profile`, `birthdate` and the stable `bankid_altsub` in the ID token,
 * client_secret_basic (or private_key_jwt), RS256.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createConnector } from '../registry.js';
import { birthDateForAge, jwkPair } from './helpers/keys.js';
import { login, oidcBattery } from './helpers/oidc-battery.js';
import { startOidcMock } from './helpers/oidc-mock.js';

const REDIRECT = 'https://api.v18.test/v1/connect/bankid_no/callback';
const minor = birthDateForAge(17);
const person = (sub: string, altsub: string, birthdate?: string) => ({
  sub,
  claims: { bankid_altsub: altsub, given_name: 'Kari', family_name: 'Nordmann', name: 'Kari Nordmann', ...(birthdate ? { birthdate } : {}) },
});

const profile = (client: Record<string, unknown>) => ({
  signingAlg: 'RS256' as const,
  scopes: ['openid', 'profile'],
  claims: { openid: ['sub', 'bankid_altsub'], profile: ['birthdate', 'given_name', 'family_name', 'name'] },
  idTokenHasScopeClaims: true,
  client: { redirect_uris: [REDIRECT], response_types: ['code'], grant_types: ['authorization_code'], id_token_signed_response_alg: 'RS256', ...client },
});

oidcBattery({
  id: 'bankid_no',
  redirectUri: REDIRECT,
  profile: async () => profile({ client_id: 'v18-bankid-no', client_secret: 'test-secret-bankid-no-0123456789abcdef', token_endpoint_auth_method: 'client_secret_basic' }),
  env: (mock) => ({
    V18_CONNECTOR_BANKID_NO_CLIENT_ID: 'v18-bankid-no',
    V18_CONNECTOR_BANKID_NO_CLIENT_SECRET: 'test-secret-bankid-no-0123456789abcdef',
    V18_CONNECTOR_BANKID_NO_ISSUER: mock.discoveryUrl,
  }),
  adult: person('e8c523ff-52a2-42e2-a7a5-f1d0fbb76204', '9578-5999-4-1765512', '1986-10-01'),
  adultSubject: '9578-5999-4-1765512',
  minor: person('11111111-52a2-42e2-a7a5-f1d0fbb76204', '9578-5999-4-0000017', minor.iso),
  missing: person('22222222-52a2-42e2-a7a5-f1d0fbb76204', '9578-5999-4-0000099'),
  personal: ['1986-10-01', 'Kari', 'Nordmann', minor.iso],
  extra: ({ mock, connector }) => {
    test('bankid_no: asks for BankID High (acr urn:bankid:bid) with PKCE S256', async () => {
      const { authUrl } = await connector().buildAuthUrl({ state: 's'.repeat(40), nonce: 'n'.repeat(40), codeVerifier: 'v'.repeat(50), redirectUri: REDIRECT });
      const q = new URL(authUrl).searchParams;
      assert.equal(q.get('acr_values'), 'urn:bankid:bid');
      assert.equal(q.get('scope'), 'openid profile');
      assert.equal(q.get('code_challenge_method'), 'S256');
    });
    test('bankid_no: without the stable bankid_altsub the login is refused (sub is documented as unstable)', async () => {
      const cb = await login(connector(), mock(), { sub: 'x', claims: { birthdate: '1986-10-01' } }, REDIRECT);
      await assert.rejects(connector().handleCallback(cb), { code: 'INVALID_RESPONSE' });
    });
  },
});

test('bankid_no: private_key_jwt works when a signing key is set instead of a secret', async () => {
  const sig = await jwkPair('RS256', 'v18-bankid-no-sig', 'sig');
  const mock = await startOidcMock(
    profile({ client_id: 'v18-bankid-no-pkjwt', token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_signing_alg: 'RS256', jwks: { keys: [sig.publicJwk] } }),
  );
  try {
    const env = {
      V18_CONNECTOR_BANKID_NO_CLIENT_ID: 'v18-bankid-no-pkjwt',
      V18_CONNECTOR_BANKID_NO_SIGNING_KEY: JSON.stringify(sig.privateJwk),
      V18_CONNECTOR_BANKID_NO_ISSUER: mock.discoveryUrl,
    };
    const c = createConnector('bankid_no', env, { allowInsecureLocalhost: true });
    assert.equal(c.isConfigured(env), true);
    const cb = await login(c, mock, person('p-1', '9578-5999-4-1234567', '1990-02-03'), REDIRECT);
    assert.deepEqual(await c.handleCallback(cb), { over18: true, subject: '9578-5999-4-1234567' });
  } finally {
    await mock.close();
  }
});
