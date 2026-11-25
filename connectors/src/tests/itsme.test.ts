/**
 * itsme against a local oidc-provider mock set up like itsme v2: scope
 * `openid service:<code>`, the `claims` parameter for `age_gte_18`, private_key_jwt (RS256),
 * ID token and userinfo signed then encrypted (RSA-OAEP / A128CBC-HS256).
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createConnector } from '../registry.js';
import { birthDateForAge, jwkPair } from './helpers/keys.js';
import { login, oidcBattery } from './helpers/oidc-battery.js';
import type { OidcMock } from './helpers/oidc-mock.js';

const REDIRECT = 'https://api.v18.test/v1/connect/itsme/callback';
const keys = (async () => ({ sig: await jwkPair('RS256', 'v18-itsme-sig', 'sig'), enc: await jwkPair('RSA-OAEP', 'v18-itsme-enc', 'enc') }))();
const minor = birthDateForAge(17);
const sub = (n: string) => `${n}`.padEnd(36, '0');

const envFor = async (mock: OidcMock, extra: Record<string, string> = {}) => {
  const k = await keys;
  return {
    V18_CONNECTOR_ITSME_CLIENT_ID: 'v18-itsme',
    V18_CONNECTOR_ITSME_SERVICE_CODE: 'V18AGECHECK',
    V18_CONNECTOR_ITSME_SIGNING_KEY: JSON.stringify(k.sig.privateJwk),
    V18_CONNECTOR_ITSME_ENCRYPTION_KEY: JSON.stringify(k.enc.privateJwk),
    V18_CONNECTOR_ITSME_ISSUER: mock.discoveryUrl,
    ...extra,
  };
};

oidcBattery({
  id: 'itsme',
  redirectUri: REDIRECT,
  profile: async () => {
    const k = await keys;
    return {
      signingAlg: 'RS256',
      scopes: ['openid', 'service:V18AGECHECK', 'profile'],
      claims: { openid: ['sub'], profile: ['birthdate', 'given_name', 'family_name'], age_gte_18: null, birthdate: null },
      client: {
        client_id: 'v18-itsme',
        redirect_uris: [REDIRECT],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'RS256',
        jwks: { keys: [k.sig.publicJwk, k.enc.publicJwk] },
        id_token_signed_response_alg: 'RS256',
        id_token_encrypted_response_alg: 'RSA-OAEP',
        id_token_encrypted_response_enc: 'A128CBC-HS256',
        userinfo_signed_response_alg: 'RS256',
        userinfo_encrypted_response_alg: 'RSA-OAEP',
        userinfo_encrypted_response_enc: 'A128CBC-HS256',
      },
    };
  },
  env: (mock) => envFor(mock),
  adult: { sub: sub('a1b2c3'), claims: { age_gte_18: true, birthdate: '1974-10-23', given_name: 'Jan', family_name: 'Peeters' } },
  adultSubject: sub('a1b2c3'),
  minor: { sub: sub('m1n0r'), claims: { age_gte_18: false, birthdate: minor.iso, given_name: 'Lien', family_name: 'Peeters' } },
  missing: { sub: sub('n0dat'), claims: { given_name: 'Noor', family_name: 'Janssens' } },
  personal: ['1974-10-23', 'Jan', 'Peeters', minor.iso, 'Janssens'],
  extra: ({ mock, connector }) => {
    test('itsme: asks only for age_gte_18 through the claims parameter, with the service code', async () => {
      const { authUrl } = await connector().buildAuthUrl({ state: 's'.repeat(40), nonce: 'n'.repeat(40), codeVerifier: 'v'.repeat(50), redirectUri: REDIRECT });
      const q = new URL(authUrl).searchParams;
      assert.equal(q.get('scope'), 'openid service:V18AGECHECK');
      assert.deepEqual(JSON.parse(q.get('claims')!), { userinfo: { age_gte_18: null } });
    });
    test('itsme: with ASK_BIRTHDATE=1 a birth date is the fallback when age_gte_18 is absent', async () => {
      const env = await envFor(mock(), { V18_CONNECTOR_ITSME_ASK_BIRTHDATE: '1' });
      const c = createConnector('itsme', env, { allowInsecureLocalhost: true });
      const cb = await login(c, mock(), { sub: sub('fallback'), claims: { birthdate: '1990-01-02' } }, REDIRECT);
      assert.deepEqual(await c.handleCallback(cb), { over18: true, subject: sub('fallback') });
    });
  },
});
