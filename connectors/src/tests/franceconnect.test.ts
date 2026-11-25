/**
 * FranceConnect v2 against a local oidc-provider mock set up like FranceConnect:
 * scope `openid birthdate`, acr `eidas1`, client_secret_post, ES256 ID token,
 * userinfo as an ES256-signed JWT, `sub` of 64 hex characters + "v1".
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { franceConnectDate } from '../providers/oidc-providers.js';
import { birthDateForAge } from './helpers/keys.js';
import { oidcBattery } from './helpers/oidc-battery.js';

const REDIRECT = 'https://api.v18.test/v1/connect/franceconnect/callback';
const minor = birthDateForAge(17, -60);
const sub = (c: string) => c.repeat(64).slice(0, 64) + 'v1';
const pivot = (birthdate?: string) => ({
  given_name: 'Angela Claire Louise',
  family_name: 'DUBOIS',
  gender: 'female',
  birthplace: '75107',
  birthcountry: '99100',
  ...(birthdate ? { birthdate } : {}),
});

oidcBattery({
  id: 'franceconnect',
  redirectUri: REDIRECT,
  profile: async () => ({
    signingAlg: 'ES256',
    scopes: ['openid', 'birthdate', 'profile'],
    claims: { openid: ['sub'], birthdate: ['birthdate'], profile: ['given_name', 'family_name', 'gender', 'birthdate'] },
    client: {
      client_id: 'v18-franceconnect',
      client_secret: 'test-secret-franceconnect-0123456789abcdef0123',
      token_endpoint_auth_method: 'client_secret_post',
      redirect_uris: [REDIRECT],
      response_types: ['code'],
      grant_types: ['authorization_code'],
      id_token_signed_response_alg: 'ES256',
      userinfo_signed_response_alg: 'ES256',
    },
  }),
  env: (mock) => ({
    V18_CONNECTOR_FRANCECONNECT_CLIENT_ID: 'v18-franceconnect',
    V18_CONNECTOR_FRANCECONNECT_CLIENT_SECRET: 'test-secret-franceconnect-0123456789abcdef0123',
    V18_CONNECTOR_FRANCECONNECT_ISSUER: mock.discoveryUrl,
  }),
  adult: { sub: sub('b6048e95bb134ec5'), claims: pivot('1962-08-24') },
  adultSubject: sub('b6048e95bb134ec5'),
  minor: { sub: sub('c0ffee'), claims: pivot(minor.iso) },
  missing: { sub: sub('d00d'), claims: pivot() },
  personal: ['1962-08-24', 'Angela', 'DUBOIS', '75107', minor.iso],
  extra: ({ connector }) => {
    test('franceconnect: sends eidas1, the birthdate scope, and refuses short state or nonce', async () => {
      const { authUrl } = await connector().buildAuthUrl({ state: 's'.repeat(40), nonce: 'n'.repeat(40), codeVerifier: 'v'.repeat(50), redirectUri: REDIRECT });
      const q = new URL(authUrl).searchParams;
      assert.equal(q.get('acr_values'), 'eidas1');
      assert.equal(q.get('scope'), 'openid birthdate');
      await assert.rejects(connector().buildAuthUrl({ state: 's'.repeat(20), nonce: 'n'.repeat(40), codeVerifier: 'v'.repeat(50), redirectUri: REDIRECT }), { code: 'BAD_REQUEST' });
    });
  },
});

test('franceconnect: a guessed "-01-01" or "-01" date is treated as unknown day/month (cautious)', () => {
  assert.deepEqual(franceConnectDate('2008-01-01'), { year: 2008 });
  assert.deepEqual(franceConnectDate('2008-06-01'), { year: 2008, month: 6 });
  assert.deepEqual(franceConnectDate('2008-06-15'), { year: 2008, month: 6, day: 15 });
});
