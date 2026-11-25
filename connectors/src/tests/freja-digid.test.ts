/**
 * Freja eID (its own OIDC service) and DigiD (through an OIDC broker), each against a local
 * oidc-provider mock set up in that provider's format.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createConnector } from '../registry.js';
import { birthDateForAge } from './helpers/keys.js';
import { oidcBattery } from './helpers/oidc-battery.js';

const minor = birthDateForAge(17);

// ---------------------------------------------------------------- Freja eID
const FREJA_REDIRECT = 'https://api.v18.test/v1/connect/freja/callback';
const FREJA_SCOPE = 'https://frejaeid.com/oidc/scopes/birthdate';
const frejaPerson = (sub: string, birthdate?: string) => ({
  sub,
  claims: {
    'https://frejaeid.com/oidc/claims/registrationLevel': 'EXTENDED',
    ...(birthdate ? { birthdate } : {}),
  },
});

oidcBattery({
  id: 'freja',
  redirectUri: FREJA_REDIRECT,
  profile: async () => ({
    signingAlg: 'RS256',
    scopes: ['openid', FREJA_SCOPE],
    claims: { openid: ['sub', 'https://frejaeid.com/oidc/claims/registrationLevel'], [FREJA_SCOPE]: ['birthdate'] },
    idTokenHasScopeClaims: true,
    extraParams: ['min_registration_level'],
    client: {
      client_id: 'v18-freja',
      client_secret: 'test-secret-freja-0123456789abcdef0123456789',
      token_endpoint_auth_method: 'client_secret_post',
      redirect_uris: [FREJA_REDIRECT],
      response_types: ['code'],
      grant_types: ['authorization_code'],
    },
  }),
  env: (mock) => ({
    V18_CONNECTOR_FREJA_CLIENT_ID: 'v18-freja',
    V18_CONNECTOR_FREJA_CLIENT_SECRET: 'test-secret-freja-0123456789abcdef0123456789',
    V18_CONNECTOR_FREJA_ISSUER: mock.discoveryUrl,
  }),
  adult: frejaPerson('freja-user-0001', '1979-04-12'),
  adultSubject: 'freja-user-0001',
  minor: frejaPerson('freja-user-0017', minor.iso),
  missing: frejaPerson('freja-user-0099'),
  personal: ['1979-04-12', minor.iso],
  extra: ({ connector }) => {
    test('freja: asks for the birthdate scope and an EXTENDED (ID-checked) account', async () => {
      const { authUrl } = await connector().buildAuthUrl({ state: 's'.repeat(40), nonce: 'n'.repeat(40), codeVerifier: 'v'.repeat(50), redirectUri: FREJA_REDIRECT });
      const q = new URL(authUrl).searchParams;
      assert.equal(q.get('scope'), `openid ${FREJA_SCOPE}`);
      assert.equal(q.get('min_registration_level'), 'EXTENDED');
    });
  },
});

// ---------------------------------------------------------------- DigiD via a broker
const DIGID_REDIRECT = 'https://api.v18.test/v1/connect/digid/callback';
const digidPerson = (sub: string, birthdate?: string) => ({
  sub,
  claims: { 'nl.bsn': '999993653', ...(birthdate ? { birthdate } : {}) },
});

oidcBattery({
  id: 'digid',
  redirectUri: DIGID_REDIRECT,
  profile: async () => ({
    signingAlg: 'RS256',
    scopes: ['openid', 'profile'],
    claims: { openid: ['sub'], profile: ['birthdate'], 'nl.bsn': null },
    client: {
      client_id: 'v18-digid-broker',
      client_secret: 'test-secret-digid-0123456789abcdef0123456789',
      token_endpoint_auth_method: 'client_secret_basic',
      redirect_uris: [DIGID_REDIRECT],
      response_types: ['code'],
      grant_types: ['authorization_code'],
    },
  }),
  env: (mock) => ({
    V18_CONNECTOR_DIGID_CLIENT_ID: 'v18-digid-broker',
    V18_CONNECTOR_DIGID_CLIENT_SECRET: 'test-secret-digid-0123456789abcdef0123456789',
    V18_CONNECTOR_DIGID_ISSUER: mock.discoveryUrl,
    V18_CONNECTOR_DIGID_SCOPE: 'openid profile',
  }),
  adult: digidPerson('broker-pairwise-aaaa', '1980-12-31'),
  adultSubject: 'broker-pairwise-aaaa',
  minor: digidPerson('broker-pairwise-bbbb', minor.iso),
  missing: digidPerson('broker-pairwise-cccc'),
  personal: ['1980-12-31', '999993653', minor.iso],
});

test('digid: stays off without the broker issuer, even with a client ID and secret', () => {
  const env = { V18_CONNECTOR_DIGID_CLIENT_ID: 'x', V18_CONNECTOR_DIGID_CLIENT_SECRET: 'y' };
  assert.equal(createConnector('digid', env).isConfigured(env), false);
});
