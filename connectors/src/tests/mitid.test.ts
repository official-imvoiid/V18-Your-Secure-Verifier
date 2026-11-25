/**
 * MitID through the Signaturgruppen broker, against a local oidc-provider mock set up like
 * the broker: default `openid age_verify:18` returning only `idbrokerdk_age_verified: "18:true"`
 * in the ID token; mode `mitid` returning `mitid.date_of_birth` from userinfo.
 */
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { createConnector } from '../registry.js';
import { birthDateForAge } from './helpers/keys.js';
import { assertConnectorError, assertOnlyAgeAndSubject } from './helpers/checks.js';
import { login, oidcBattery } from './helpers/oidc-battery.js';
import { startOidcMock, type OidcMock } from './helpers/oidc-mock.js';

const REDIRECT = 'https://api.v18.test/v1/connect/mitid/callback';
const SECRET = 'test-secret-mitid-0123456789abcdef0123456789';
const minor = birthDateForAge(17);

const profile = () => ({
  signingAlg: 'RS256' as const,
  scopes: ['openid', 'age_verify:18', 'mitid'],
  claims: {
    openid: ['sub'],
    'age_verify:18': ['idbrokerdk_age_verified'],
    mitid: ['mitid.uuid', 'mitid.date_of_birth', 'mitid.age', 'mitid.identity_name'],
    identity_type: null,
    idp: null,
    loa: null,
  },
  idTokenHasScopeClaims: true,
  extraParams: ['idp_values', 'idp_params'],
  client: {
    client_id: 'v18-mitid',
    client_secret: SECRET,
    token_endpoint_auth_method: 'client_secret_basic',
    redirect_uris: [REDIRECT],
    response_types: ['code'],
    grant_types: ['authorization_code'],
  },
});

const brokerSub = (n: string) => `${n}`.padEnd(8, '0') + '-6b5a-4a2c-9d77-0f1e2d3c4b5a';

oidcBattery({
  id: 'mitid',
  redirectUri: REDIRECT,
  profile: async () => profile(),
  env: (mock) => ({ V18_CONNECTOR_MITID_CLIENT_ID: 'v18-mitid', V18_CONNECTOR_MITID_CLIENT_SECRET: SECRET, V18_CONNECTOR_MITID_ISSUER: mock.discoveryUrl }),
  adult: { sub: brokerSub('a'), claims: { idbrokerdk_age_verified: '18:true', identity_type: 'private', idp: 'mitid', loa: 'https://data.gov.dk/concept/core/nsis/Substantial' } },
  adultSubject: brokerSub('a'),
  minor: { sub: brokerSub('b'), claims: { idbrokerdk_age_verified: '18:false', identity_type: 'private', idp: 'mitid' } },
  missing: { sub: brokerSub('c'), claims: { identity_type: 'private', idp: 'mitid' } },
  personal: [],
  extra: ({ connector }) => {
    test('mitid: default mode asks only "is this person 18?" (scope age_verify:18), no birth date', async () => {
      const { authUrl } = await connector().buildAuthUrl({ state: 's'.repeat(40), nonce: 'n'.repeat(40), codeVerifier: 'v'.repeat(50), redirectUri: REDIRECT });
      assert.equal(new URL(authUrl).searchParams.get('scope'), 'openid age_verify:18');
    });
  },
});

describe('mitid MODE=mitid (full MitID claims from userinfo)', () => {
  let mock: OidcMock;
  before(async () => {
    mock = await startOidcMock(profile());
  });
  after(() => mock.close());
  const env = () => ({
    V18_CONNECTOR_MITID_CLIENT_ID: 'v18-mitid',
    V18_CONNECTOR_MITID_CLIENT_SECRET: SECRET,
    V18_CONNECTOR_MITID_ISSUER: mock.discoveryUrl,
    V18_CONNECTOR_MITID_MODE: 'mitid',
  });
  const person = (dob?: string) => ({
    sub: brokerSub('d'),
    claims: { 'mitid.uuid': '7a3f8c1e-0000-4000-8000-1234567890ab', 'mitid.identity_name': 'Lars Hansen', 'mitid.age': 40, ...(dob ? { 'mitid.date_of_birth': dob } : {}) },
  });

  test('adult: over18 true, only over18 and subject', async () => {
    const c = createConnector('mitid', env(), { allowInsecureLocalhost: true });
    const cb = await login(c, mock, person('1985-02-28'), REDIRECT);
    assertOnlyAgeAndSubject(await c.handleCallback(cb), { over18: true, subject: brokerSub('d') });
  });
  test('minor: over18 false', async () => {
    const c = createConnector('mitid', env(), { allowInsecureLocalhost: true });
    const cb = await login(c, mock, person(minor.iso), REDIRECT);
    assert.equal((await c.handleCallback(cb)).over18, false);
  });
  test('no date of birth: MISSING_BIRTHDATE, nothing leaks', async () => {
    const c = createConnector('mitid', env(), { allowInsecureLocalhost: true });
    const cb = await login(c, mock, person(), REDIRECT);
    await assertConnectorError(c.handleCallback(cb), 'MISSING_BIRTHDATE', { mustNotContain: ['Lars Hansen', '7a3f8c1e'] });
  });
});
