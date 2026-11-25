/**
 * DigiLocker and UAE PASS (plain OAuth 2.0, no ID token) against a small local OAuth mock
 * that checks client credentials, redirect_uri, PKCE and one-time codes, and answers with each
 * provider's documented fields: DigiLocker's token response (digilockerid, dob as DDMMYYYY,
 * eaadhaar ...) and UAE PASS's userinfo JSON (sub, uuid, userType, idn ...).
 */
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { createConnector } from '../registry.js';
import { followToCallback, newStart, randomToken } from './helpers/browser.js';
import { assertConnectorError, assertOnlyAgeAndSubject } from './helpers/checks.js';
import { birthDateForAge, pad } from './helpers/keys.js';
import { startOAuthMock, type OAuthMock } from './helpers/oauth-mock.js';
import type { Connector, Env } from '../types.js';

async function login(c: Connector, redirectUri: string) {
  const start = newStart(redirectUri);
  const { authUrl, session } = await c.buildAuthUrl(start);
  const params = await followToCallback(authUrl, redirectUri);
  return { ...start, params, session };
}

const minor = birthDateForAge(17);

// ---------------------------------------------------------------- DigiLocker
describe('digilocker (local OAuth mock in the MeriPehchaan format)', () => {
  const REDIRECT = 'https://api.v18.test/v1/connect/digilocker/callback';
  let mock: OAuthMock;
  let env: Env;
  let c: Connector;
  const ddmmyyyy = (y: number, m: number, d: number) => `${pad(d)}${pad(m)}${y}`;
  const details = (dob: string | undefined, eaadhaar = 'Y') => ({
    scope: 'userdetails',
    consent_valid_till: 1893456000,
    digilockerid: '123e4567-e89b-12d3-a456-426655440000',
    name: 'Ajit Kumar',
    ...(dob !== undefined ? { dob } : {}),
    gender: 'M',
    eaadhaar,
    new_account: 'N',
    reference_key: '2a33349e7e606a8ad2e30e3c84521f9377450cf09083e162e0a9b1480ce0f972',
    mobile: '9999999999',
    purpose: 'verification',
  });

  before(async () => {
    mock = await startOAuthMock({
      clientId: 'V18TESTCLIENT',
      clientSecret: 'test-secret-digilocker-0123456789',
      clientAuth: 'post',
      authorizePath: '/public/oauth2/1/authorize',
      tokenPath: '/public/oauth2/1/token',
      requiredAuthorizeParams: ['state', 'purpose', 'service_name'],
      requirePkce: true,
    });
    env = {
      V18_CONNECTOR_DIGILOCKER_CLIENT_ID: 'V18TESTCLIENT',
      V18_CONNECTOR_DIGILOCKER_CLIENT_SECRET: 'test-secret-digilocker-0123456789',
      V18_CONNECTOR_DIGILOCKER_ISSUER: mock.base,
    };
    c = createConnector('digilocker', env, { allowInsecureLocalhost: true });
  });
  after(() => mock.close());

  test('is configured only with client ID and secret', () => {
    assert.equal(c.isConfigured(env), true);
    assert.equal(c.isConfigured({ V18_CONNECTOR_DIGILOCKER_CLIENT_ID: 'x' }), false);
  });
  test('sends PKCE S256 and the required purpose and service_name', async () => {
    mock.tokenExtras = details('31121970');
    await login(c, REDIRECT);
    const q = mock.lastAuthorize!;
    assert.equal(q.get('code_challenge_method'), 'S256');
    assert.equal(q.get('purpose'), 'Age check');
    assert.equal(q.get('service_name'), 'V18 age check');
  });
  test('over 18: only over18 and the DigiLocker ID come back (name, mobile, gender dropped)', async () => {
    mock.tokenExtras = details('31121970');
    const r = await c.handleCallback(await login(c, REDIRECT));
    assertOnlyAgeAndSubject(r, { over18: true, subject: '123e4567-e89b-12d3-a456-426655440000' });
    assert.ok(!JSON.stringify(r).includes('Ajit'));
  });
  test('under 18: over18 false', async () => {
    mock.tokenExtras = details(ddmmyyyy(minor.y, minor.m, minor.d));
    assert.equal((await c.handleCallback(await login(c, REDIRECT))).over18, false);
  });
  test('missing dob: MISSING_BIRTHDATE, no personal data in the error', async () => {
    mock.tokenExtras = details(undefined);
    await assertConnectorError(c.handleCallback(await login(c, REDIRECT)), 'MISSING_BIRTHDATE', { mustNotContain: ['Ajit', '9999999999'] });
  });
  test('account not linked to Aadhaar (eaadhaar N): refused by default', async () => {
    mock.tokenExtras = details('31121970', 'N');
    await assertConnectorError(c.handleCallback(await login(c, REDIRECT)), 'MISSING_BIRTHDATE');
  });
  test('replayed code: invalid_grant', async () => {
    mock.tokenExtras = details('31121970');
    const cb = await login(c, REDIRECT);
    await c.handleCallback(cb);
    await assertConnectorError(c.handleCallback(cb), 'INVALID_RESPONSE', { providerCode: 'invalid_grant' });
  });
  test('wrong PKCE verifier: invalid_grant', async () => {
    mock.tokenExtras = details('31121970');
    const cb = await login(c, REDIRECT);
    await assertConnectorError(c.handleCallback({ ...cb, codeVerifier: randomToken(48) }), 'INVALID_RESPONSE', { providerCode: 'invalid_grant' });
  });
  test('bad state: STATE_MISMATCH', async () => {
    mock.tokenExtras = details('31121970');
    const cb = await login(c, REDIRECT);
    await assertConnectorError(c.handleCallback({ ...cb, state: randomToken() }), 'STATE_MISMATCH');
  });
  test('wrong client secret: INVALID_RESPONSE invalid_client', async () => {
    const bad = createConnector('digilocker', { ...env, V18_CONNECTOR_DIGILOCKER_CLIENT_SECRET: 'wrong' }, { allowInsecureLocalhost: true });
    mock.tokenExtras = details('31121970');
    await assertConnectorError(bad.handleCallback(await login(bad, REDIRECT)), 'INVALID_RESPONSE', { providerCode: 'invalid_client' });
  });
  test('user denied consent: PROVIDER_ERROR', async () => {
    const s = newStart(REDIRECT);
    await assertConnectorError(c.handleCallback({ ...s, params: { error: 'access_denied', state: s.state } }), 'PROVIDER_ERROR', { providerCode: 'access_denied' });
  });
});

// ---------------------------------------------------------------- UAE PASS
describe('uaepass (local OAuth mock in the UAE PASS format)', () => {
  const REDIRECT = 'https://api.v18.test/v1/connect/uaepass/callback';
  let mock: OAuthMock;
  let env: Env;
  let c: Connector;
  const userinfo = (userType: string, dob?: string) => ({
    sub: 'UAEPASS/7a05992e-3244-49d3-bcbc-7894cef0e53a',
    uuid: '36cc0564-0eef-4a45-9165-1faba825024d',
    userType,
    fullnameEN: 'Ahmed Ali Test',
    firstnameEN: 'Ahmed',
    lastnameEN: 'Test',
    idn: '784199012345678',
    nationalityEN: 'ARE',
    gender: 'Male',
    mobile: '971500000000',
    email: 'test@example.invalid',
    ...(dob !== undefined ? { dateOfBirth: dob } : {}),
  });

  before(async () => {
    mock = await startOAuthMock({
      clientId: 'v18_stage',
      clientSecret: 'test-secret-uaepass-0123456789',
      clientAuth: 'basic',
      authorizePath: '/idshub/authorize',
      tokenPath: '/idshub/token',
      userinfoPath: '/idshub/userinfo',
      requiredAuthorizeParams: ['scope', 'acr_values', 'state'],
      requirePkce: false,
    });
    env = {
      V18_CONNECTOR_UAEPASS_CLIENT_ID: 'v18_stage',
      V18_CONNECTOR_UAEPASS_CLIENT_SECRET: 'test-secret-uaepass-0123456789',
      V18_CONNECTOR_UAEPASS_DOB_ATTRIBUTE: 'dateOfBirth',
      V18_CONNECTOR_UAEPASS_ISSUER: mock.base,
    };
    c = createConnector('uaepass', env, { allowInsecureLocalhost: true });
    mock.tokenExtras = { scope: 'urn:uae:digitalid:profile:general' };
  });
  after(() => mock.close());

  test('stays OFF without DOB_ATTRIBUTE (UAE PASS documents no birth date attribute)', () => {
    assert.equal(c.isConfigured(env), true);
    const { V18_CONNECTOR_UAEPASS_DOB_ATTRIBUTE: _drop, ...noDob } = env;
    assert.equal(createConnector('uaepass', noDob).isConfigured(noDob), false);
  });
  test('sends the documented scope and acr_values', async () => {
    mock.userinfo = userinfo('SOP3', '1990-03-04');
    await login(c, REDIRECT);
    assert.equal(mock.lastAuthorize!.get('scope'), 'urn:uae:digitalid:profile:general');
    assert.equal(mock.lastAuthorize!.get('acr_values'), 'urn:safelayer:tws:policies:authentication:level:low');
  });
  test('over 18 (SOP3): only over18 and uuid come back', async () => {
    mock.userinfo = userinfo('SOP3', '1990-03-04');
    assertOnlyAgeAndSubject(await c.handleCallback(await login(c, REDIRECT)), { over18: true, subject: '36cc0564-0eef-4a45-9165-1faba825024d' });
  });
  test('day-first dates are read too (dd/mm/yyyy)', async () => {
    mock.userinfo = userinfo('SOP2', '04/03/1990');
    assert.equal((await c.handleCallback(await login(c, REDIRECT))).over18, true);
  });
  test('under 18: over18 false', async () => {
    mock.userinfo = userinfo('SOP3', minor.iso);
    assert.equal((await c.handleCallback(await login(c, REDIRECT))).over18, false);
  });
  test('missing birth date: MISSING_BIRTHDATE, no personal data in the error', async () => {
    mock.userinfo = userinfo('SOP3');
    await assertConnectorError(c.handleCallback(await login(c, REDIRECT)), 'MISSING_BIRTHDATE', { mustNotContain: ['Ahmed', '784199012345678'] });
  });
  test('unverified account (SOP1): refused', async () => {
    mock.userinfo = userinfo('SOP1', '1990-03-04');
    await assertConnectorError(c.handleCallback(await login(c, REDIRECT)), 'MISSING_BIRTHDATE');
  });
  test('replayed code: invalid_grant', async () => {
    mock.userinfo = userinfo('SOP3', '1990-03-04');
    const cb = await login(c, REDIRECT);
    await c.handleCallback(cb);
    await assertConnectorError(c.handleCallback(cb), 'INVALID_RESPONSE', { providerCode: 'invalid_grant' });
  });
  test('bad state: STATE_MISMATCH', async () => {
    const cb = await login(c, REDIRECT);
    await assertConnectorError(c.handleCallback({ ...cb, params: { ...cb.params, state: randomToken() } }), 'STATE_MISMATCH');
  });
  test('wrong client secret (Basic auth): invalid_client', async () => {
    const bad = createConnector('uaepass', { ...env, V18_CONNECTOR_UAEPASS_CLIENT_SECRET: 'nope' }, { allowInsecureLocalhost: true });
    await assertConnectorError(bad.handleCallback(await login(bad, REDIRECT)), 'INVALID_RESPONSE', { providerCode: 'invalid_client' });
  });
});
