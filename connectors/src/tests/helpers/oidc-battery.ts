/**
 * TEST ONLY: the standard set of checks every OIDC connector must pass against its mock:
 * over 18, under 18, missing birth date, bad signature, bad state, replayed code,
 * cancelled login, wrong nonce, and "only over18 and subject come back".
 */
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { createConnector } from '../../registry.js';
import type { Connector, ConnectorId, Env } from '../../types.js';
import { followToCallback, newStart, randomToken } from './browser.js';
import { assertConnectorError, assertOnlyAgeAndSubject } from './checks.js';
import { startOidcMock, type MockAccount, type OidcMock, type OidcMockProfile } from './oidc-mock.js';

export interface OidcBatteryCase {
  id: ConnectorId;
  profile: () => Promise<OidcMockProfile>;
  env: (mock: OidcMock) => Promise<Env> | Env;
  redirectUri: string;
  adult: MockAccount;
  /** The subject the connector must return for `adult`. */
  adultSubject: string;
  minor: MockAccount;
  /** A person whose record has no birth date or age answer. */
  missing: MockAccount;
  /** Values that must never show up in a result or an error (names, birth dates, ID numbers). */
  personal: string[];
  /** Extra provider-specific tests, given a running mock and connector. */
  extra?: (ctx: { mock: () => OidcMock; connector: () => Connector; env: () => Env }) => void;
}

export async function login(connector: Connector, mock: OidcMock, account: MockAccount, redirectUri: string) {
  mock.account = account;
  const start = newStart(redirectUri);
  const { authUrl, session } = await connector.buildAuthUrl(start);
  const params = await followToCallback(authUrl, redirectUri);
  return { ...start, params, session };
}

export function oidcBattery(c: OidcBatteryCase) {
  describe(`${c.id} (local oidc-provider mock)`, () => {
    let mock: OidcMock;
    let env: Env;
    let connector: Connector;
    before(async () => {
      mock = await startOidcMock(await c.profile());
      env = await c.env(mock);
      connector = createConnector(c.id, env, { allowInsecureLocalhost: true });
    });
    after(async () => {
      await mock.close();
    });

    test('is configured only when its settings are present', () => {
      assert.equal(connector.isConfigured(env), true);
      assert.equal(connector.isConfigured({}), false);
    });

    test('over 18: returns over18 true and ONLY over18 and subject', async () => {
      const cb = await login(connector, mock, c.adult, c.redirectUri);
      const result = await connector.handleCallback(cb);
      assertOnlyAgeAndSubject(result, { over18: true, subject: c.adultSubject });
      const text = JSON.stringify(result);
      for (const p of c.personal) assert.ok(!text.includes(p) || p === c.adultSubject, 'result must not hold personal data');
    });

    test('under 18: returns over18 false', async () => {
      const cb = await login(connector, mock, c.minor, c.redirectUri);
      const result = await connector.handleCallback(cb);
      assert.equal(result.over18, false);
      assert.deepEqual(Object.keys(result).sort(), ['over18', 'subject']);
    });

    test('missing birth date: MISSING_BIRTHDATE', async () => {
      const cb = await login(connector, mock, c.missing, c.redirectUri);
      await assertConnectorError(connector.handleCallback(cb), 'MISSING_BIRTHDATE', { mustNotContain: c.personal });
    });

    test('state mismatch: STATE_MISMATCH, nothing exchanged', async () => {
      const cb = await login(connector, mock, c.adult, c.redirectUri);
      await assertConnectorError(connector.handleCallback({ ...cb, state: randomToken() }), 'STATE_MISMATCH');
      await assertConnectorError(connector.handleCallback({ ...cb, params: { ...cb.params, state: randomToken() } }), 'STATE_MISMATCH');
      // The real login still works afterwards: the code was never sent to the provider.
      const ok = await connector.handleCallback(cb);
      assert.equal(ok.over18, true);
    });

    test('replayed code: the second use is refused', async () => {
      const cb = await login(connector, mock, c.adult, c.redirectUri);
      const first = await connector.handleCallback(cb);
      assert.equal(first.over18, true);
      await assertConnectorError(connector.handleCallback(cb), 'INVALID_RESPONSE', { providerCode: 'invalid_grant', mustNotContain: c.personal });
    });

    test('cancelled at the provider: PROVIDER_ERROR with only the error code', async () => {
      const start = newStart(c.redirectUri);
      const err = await assertConnectorError(
        connector.handleCallback({ ...start, params: { error: 'access_denied', error_description: 'User Jane Doe cancelled', state: start.state } }),
        'PROVIDER_ERROR',
        { providerCode: 'access_denied', mustNotContain: ['Jane Doe'] },
      );
      assert.equal(err.connector, c.id);
    });

    test('wrong nonce (ID token not for this login): INVALID_RESPONSE, no claims in the error', async () => {
      const cb = await login(connector, mock, c.adult, c.redirectUri);
      await assertConnectorError(connector.handleCallback({ ...cb, nonce: randomToken() }), 'INVALID_RESPONSE', { mustNotContain: c.personal });
    });

    test('bad signature (provider keys do not match): INVALID_RESPONSE', async () => {
      // A fresh connector, so no keys are cached from earlier tests.
      const fresh = createConnector(c.id, env, { allowInsecureLocalhost: true });
      const cb = await login(fresh, mock, c.adult, c.redirectUri);
      mock.tamperJwks = true;
      try {
        await assertConnectorError(fresh.handleCallback(cb), 'INVALID_RESPONSE', { mustNotContain: c.personal });
      } finally {
        mock.tamperJwks = false;
      }
    });

    test('plain http is refused unless the test option allows it (localhost only)', async () => {
      const strict = createConnector(c.id, env);
      await assertConnectorError(strict.buildAuthUrl(newStart(c.redirectUri)), 'INVALID_RESPONSE');
    });

    c.extra?.({ mock: () => mock, connector: () => connector, env: () => env });
  });
}
