/**
 * Singpass (Myinfo v5, FAPI 2.0) against a local oidc-provider mock set up like Singpass:
 * PAR required, DPoP-bound tokens, private_key_jwt (ES256), ID token encrypted
 * (ECDH-ES+A256KW / A256CBC-HS512), userinfo signed then encrypted, data under `person_info`.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { birthDateForAge, jwkPair } from './helpers/keys.js';
import { oidcBattery, login } from './helpers/oidc-battery.js';

const REDIRECT = 'https://api.v18.test/v1/connect/singpass/callback';
const keys = (async () => ({ sig: await jwkPair('ES256', 'v18-sig-1', 'sig'), enc: await jwkPair('ECDH-ES+A256KW', 'v18-enc-1', 'enc') }))();

const myinfoDob = (value: string) => ({ lastupdated: '2024-03-01', source: '1', classification: 'C', value });
const minor = birthDateForAge(17);

oidcBattery({
  id: 'singpass',
  redirectUri: REDIRECT,
  profile: async () => {
    const k = await keys;
    return {
      signingAlg: 'ES256',
      scopes: ['openid', 'dob'],
      claims: { openid: ['sub'], dob: ['person_info'] },
      client: {
        client_id: 'v18-singpass-test-client-0000000',
        redirect_uris: [REDIRECT],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [k.sig.publicJwk, k.enc.publicJwk] },
        id_token_signed_response_alg: 'ES256',
        id_token_encrypted_response_alg: 'ECDH-ES+A256KW',
        id_token_encrypted_response_enc: 'A256CBC-HS512',
        userinfo_signed_response_alg: 'ES256',
        userinfo_encrypted_response_alg: 'ECDH-ES+A256KW',
        userinfo_encrypted_response_enc: 'A256CBC-HS512',
        require_pushed_authorization_requests: true,
        dpop_bound_access_tokens: true,
      },
    };
  },
  env: async (mock) => {
    const k = await keys;
    return {
      V18_CONNECTOR_SINGPASS_CLIENT_ID: 'v18-singpass-test-client-0000000',
      V18_CONNECTOR_SINGPASS_SIGNING_KEY: JSON.stringify(k.sig.privateJwk),
      V18_CONNECTOR_SINGPASS_ENCRYPTION_KEY: JSON.stringify(k.enc.privateJwk),
      V18_CONNECTOR_SINGPASS_ISSUER: mock.discoveryUrl,
    };
  },
  adult: { sub: '7c9c72ec-5be2-495a-a78e-61e809a2a236', claims: { person_info: { dob: myinfoDob('1988-10-06') } } },
  adultSubject: '7c9c72ec-5be2-495a-a78e-61e809a2a236',
  minor: { sub: 'b1f1d2a4-0000-4000-8000-000000000017', claims: { person_info: { dob: myinfoDob(minor.iso) } } },
  missing: {
    sub: 'c2a0f3b5-0000-4000-8000-0000000000aa',
    claims: { person_info: { dob: { lastupdated: '2024-03-01', source: '1', classification: 'C', unavailable: true } } },
  },
  personal: ['1988-10-06', minor.iso],
  extra: ({ mock, connector }) => {
    test('singpass: uses PAR (the browser URL carries only client_id and request_uri)', async () => {
      const { authUrl } = await connector().buildAuthUrl({
        state: 'state-'.padEnd(40, 'x'),
        nonce: 'nonce-'.padEnd(40, 'y'),
        codeVerifier: 'v'.repeat(50),
        redirectUri: REDIRECT,
      });
      const q = new URL(authUrl).searchParams;
      assert.deepEqual([...q.keys()].sort(), ['client_id', 'request_uri']);
    });
    test('singpass: the session holds a DPoP key, and the login fails without it', async () => {
      const cb = await login(connector(), mock(), { sub: '7c9c72ec-5be2-495a-a78e-61e809a2a236', claims: { person_info: { dob: myinfoDob('1988-10-06') } } }, REDIRECT);
      assert.ok(cb.session && JSON.parse(cb.session).dpop.privateJwk.d);
      await assert.rejects(connector().handleCallback({ ...cb, session: undefined }), { code: 'INVALID_RESPONSE' });
    });
    test('singpass: publishes its public signing and encryption keys, never the private parts', async () => {
      const jwks = await connector().jwks!();
      assert.equal(jwks.keys.length, 2);
      for (const k of jwks.keys) assert.equal(k.d, undefined);
      assert.deepEqual(jwks.keys.map((k) => k.use).sort(), ['enc', 'sig']);
    });
  },
});
