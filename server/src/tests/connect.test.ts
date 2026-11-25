/**
 * Government and bank logins (4d.4).
 *
 * Part 1 runs the REAL @v18/connectors FranceConnect connector against the
 * local oidc-provider mock from connectors/ (set up like FranceConnect:
 * eidas1, ES256 ID token, signed userinfo, the pivot identity with names and
 * birth date). The server must keep NOTHING of it except the card.
 *
 * Part 2 uses a small in-process connector to cover the edge cases.
 */
import 'reflect-metadata';
import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { ConnectorLike, RegistryLike } from '../connect/service.js';
import { NullifierStore } from '../nullifier/store.js';
import { api, dumpTables, makeTicket, newChallenge, ss, startServer, TestDevice, TestServer } from './helpers.js';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const mocks = require('@v18/connectors/dist/tests/helpers/oidc-mock.js') as { startOidcMock(p: unknown): Promise<any> };
// eslint-disable-next-line @typescript-eslint/no-require-imports
const browser = require('@v18/connectors/dist/tests/helpers/browser.js') as {
  followToCallback(authUrl: string, redirectUri: string): Promise<Record<string, string>>;
};

const PUBLIC = 'https://api.v18.test';
const REDIRECT = `${PUBLIC}/v1/connect/franceconnect/callback`;
const SECRET = 'test-secret-franceconnect-0123456789abcdef0123';
const sub = (c: string) => c.repeat(64).slice(0, 64) + 'v1';
const pivot = (birthdate: string) => ({
  given_name: 'Angela Claire Louise',
  family_name: 'DUBOIS',
  gender: 'female',
  birthplace: '75107',
  birthcountry: '99100',
  birthdate,
});

async function startLogin(srv: TestServer, id: string, dev?: TestDevice) {
  const d = dev ?? (await TestDevice.es256());
  const challenge = await newChallenge(srv.url);
  const r = await api(srv.url, 'POST', `/v1/connect/${id}/start`, {
    challenge,
    devicePublicKey: d.jwkWithAlg,
    deviceSignature: d.sign(ss.cardIssue(challenge, d.thumbprint)),
  });
  return { r, dev: d };
}

async function callback(srv: TestServer, id: string, params: Record<string, string>) {
  const res = await fetch(`${srv.url}/v1/connect/${id}/callback?${new URLSearchParams(params)}`, { redirect: 'manual' });
  const loc = res.headers.get('location') ?? '';
  return { status: res.status, location: loc, q: Object.fromEntries(new URL(loc.replace('v18://', 'v18://x/')).searchParams) };
}

describe('FranceConnect through the real @v18/connectors package and a local oidc-provider mock', () => {
  let mock: any;
  let srv: TestServer;
  before(async () => {
    mock = await mocks.startOidcMock({
      signingAlg: 'ES256',
      scopes: ['openid', 'birthdate', 'profile'],
      claims: { openid: ['sub'], birthdate: ['birthdate'], profile: ['given_name', 'family_name', 'gender', 'birthdate'] },
      client: {
        client_id: 'v18-franceconnect',
        client_secret: SECRET,
        token_endpoint_auth_method: 'client_secret_post',
        redirect_uris: [REDIRECT],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        id_token_signed_response_alg: 'ES256',
        userinfo_signed_response_alg: 'ES256',
      },
    });
    const env = {
      V18_CONNECTOR_FRANCECONNECT_CLIENT_ID: 'v18-franceconnect',
      V18_CONNECTOR_FRANCECONNECT_CLIENT_SECRET: SECRET,
      V18_CONNECTOR_FRANCECONNECT_ISSUER: mock.discoveryUrl,
    };
    // The real registry from @v18/connectors. allowInsecureLocalhost is the package's TEST-only
    // switch for plain http to the local mock; the server itself never sets it.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { createRegistry } = require('@v18/connectors') as { createRegistry(env: unknown, o: unknown): RegistryLike };
    srv = await startServer({ env, connectorRegistry: createRegistry(env, { allowInsecureLocalhost: true }), config: { publicUrl: PUBLIC } });
  });
  after(async () => {
    await srv.close();
    await mock.close();
  });

  it('is listed in health only because its credentials are set', async () => {
    const h = (await api(srv.url, 'GET', '/v1/health')).body;
    assert.deepEqual(h.connectors, ['franceconnect']);
    assert.equal(h.methods['connector:franceconnect'], 'ready');
  });

  it('an adult logs in: card bound to the device key, birth date and names never stored', async () => {
    mock.account = { sub: sub('b6048e95bb134ec5'), claims: pivot('1962-08-24') };
    const { r, dev } = await startLogin(srv, 'franceconnect');
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.match(r.body.state, /^[A-Za-z0-9_-]{43}$/);
    const authUrl = new URL(r.body.authUrl);
    assert.equal(authUrl.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(authUrl.searchParams.get('state'), r.body.state);

    const params = await browser.followToCallback(r.body.authUrl, REDIRECT);
    const cb = await callback(srv, 'franceconnect', params);
    assert.equal(cb.status, 302);
    assert.equal(cb.q.status, 'ok', cb.location);
    assert.equal(cb.q.state, r.body.state);

    const poll = await api(srv.url, 'GET', `/v1/connect/session/${r.body.state}`);
    assert.equal(poll.body.status, 'ok');
    assert.equal(poll.body.card.cardId, cb.q.cardId);
    assert.equal(poll.body.card.method, 'connector:franceconnect');
    assert.equal(poll.body.card.assuranceLevel, 'substantial');
    assert.equal((await api(srv.url, 'GET', `/v1/connect/session/${r.body.state}`)).body.card, undefined, 'card returned once');
    assert.ok(await makeTicket(srv, cb.q.cardId, dev, { origin: 'https://fr.example', challenge: 'c'.repeat(24) }));

    const dump = JSON.stringify(await dumpTables(srv.services.db));
    for (const secret of ['1962-08-24', 'Angela', 'DUBOIS', '75107', sub('b6048e95bb134ec5')]) {
      assert.ok(!dump.includes(secret), `the database holds "${secret}"`);
    }
    // The nullifier is HMAC-SHA256(V18_NULLIFIER_SECRET, id|subject), hashed again for storage.
    const hmac = crypto.createHmac('sha256', srv.services.config.nullifierSecret!).update(`franceconnect|${sub('b6048e95bb134ec5')}`).digest('hex');
    assert.equal(await srv.services.nullifiers.has(NullifierStore.hashFor('connector:franceconnect', hmac)), true);
  });

  it('a 17-year-old gets status under_age and no card', async () => {
    const y = new Date().getUTCFullYear() - 17;
    mock.account = { sub: sub('c0ffee'), claims: pivot(`${y}-01-01`) };
    const { r } = await startLogin(srv, 'franceconnect');
    const cb = await callback(srv, 'franceconnect', await browser.followToCallback(r.body.authUrl, REDIRECT));
    assert.equal(cb.q.status, 'under_age');
    assert.equal((await api(srv.url, 'GET', `/v1/connect/session/${r.body.state}`)).body.status, 'under_age');
  });
});

// ---- Part 2: edge cases with an in-process connector ---------------------------------

interface Script {
  over18?: boolean;
  subject?: string;
  fail?: string;
  pendingOnce?: boolean;
}

function scripted(id: string, script: Script): ConnectorLike {
  let pending = script.pendingOnce ?? false;
  return {
    id,
    countries: ['SE'],
    assurance: 'high',
    label: id,
    callbackMethod: 'GET',
    async buildAuthUrl(p) {
      return { authUrl: `https://login.example/authorize?state=${p.state}`, session: 'opaque-connector-data' };
    },
    async handleCallback(p) {
      assert.equal(p.session, 'opaque-connector-data');
      assert.equal(p.params.state, p.state);
      if (pending) {
        pending = false;
        throw Object.assign(new Error('pending'), { code: 'PENDING' });
      }
      if (script.fail) throw Object.assign(new Error('x'), { code: script.fail });
      return { over18: script.over18 ?? true, subject: script.subject ?? 'subject-1' };
    },
  };
}

describe('Login connector edge cases', () => {
  const script: Script = {};
  const registry: RegistryLike = {
    list: () => [scripted('bankid_se', script)],
    get: (id) => (id === 'bankid_se' ? scripted('bankid_se', script) : undefined),
  };
  let srv: TestServer;
  before(async () => {
    srv = await startServer({ connectorRegistry: registry });
  });
  after(async () => srv.close());

  const run = async () => {
    const { r } = await startLogin(srv, 'bankid_se');
    return { state: r.body.state as string, cb: await callback(srv, 'bankid_se', { state: r.body.state, code: 'abc' }) };
  };

  it('one person (same subject) gets at most 3 cards; a different subject is a different person', async () => {
    Object.assign(script, { over18: true, subject: 'person-A', fail: undefined });
    for (let i = 0; i < 3; i++) assert.equal((await run()).cb.q.status, 'ok');
    const fourth = await run();
    assert.equal(fourth.cb.q.status, 'error');
    assert.equal(fourth.cb.q.code, 'NULLIFIER_OVERUSED');
    script.subject = 'person-B';
    assert.equal((await run()).cb.q.status, 'ok');
  });

  it('a provider error, an unknown or reused state, and an expired login all end in an error link', async () => {
    Object.assign(script, { fail: 'PROVIDER_ERROR' });
    const e = await run();
    assert.deepEqual([e.cb.q.status, e.cb.q.code], ['error', 'PROVIDER_ERROR']);
    assert.equal((await api(srv.url, 'GET', `/v1/connect/session/${e.state}`)).body.status, 'error');
    script.fail = undefined;
    const bad = await callback(srv, 'bankid_se', { state: 'A'.repeat(43), code: 'x' });
    assert.equal(bad.q.code, 'STATE_MISMATCH');
    const ok = await run();
    const again = await callback(srv, 'bankid_se', { state: ok.state, code: 'abc' });
    assert.equal(again.q.code, 'ALREADY_USED');
    const { r } = await startLogin(srv, 'bankid_se');
    srv.clock.advance(11 * 60_000);
    assert.equal((await callback(srv, 'bankid_se', { state: r.body.state, code: 'x' })).q.code, 'EXPIRED');
  });

  it('BankID-style PENDING: the first callback says pending, the next one finishes', async () => {
    const reg: RegistryLike = (() => {
      const c = scripted('bankid_se', { pendingOnce: true, subject: 'pending-person' });
      return { list: () => [c], get: () => c };
    })();
    const s = await startServer({ connectorRegistry: reg });
    const { r } = await startLogin(s, 'bankid_se');
    assert.equal((await callback(s, 'bankid_se', { state: r.body.state })).q.status, 'pending');
    assert.equal((await api(s.url, 'GET', `/v1/connect/session/${r.body.state}`)).body.status, 'waiting');
    assert.equal((await callback(s, 'bankid_se', { state: r.body.state })).q.status, 'ok');
    await s.close();
  });

  it('start checks the challenge and the device signature; unconfigured logins are 404', async () => {
    const d = await TestDevice.es256();
    const c = await newChallenge(srv.url);
    const bad = await api(srv.url, 'POST', '/v1/connect/bankid_se/start', {
      challenge: c,
      devicePublicKey: d.jwkWithAlg,
      deviceSignature: d.sign('something else'),
    });
    assert.equal(bad.status, 401);
    assert.equal((await api(srv.url, 'POST', '/v1/connect/singpass/start', {})).body.code, 'CONNECTOR_NOT_ENABLED');
    assert.equal((await api(srv.url, 'GET', '/v1/connect/session/nope')).status, 404);
  });

  it('production without V18_NULLIFIER_SECRET refuses to start when a connector is configured', async () => {
    await assert.rejects(
      startServer({ connectorRegistry: registry, config: { devMode: false, nullifierSecret: null, aadhaarNullifierSeed: '1' } }),
      /V18_NULLIFIER_SECRET/
    );
  });
});

describe('Routes the login providers and apps fetch (jwks, SAML metadata, identity providers, BankID QR)', () => {
  const pub = { kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', kid: 'v18-singpass-sig' };
  let leakPrivate = false;
  const make = (id: string, extra: Partial<ConnectorLike>): ConnectorLike => ({ ...scripted(id, {}), ...extra });
  const connectors: Record<string, ConnectorLike> = {
    singpass: make('singpass', { jwks: async () => ({ keys: [leakPrivate ? { ...pub, d: 'secret' } : pub] }) }),
    spid: make('spid', {
      callbackMethod: 'POST',
      metadata: async (acs) => `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:AssertionConsumerService Location="${acs}"/></md:EntityDescriptor>`,
      identityProviders: () => [{ entityId: 'https://idp.example/spid', name: 'Example IdP' }],
    }),
    bankid_se: make('bankid_se', {
      buildAuthUrl: async () => ({
        authUrl: 'https://app.bankid.com/?autostarttoken=x',
        session: JSON.stringify({ orderRef: 'o1', startedAt: Date.UTC(2026, 10, 9, 12, 0, 0), qrStartToken: '67df3917-fa0d-44e5-b327-edcc928297f8', qrStartSecret: 'd28db9a7-4cde-429e-a983-359be676944c' }),
      }),
      handleCallback: async () => ({ over18: true, subject: 'bankid-person' }),
    }),
    freja: make('freja', {}),
  };
  const reg: RegistryLike = { list: () => Object.values(connectors), get: (id) => connectors[id] };
  let srv: TestServer;
  before(async () => {
    srv = await startServer({ connectorRegistry: reg, config: { publicUrl: 'https://api.v18.test' } });
  });
  after(async () => srv.close());

  it('serves a connector JWKS with public keys only, cached; refuses to publish a private part', async () => {
    const r = await api(srv.url, 'GET', '/v1/connect/singpass/jwks');
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { keys: [pub] });
    assert.equal(r.headers.get('cache-control'), 'public, max-age=3600');
    leakPrivate = true;
    assert.equal((await api(srv.url, 'GET', '/v1/connect/singpass/jwks')).status, 500);
    leakPrivate = false;
    assert.equal((await api(srv.url, 'GET', '/v1/connect/freja/jwks')).status, 404);
    assert.equal((await api(srv.url, 'GET', '/v1/connect/itsme/jwks')).body.code, 'CONNECTOR_NOT_ENABLED');
  });

  it('serves SAML metadata whose ACS is the POST callback, and the SPID identity provider list', async () => {
    const res = await fetch(`${srv.url}/v1/connect/spid/metadata`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') ?? '', /application\/samlmetadata\+xml/);
    assert.match(await res.text(), /Location="https:\/\/api\.v18\.test\/v1\/connect\/spid\/callback"/);
    const idps = await api(srv.url, 'GET', '/v1/connect/spid/identity-providers');
    assert.deepEqual(idps.body, { identityProviders: [{ entityId: 'https://idp.example/spid', name: 'Example IdP' }] });
    assert.equal((await api(srv.url, 'GET', '/v1/connect/singpass/metadata')).status, 404);
  });

  it('BankID on a PC: the animated QR text comes from the server-kept session, changes each second, and stops after the login', async () => {
    const { r } = await startLogin(srv, 'bankid_se');
    assert.equal(r.status, 201);
    assert.equal(JSON.stringify(r.body).includes('qrStartSecret'), false, 'the secret never goes to the app');
    srv.clock.advance(3000);
    const q = await api(srv.url, 'GET', `/v1/connect/session/${r.body.state}/qr`);
    assert.equal(q.status, 200, JSON.stringify(q.body));
    const code = crypto.createHmac('sha256', 'd28db9a7-4cde-429e-a983-359be676944c').update('3').digest('hex');
    assert.equal(q.body.qrData, `bankid.67df3917-fa0d-44e5-b327-edcc928297f8.3.${code}`);
    assert.equal(q.body.refreshMs, 1000);
    assert.equal((await callback(srv, 'bankid_se', { state: r.body.state })).q.status, 'ok');
    assert.equal((await api(srv.url, 'GET', `/v1/connect/session/${r.body.state}/qr`)).status, 404);
    const other = await startLogin(srv, 'freja');
    assert.equal((await api(srv.url, 'GET', `/v1/connect/session/${other.r.body.state}/qr`)).status, 404);
  });
});
