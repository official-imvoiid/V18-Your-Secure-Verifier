/**
 * Swedish BankID (RP API v6.0) against a local mutual-TLS mock of /auth and /collect.
 */
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { bankIdQrData } from '../providers/bankid-se.js';
import { createConnector } from '../registry.js';
import type { Connector, Env } from '../types.js';
import { newStart, randomToken } from './helpers/browser.js';
import { startBankIdMock, type BankIdMock } from './helpers/bankid-mock.js';
import { assertConnectorError, assertOnlyAgeAndSubject } from './helpers/checks.js';
import { birthDateForAge, pad, testPki } from './helpers/keys.js';

const REDIRECT = 'https://api.v18.test/v1/connect/bankid_se/callback';
const minor = birthDateForAge(17);
const minorPnr = `${minor.y}${pad(minor.m)}${pad(minor.d)}2384`;

describe('bankid_se (local mutual-TLS mock of the RP API v6.0)', () => {
  let pki: Awaited<ReturnType<typeof testPki>>;
  let mock: BankIdMock;
  let env: Env;
  let c: Connector;
  const fast = { bankidPoll: { intervalMs: 5, attempts: 5 } };

  before(async () => {
    pki = await testPki();
    mock = await startBankIdMock(pki);
    env = {
      V18_CONNECTOR_BANKID_SE_API_URL: mock.apiUrl,
      V18_CONNECTOR_BANKID_SE_CA: pki.ca.certPem,
      V18_CONNECTOR_BANKID_SE_CERT: pki.client.certPem,
      V18_CONNECTOR_BANKID_SE_KEY: pki.client.keyPem,
    };
    c = createConnector('bankid_se', env, fast);
  });
  after(() => mock.close());

  async function start() {
    const s = { ...newStart(REDIRECT), endUserIp: '192.0.2.10' };
    const { authUrl, session } = await c.buildAuthUrl(s);
    // The BankID app opens the returnUrl when done; it carries our state.
    const returnUrl = new URL(String(mock.lastAuthBody!.returnUrl));
    return { ...s, authUrl, session, params: Object.fromEntries(returnUrl.searchParams) };
  }

  test('is configured only with a CA plus a client certificate', () => {
    assert.equal(c.isConfigured(env), true);
    assert.equal(c.isConfigured({ V18_CONNECTOR_BANKID_SE_CA: 'x' }), false);
  });

  test('start: calls /auth with endUserIp and a returnUrl carrying state; authUrl is the BankID app link', async () => {
    const s = await start();
    assert.equal(mock.lastAuthBody!.endUserIp, '192.0.2.10');
    assert.equal(s.params.state, s.state);
    assert.match(s.authUrl, /^https:\/\/app\.bankid\.com\/\?autostarttoken=[0-9a-f-]{36}$/);
  });

  test('over 18: pending, pending, complete -> over18 true; only over18 and subject (name, signature, OCSP dropped)', async () => {
    mock.script = {
      steps: [
        { status: 'pending', hintCode: 'outstandingTransaction' },
        { status: 'pending', hintCode: 'userSign' },
        { status: 'complete', personalNumber: '199001012384' },
      ],
    };
    const r = await c.handleCallback(await start());
    assertOnlyAgeAndSubject(r, { over18: true, subject: '199001012384' });
    assert.ok(!JSON.stringify(r).includes('Alex'));
  });

  test('under 18: over18 false', async () => {
    mock.script = { steps: [{ status: 'complete', personalNumber: minorPnr }] };
    assert.equal((await c.handleCallback(await start())).over18, false);
  });

  test('coordination number (day + 60) is read correctly', async () => {
    mock.script = { steps: [{ status: 'complete', personalNumber: '199001612384' }] };
    assert.equal((await c.handleCallback(await start())).over18, true);
  });

  test('missing personal number: MISSING_BIRTHDATE', async () => {
    mock.script = { steps: [{ status: 'complete', personalNumber: '' }] };
    await assertConnectorError(c.handleCallback(await start()), 'INVALID_RESPONSE');
    mock.script = { steps: [{ status: 'complete', personalNumber: 'not-a-number' }] };
    await assertConnectorError(c.handleCallback(await start()), 'MISSING_BIRTHDATE', { mustNotContain: ['Alex Johnson'] });
  });

  test('user cancelled in the app: PROVIDER_ERROR userCancel', async () => {
    mock.script = { steps: [{ status: 'failed', hintCode: 'userCancel' }] };
    await assertConnectorError(c.handleCallback(await start()), 'PROVIDER_ERROR', { providerCode: 'userCancel' });
  });

  test('still pending after all polls: PENDING (the server may try again)', async () => {
    mock.script = { steps: [{ status: 'pending', hintCode: 'userSign' }] };
    await assertConnectorError(c.handleCallback(await start()), 'PENDING');
  });

  test('replayed callback: the finished order is gone, so the second use fails', async () => {
    mock.script = { steps: [{ status: 'complete', personalNumber: '199001012384' }] };
    const cb = await start();
    await c.handleCallback(cb);
    await assertConnectorError(c.handleCallback(cb), 'INVALID_RESPONSE', { providerCode: 'invalidParameters' });
  });

  test('bad state: STATE_MISMATCH before any call to BankID', async () => {
    const cb = await start();
    await assertConnectorError(c.handleCallback({ ...cb, params: { state: randomToken() } }), 'STATE_MISMATCH');
  });

  test('missing endUserIp: BAD_REQUEST', async () => {
    await assertConnectorError(c.buildAuthUrl(newStart(REDIRECT)), 'BAD_REQUEST');
  });

  test('server certificate not from the configured CA (wrong "signature"): refused', async () => {
    const otherPki = await testPki();
    const wrongCa = createConnector('bankid_se', { ...env, V18_CONNECTOR_BANKID_SE_CA: otherPki.ca.certPem }, fast);
    await assertConnectorError(wrongCa.buildAuthUrl({ ...newStart(REDIRECT), endUserIp: '192.0.2.10' }), 'INVALID_RESPONSE', { providerCode: 'network' });
  });

  test('client certificate not trusted by BankID: refused', async () => {
    const otherPki = await testPki();
    const wrongClient = createConnector('bankid_se', { ...env, V18_CONNECTOR_BANKID_SE_CERT: otherPki.client.certPem, V18_CONNECTOR_BANKID_SE_KEY: otherPki.client.keyPem }, fast);
    await assertConnectorError(wrongClient.buildAuthUrl({ ...newStart(REDIRECT), endUserIp: '192.0.2.10' }), 'INVALID_RESPONSE');
  });
});

test('bankid_se: animated QR data matches the example in BankID’s QR code guide', () => {
  const session = JSON.stringify({
    orderRef: 'x',
    qrStartToken: '67df3917-fa0d-44e5-b327-edcc928297f8',
    qrStartSecret: 'd28db9a7-4cde-429e-a983-359be676944c',
    startedAt: 1_000_000,
  });
  assert.equal(bankIdQrData(session, 1_000_000), 'bankid.67df3917-fa0d-44e5-b327-edcc928297f8.0.dc69358e712458a66a7525beef148ae8526b1c71610eff2c16cdffb4cdac9bf8');
  assert.equal(bankIdQrData(session, 1_001_000), 'bankid.67df3917-fa0d-44e5-b327-edcc928297f8.1.949d559bf23403952a94d103e67743126381eda00f0b3cbddbf7c96b1adcbce2');
  assert.equal(bankIdQrData(session, 1_002_500), 'bankid.67df3917-fa0d-44e5-b327-edcc928297f8.2.a9e5ec59cb4eee4ef4117150abc58fad7a85439a6a96ccbecc3668b41795b3f3');
});
