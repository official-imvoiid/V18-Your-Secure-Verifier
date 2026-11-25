/** The 18+ rule, date parsing, the registry, and the "only configured connectors" rule. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { birthDateFromSwedishPersonalNumber, isOver18, parseDayFirstDate, parseIsoDate } from '../age.js';
import { decide } from '../oidc.js';
import { CONNECTOR_IDS, createConnector, createRegistry } from '../registry.js';
import { ConnectorError } from '../types.js';

const at = (iso: string) => new Date(iso);

test('age: 18th birthday counts only once it has started everywhere (UTC-12)', () => {
  const b = { year: 2008, month: 6, day: 15 };
  assert.equal(isOver18(b, at('2026-06-14T23:59:59Z')), false);
  assert.equal(isOver18(b, at('2026-06-15T11:59:59Z')), false, 'still 14 June in UTC-12');
  assert.equal(isOver18(b, at('2026-06-15T12:00:00Z')), true);
});

test('age: born 29 February -> 18 on 1 March in a non-leap year', () => {
  const b = { year: 2008, month: 2, day: 29 };
  assert.equal(isOver18(b, at('2026-02-28T23:00:00Z')), false);
  assert.equal(isOver18(b, at('2026-03-01T12:00:00Z')), true);
});

test('age: partial dates use the latest possible day (cautious)', () => {
  assert.equal(isOver18({ year: 2008 }, at('2026-12-31T11:00:00Z')), false);
  assert.equal(isOver18({ year: 2008 }, at('2026-12-31T12:00:00Z')), true);
  assert.equal(isOver18({ year: 2008, month: 4 }, at('2026-04-30T12:00:00Z')), true);
  assert.equal(isOver18({ year: 2008, month: 4 }, at('2026-04-29T12:00:00Z')), false);
  // February 2008 may be 29 February (leap year), so 18 only from 1 March 2026.
  assert.equal(isOver18({ year: 2008, month: 2 }, at('2026-02-28T12:00:00Z')), false);
  assert.equal(isOver18({ year: 2008, month: 2 }, at('2026-03-01T12:00:00Z')), true);
});

test('dates: ISO, day-first and Swedish personal numbers', () => {
  assert.deepEqual(parseIsoDate('1990-05-17'), { year: 1990, month: 5, day: 17 });
  assert.deepEqual(parseIsoDate('1990-05'), { year: 1990, month: 5 });
  assert.deepEqual(parseIsoDate('1990'), { year: 1990 });
  assert.equal(parseIsoDate('1990-02-30'), undefined);
  assert.equal(parseIsoDate('17/05/1990'), undefined);
  assert.equal(parseIsoDate(19900517), undefined);
  assert.deepEqual(parseDayFirstDate('31121970'), { year: 1970, month: 12, day: 31 });
  assert.deepEqual(parseDayFirstDate('01/02/1990'), { year: 1990, month: 2, day: 1 });
  assert.deepEqual(parseDayFirstDate('01.11.1978'), { year: 1978, month: 11, day: 1 });
  assert.equal(parseDayFirstDate('1990-02-01'), undefined);
  assert.deepEqual(birthDateFromSwedishPersonalNumber('200001012384'), { year: 2000, month: 1, day: 1 });
  assert.deepEqual(birthDateFromSwedishPersonalNumber('200001612384'), { year: 2000, month: 1, day: 1 }, 'coordination number');
  assert.equal(birthDateFromSwedishPersonalNumber('0001012384'), undefined, '10-digit form is not what BankID sends');
});

test('decide: builds a fresh {over18, subject} and nothing else', () => {
  const r = decide('freja', { subject: ' s-1 ', birthDate: { year: 1990, month: 1, day: 1 } }, at('2026-01-01T00:00:00Z'));
  assert.deepEqual(r, { over18: true, subject: 's-1' });
  assert.deepEqual(decide('mitid', { subject: 's', over18: false }, new Date()), { over18: false, subject: 's' });
  assert.throws(() => decide('freja', { birthDate: { year: 1990 } }, new Date()), (e: unknown) => e instanceof ConnectorError && e.code === 'INVALID_RESPONSE');
  assert.throws(() => decide('freja', { subject: 'x' }, new Date()), (e: unknown) => e instanceof ConnectorError && e.code === 'MISSING_BIRTHDATE');
});

test('registry: with no settings, no connector is enabled', () => {
  const r = createRegistry({});
  assert.deepEqual(r.list(), []);
  assert.equal(r.get('singpass'), undefined);
  assert.deepEqual(r.summaries(), []);
});

test('registry: lists only configured connectors, with country lookup and safe summaries', () => {
  const env = {
    V18_CONNECTOR_FRANCECONNECT_CLIENT_ID: 'a',
    V18_CONNECTOR_FRANCECONNECT_CLIENT_SECRET: 'b',
    V18_CONNECTOR_MITID_CLIENT_ID: 'c',
    V18_CONNECTOR_MITID_CLIENT_SECRET: 'd',
    V18_CONNECTOR_ITSME_CLIENT_ID: 'only-half-configured',
  };
  const r = createRegistry(env);
  assert.deepEqual(r.list().map((c) => c.id), ['mitid', 'franceconnect']);
  assert.deepEqual(r.forCountry('dk').map((c) => c.id), ['mitid']);
  assert.deepEqual(r.forCountry('BE'), []);
  assert.deepEqual(r.summaries()[1], { id: 'franceconnect', label: 'FranceConnect', countries: ['FR'], assurance: 'substantial', callbackMethod: 'GET' });
  assert.ok(!JSON.stringify(r.summaries()).includes('"b"'), 'summaries never include secrets');
});

test('registry: all 12 connectors from PROTOCOL.md 4d.4 exist with countries and assurance', () => {
  assert.deepEqual([...CONNECTOR_IDS].sort(), ['bankid_no', 'bankid_se', 'cie', 'digid', 'digilocker', 'franceconnect', 'freja', 'itsme', 'mitid', 'singpass', 'spid', 'uaepass']);
  const countries: Record<string, string[]> = {};
  for (const id of CONNECTOR_IDS) {
    const c = createConnector(id, {});
    assert.equal(c.id, id);
    assert.ok(c.countries.length > 0);
    assert.ok(c.assurance === 'high' || c.assurance === 'substantial');
    assert.equal(c.isConfigured({}), false);
    countries[id] = [...c.countries];
  }
  assert.deepEqual(countries.itsme, ['BE', 'NL', 'LU']);
  assert.deepEqual(countries.singpass, ['SG']);
});

test('errors: ConnectorError serialises to code and fixed text only', () => {
  const e = new ConnectorError('singpass', 'PROVIDER_ERROR', 'The login was cancelled.', 'access_denied');
  assert.deepEqual(JSON.parse(JSON.stringify(e)), {
    name: 'ConnectorError',
    code: 'PROVIDER_ERROR',
    connector: 'singpass',
    providerCode: 'access_denied',
    message: 'The login was cancelled.',
  });
  assert.equal(new ConnectorError('singpass', 'PROVIDER_ERROR', 'x', 'Jane Doe <script>').providerCode, undefined, 'odd provider codes are dropped');
});

test('start parameters are checked before anything is sent', async () => {
  const env = { V18_CONNECTOR_FREJA_CLIENT_ID: 'a', V18_CONNECTOR_FREJA_CLIENT_SECRET: 'b' };
  const c = createConnector('freja', env);
  const ok = { state: 's'.repeat(32), nonce: 'n'.repeat(32), codeVerifier: 'v'.repeat(43), redirectUri: 'https://x.test/cb' };
  await assert.rejects(c.buildAuthUrl({ ...ok, state: 'short' }), { code: 'BAD_REQUEST' });
  await assert.rejects(c.buildAuthUrl({ ...ok, codeVerifier: 'too-short' }), { code: 'BAD_REQUEST' });
  await assert.rejects(c.buildAuthUrl({ ...ok, redirectUri: 'not a url' }), { code: 'BAD_REQUEST' });
});
