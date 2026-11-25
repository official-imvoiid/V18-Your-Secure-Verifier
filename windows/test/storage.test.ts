import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { sanitizeState, serializeState } from '../src/shared/storage.js';

const opts = { debug: true, defaultServerUrl: 'http://localhost:8080/v1' };
const goodCard = { cardId: 'card_AAAAAAAAAAAAAAAAAAAAAA', method: 'test_dev', validUntil: '2027-01-01T00:00:00.000Z', keyAlias: 'hello:v18-card-abcdefghijkl' };

function allKeys(v: unknown, prefix = ''): string[] {
  if (!v || typeof v !== 'object') return [];
  return Object.entries(v).flatMap(([k, x]) => [prefix + k, ...allKeys(x, prefix + k + '.')]);
}

describe('storage rules (PROTOCOL 3.10)', () => {
  it('stores only card ID, method, validUntil, key alias, server URL and settings', () => {
    const json = serializeState(
      {
        version: 1,
        serverUrl: 'http://localhost:8080/v1',
        settings: { firstRunDone: true, sharedPc: false, notify: true, validityMonths: 12 } as never,
        card: goodCard,
      },
      opts,
    );
    assert.deepEqual(allKeys(JSON.parse(json)).sort(), [
      'card',
      'card.cardId',
      'card.keyAlias',
      'card.method',
      'card.validUntil',
      'serverUrl',
      'settings',
      'settings.firstRunDone',
      'settings.notify',
      'settings.sharedPc',
      'version',
    ]);
  });

  it('drops anything extra, even if a bug tries to save it', () => {
    const s = sanitizeState(
      {
        serverUrl: 'http://localhost:8080/v1',
        name: 'Alice',
        birthDate: '1990-01-01',
        visitedSites: ['https://a.test'],
        lastTicket: 'v18-age18.x.y',
        settings: { sharedPc: false, theme: 'dark', history: [1] },
        card: { ...goodCard, assuranceLevel: 'high', nullifier: 'abc', devicePrivateKey: 'secret', deviceKeyPem: '-----BEGIN' },
      },
      opts,
    );
    const text = JSON.stringify(s);
    for (const bad of ['Alice', '1990-01-01', 'a.test', 'v18-age18.x.y', 'theme', 'history', 'assuranceLevel', 'nullifier', 'secret', 'BEGIN']) {
      assert.ok(!text.includes(bad), bad);
    }
    assert.deepEqual(s.card, goodCard);
  });

  it('keeps no card at all in shared-PC mode', () => {
    const s = sanitizeState({ settings: { sharedPc: true, firstRunDone: true }, card: goodCard }, opts);
    assert.equal(s.card, null);
    assert.ok(!serializeState(s, opts).includes('card_'));
  });

  it('refuses malformed card fields instead of storing them', () => {
    for (const bad of [
      { ...goodCard, cardId: 'Alice Smith' },
      { ...goodCard, method: 'Passport 1234' },
      { ...goodCard, validUntil: 'soon' },
      { ...goodCard, keyAlias: 'C:\\keys\\private.pem' },
      { ...goodCard, keyAlias: 'software:v18-card-abcdefghijkl' },
    ]) {
      assert.equal(sanitizeState({ card: bad }, opts).card, null, JSON.stringify(bad));
    }
  });

  it('only keeps an allowed server URL', () => {
    assert.equal(sanitizeState({ serverUrl: 'https://evil.test/v1' }, opts).serverUrl, 'http://localhost:8080/v1');
    assert.equal(sanitizeState({ serverUrl: 'http://localhost:8080' }, opts).serverUrl, 'http://localhost:8080/v1');
    assert.equal(sanitizeState({ serverUrl: 'http://localhost:8080/v1' }, { debug: false, defaultServerUrl: 'https://api.v18.example/v1' }).serverUrl, 'https://api.v18.example/v1');
  });

  it('starts empty from nothing or from garbage', () => {
    for (const raw of [null, undefined, 42, 'x', []]) {
      const s = sanitizeState(raw, opts);
      assert.equal(s.card, null);
      assert.equal(s.settings.firstRunDone, false);
      assert.equal(s.settings.notify, true);
    }
  });
});
