// PROTOCOL 4d: the country catalog drives the screens, and login connectors run through the
// system browser and come back through v18://connect (or the session poll).
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { V18Engine, type EngineDeps } from '../src/main/engine.js';
import { HelloKeyProvider } from '../src/main/keys.js';
import type { ViewState } from '../src/main/view.js';
import { mergeCatalogs, parseCatalog, pcMethods } from '../src/shared/catalog.js';
import { parseDeepLink } from '../src/shared/deeplink.js';
import { FakeHelloAddon } from './helpers/fake-hello.js';
import { startMockServer, type MockServer } from './helpers/mock-server.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const realCatalogFile = path.join(here, '..', '..', 'catalog', 'countries.json');

const CATALOG = {
  version: 1,
  countries: [
    {
      code: 'IN',
      name: 'India',
      region: 'asia',
      methods: [
        { method: 'anon_aadhaar', label: 'Aadhaar QR', documents: ['Aadhaar letter'], needs: ['camera'], privacy: 'zero_knowledge', platforms: ['android', 'windows'] },
        { method: 'emrtd_attested', label: 'Passport (chip)', documents: ['Indian e-passport'], docTypes: ['P'], needs: ['nfc'], privacy: 'on_device', platforms: ['android'] },
        { method: 'connector:digilocker', label: 'DigiLocker', documents: ['DigiLocker account'], needs: ['password'], privacy: 'login', platforms: ['android', 'windows'] },
      ],
    },
    {
      code: 'SG',
      name: 'Singapore',
      region: 'asia',
      methods: [
        { method: 'emrtd_attested', label: 'Passport (chip)', documents: [], needs: ['nfc'], privacy: 'on_device', platforms: ['android'] },
        { method: 'connector:singpass', label: 'Singpass (Myinfo)', documents: ['Singpass account'], needs: ['password'], privacy: 'login', platforms: ['android', 'windows'] },
      ],
    },
    {
      code: 'DE',
      name: 'Germany',
      region: 'europe',
      methods: [
        { method: 'emrtd_attested', label: 'Passport or ID card (chip)', documents: ['Reisepass', 'Personalausweis'], needs: ['nfc'], privacy: 'on_device', platforms: ['android'] },
        { method: 'mdoc_wallet', label: 'EU wallet', documents: [], needs: ['wallet'], privacy: 'wallet', platforms: ['web'] },
      ],
    },
    { code: 'XX', name: 'Nowhere', region: 'other', methods: [{ method: 'mdoc_wallet', label: 'Web only', documents: [], needs: [], privacy: 'wallet', platforms: ['web'] }] },
  ],
};

describe('country catalog (PROTOCOL 4d.2)', () => {
  it('sorts each country into "on this PC" and "with your phone", most private first', () => {
    const [india, sg, de, xx] = parseCatalog(CATALOG);
    assert.deepEqual(
      pcMethods(india).map((m) => [m.kind, m.method]),
      [
        ['aadhaar', 'anon_aadhaar'],
        ['phone', 'emrtd_attested'],
        ['connector', 'connector:digilocker'],
      ],
    );
    assert.equal(pcMethods(sg).find((m) => m.kind === 'connector')?.connectorId, 'singpass');
    // Browser-only methods are not shown in the PC app at all.
    assert.deepEqual(pcMethods(de).map((m) => m.kind), ['phone']);
    assert.equal(pcMethods(xx).length, 0);
  });

  it('keeps a method listed twice with different documents (passport and ID card)', () => {
    const [fr] = parseCatalog({
      countries: [
        {
          code: 'FR',
          name: 'France',
          region: 'europe',
          methods: [
            { method: 'emrtd_attested', label: 'Passport (chip)', privacy: 'on_device', platforms: ['android'] },
            { method: 'emrtd_attested', label: 'ID card (chip)', privacy: 'on_device', platforms: ['android'] },
            { method: 'emrtd_attested', label: 'ID card (chip)', privacy: 'on_device', platforms: ['android'] },
            { method: 'connector:franceconnect', label: 'FranceConnect', privacy: 'login', platforms: ['android', 'windows'] },
          ],
        },
      ],
    });
    assert.deepEqual(pcMethods(fr).map((m) => m.label), ['ID card (chip)', 'Passport (chip)', 'FranceConnect']);
  });

  it('drops broken entries instead of showing them half-made', () => {
    const list = parseCatalog({
      countries: [
        { code: 'in', name: 'India', methods: [{ method: 'anon_aadhaar', label: 'Aadhaar QR', privacy: 'zero_knowledge', platforms: ['windows'] }] },
        { code: 'IN', name: 'Duplicate' },
        { code: '123', name: 'Bad code' },
        { code: 'FR', name: 'France', methods: [{ method: 'x', label: '', privacy: 'zero_knowledge' }, { method: 'BAD METHOD', label: 'x', privacy: 'login' }, { method: 'connector:franceconnect', label: 'FranceConnect', privacy: 'nope' }] },
      ],
    });
    assert.deepEqual(list.map((c) => c.code), ['IN', 'FR']);
    assert.equal(list[1].methods.length, 0);
    assert.throws(() => parseCatalog({ nope: [] }));
  });

  it('joins the windows and android answers when the server filters by platform', () => {
    const strict = (p: string) => ({ countries: CATALOG.countries.map((c) => ({ ...c, methods: c.methods.filter((m) => m.platforms.includes(p)) })) });
    const merged = mergeCatalogs(parseCatalog(strict('windows')), parseCatalog(strict('android')));
    const india = merged.find((c) => c.code === 'IN')!;
    assert.deepEqual(pcMethods(india).map((m) => m.kind), ['aadhaar', 'phone', 'connector']);
    assert.deepEqual(merged.map((c) => c.name), ['Germany', 'India', 'Nowhere', 'Singapore']);
  });

  it('reads the real catalog draft (catalog/countries.json), if it is there', { skip: existsSync(realCatalogFile) ? false : 'no catalog/countries.json yet' }, () => {
    const raw = JSON.parse(readFileSync(realCatalogFile, 'utf8'));
    const list = parseCatalog(raw);
    assert.equal(list.length, raw.countries.length, 'every country in the draft parses');
    const india = list.find((c) => c.code === 'IN');
    assert.ok(india);
    assert.ok(pcMethods(india).some((m) => m.kind === 'aadhaar'));
    // Every country with an app method gets at least one row on Windows (on this PC or with the phone).
    // Countries with no app method yet (empty in the draft) are hidden by the engine.
    const usable = list.filter((c) => c.methods.some((m) => m.platforms.includes('windows') || m.platforms.includes('android')));
    assert.ok(usable.length > 0);
    assert.ok(usable.every((c) => pcMethods(c).length > 0));
  });

  it('parses v18://connect links strictly', () => {
    const opts = { debug: true, defaultServer: 'http://localhost:8080/v1' };
    const ok = parseDeepLink('v18://connect?status=ok&cardId=card_AAAAAAAAAAAAAAAAAAAAAA&state=abcdefgh12345678', opts);
    assert.deepEqual(ok, { kind: 'connect', status: 'ok', cardId: 'card_AAAAAAAAAAAAAAAAAAAAAA', state: 'abcdefgh12345678' });
    assert.equal((parseDeepLink('v18://connect/?status=under_age', opts) as { status: string }).status, 'under_age');
    for (const bad of ['v18://connect', 'v18://connect?status=OK%20now', 'v18://connect?status=ok&cardId=evil', 'v18://connect?status=ok&state=a', 'v18://connect?status=ok&status=no']) {
      assert.throws(() => parseDeepLink(bad, opts), bad);
    }
  });
});

describe('login connectors (PROTOCOL 4d.4), against the mock server and a mock provider', () => {
  let mock: MockServer;
  before(async () => {
    mock = await startMockServer({ devMode: true, catalog: CATALOG });
  });
  after(async () => {
    await mock.close();
  });

  /** Plays the web browser: follows the provider's redirects until the server sends it to v18://. */
  async function browse(url: string): Promise<string> {
    for (let i = 0; i < 10; i++) {
      const res = await fetch(url, { redirect: 'manual' });
      const to = res.headers.get('location');
      if (!to) throw new Error(`no redirect from ${url} (${res.status})`);
      if (to.startsWith('v18:')) return to;
      url = new URL(to, url).href;
    }
    throw new Error('too many redirects');
  }

  function makeEngine(m: MockServer, over: Partial<EngineDeps> & { browser?: 'returns' | 'stays' } = {}) {
    let data: any = { serverUrl: m.url, settings: { firstRunDone: true } };
    const hello = new FakeHelloAddon();
    const opened: string[] = [];
    let engine: V18Engine;
    const deps: EngineDeps = {
      debug: true,
      store: { load: () => data, save: (j) => (data = JSON.parse(j)) },
      hello: new HelloKeyProvider(hello),
      testKeys: null,
      makeQr: async () => 'data:,qr',
      onChange: () => undefined,
      extraServerOrigins: [m.origin],
      linkPollMs: 30,
      localeCountry: 'IN',
      openExternal: async (url) => {
        opened.push(url);
        const back = await browse(url);
        if (over.browser !== 'stays') setTimeout(() => void engine.handleDeepLink(back), 5);
      },
      ...over,
    };
    engine = new V18Engine(deps);
    return { engine, hello, opened, stored: () => data, view: () => engine.getView() };
  }

  function waitFor(get: () => ViewState, pred: (v: ViewState) => boolean, ms = 5000): Promise<ViewState> {
    const end = Date.now() + ms;
    return new Promise((resolve, reject) => {
      const t = () => {
        const v = get();
        if (pred(v)) return resolve(v);
        if (Date.now() > end) return reject(new Error('timed out; last: ' + JSON.stringify({ screen: v.screen, connect: v.connect, error: v.error })));
        setTimeout(t, 10);
      };
      t();
    });
  }

  it('builds the country list from the server, and pre-selects the PC\'s region', async () => {
    const { engine, view } = makeEngine(mock);
    await engine.init();
    assert.equal(view().catalog.status, 'ok');
    assert.deepEqual(view().catalog.countries.map((c) => c.code), ['DE', 'IN', 'SG'], 'web-only countries are left out');
    assert.equal(view().localeCountry, 'IN');
    assert.ok(mock.calls.includes('GET /catalog'));
  });

  it('Singpass: signs in through the browser, comes back via v18://connect, and saves the card', async () => {
    const { engine, opened, stored, view, hello } = makeEngine(mock);
    await engine.init();
    await engine.startConnector('singpass');
    await waitFor(view, (v) => v.screen === 'card-saved');
    assert.equal(opened.length, 1);
    assert.match(opened[0], /\/mock-provider\/singpass\/authorize\?state=/);
    assert.equal(stored().card.method, 'connector:singpass');
    assert.equal(view().card?.methodLabel, 'Singpass (Myinfo)');
    assert.equal(hello.signCount, 1, 'one Windows Hello signature for the request');
  });

  it('still finishes by polling when the browser never comes back to V18', async () => {
    const { engine, stored, view } = makeEngine(mock, { browser: 'stays' });
    await engine.init();
    await engine.startConnector('digilocker');
    await waitFor(view, (v) => v.screen === 'card-saved');
    assert.equal(stored().card.method, 'connector:digilocker');
  });

  it('a fake v18://connect link from any web page changes nothing', async () => {
    const { engine, stored, view } = makeEngine(mock);
    await engine.init();
    await engine.handleDeepLink('v18://connect?status=ok&cardId=card_AAAAAAAAAAAAAAAAAAAAAA&state=forgedforgedforged');
    assert.equal(stored().card ?? null, null);
    assert.match(view().notice ?? '', /wasn't waiting/);
    assert.equal(view().ask, null, 'no site-asks dialog for connect links');
  });

  it('under 18 at the provider: no card, and the new key is removed', async () => {
    const young = await startMockServer({ devMode: true, catalog: CATALOG, connectorBirthDate: `${new Date().getUTCFullYear() - 15}-01-01` });
    try {
      const { engine, stored, view, hello } = makeEngine(young);
      await engine.init();
      await engine.startConnector('singpass');
      await waitFor(view, (v) => v.screen === 'err-under18');
      assert.equal(stored().card ?? null, null);
      await waitFor(view, () => hello.keys.size === 0);
    } finally {
      await young.close();
    }
  });

  it('refuses to open a login link that is not https', async () => {
    const evil = await startMockServer({ devMode: true, catalog: CATALOG, connectAuthUrl: 'file:///C:/Windows/System32/calc.exe' });
    try {
      const { engine, opened, view } = makeEngine(evil);
      await engine.init();
      await engine.startConnector('singpass');
      assert.equal(opened.length, 0);
      assert.equal(view().screen, 'err-general');
    } finally {
      await evil.close();
    }
  });

  it('only connectors the catalog lists can be started, and Cancel removes the key', async () => {
    const { engine, opened, view, hello } = makeEngine(mock, { browser: 'stays', openExternal: async () => undefined });
    await engine.init();
    await engine.startConnector('mitid'); // not in this catalog
    assert.equal(opened.length, 0);
    assert.notEqual(view().screen, 'card-connect');
    await engine.startConnector('singpass');
    assert.equal(view().screen, 'card-connect');
    assert.equal(view().connect?.status, 'browser');
    engine.cancelConnect();
    await waitFor(view, () => hello.keys.size === 0);
  });

  it('shows a plain message and the phone option when the catalog can\'t be loaded', async () => {
    const plain = await startMockServer({ devMode: true });
    try {
      const { engine, view } = makeEngine(plain);
      await engine.init();
      assert.equal(view().catalog.status, 'error');
      assert.equal(view().catalog.countries.length, 0);
    } finally {
      await plain.close();
    }
  });
});
