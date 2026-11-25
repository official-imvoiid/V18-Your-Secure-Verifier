/**
 * GET /v1/catalog (4d.2) and GET /v1/artifacts/* (4c.1).
 */
import 'reflect-metadata';
import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { validateCatalog } from '../catalog/service.js';
import { repoRoot } from '../config.js';
import { ConnectorLike, RegistryLike } from '../connect/service.js';
import { api, startServer, TestServer } from './helpers.js';

const REAL_CATALOG = path.join(repoRoot, 'catalog', 'countries.json');

function tmpCatalog(content: unknown): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-cat-'));
  const f = path.join(dir, 'countries.json');
  fs.writeFileSync(f, typeof content === 'string' ? content : JSON.stringify(content));
  return f;
}

const SAMPLE = {
  version: 1,
  countries: [
    {
      code: 'SG',
      name: 'Singapore',
      region: 'asia',
      methods: [
        { method: 'emrtd_attested', label: 'Passport (chip)', documents: ['Singapore passport'], docTypes: ['P'], needs: ['nfc'], privacy: 'on_device', platforms: ['android'] },
        { method: 'connector:singpass', label: 'Singpass', documents: ['Singpass app'], needs: ['password'], privacy: 'login', platforms: ['android', 'windows'] },
        { method: 'face_estimate', label: 'Face', documents: [], needs: ['camera'], privacy: 'estimate', platforms: ['android'] },
      ],
    },
    {
      code: 'IN',
      name: 'India',
      region: 'asia',
      methods: [
        { method: 'anon_aadhaar', label: 'Aadhaar QR', documents: ['Aadhaar letter'], needs: ['camera'], privacy: 'zero_knowledge', platforms: ['android', 'windows'] },
        { method: 'mdoc_wallet', label: 'Wallet', documents: ['mDL'], needs: ['wallet'], privacy: 'wallet', platforms: ['web'] },
      ],
    },
  ],
};

function fakeConnector(id: string): ConnectorLike {
  return {
    id,
    countries: ['SG'],
    assurance: 'high',
    label: id,
    callbackMethod: 'GET',
    async buildAuthUrl() {
      return { authUrl: 'https://login.example/' };
    },
    async handleCallback() {
      return { over18: true, subject: 's' };
    },
  };
}
const registry = (ids: string[]): RegistryLike => ({
  list: () => ids.map(fakeConnector),
  get: (id) => (ids.includes(id) ? fakeConnector(id) : undefined),
});

describe('Country catalog (4d.2)', () => {
  it('the real catalog/countries.json follows the 4d.2 schema', () => {
    assert.ok(fs.existsSync(REAL_CATALOG), 'catalog/countries.json is present');
    const errs = validateCatalog(JSON.parse(fs.readFileSync(REAL_CATALOG, 'utf8')));
    assert.deepEqual(errs, []);
  });

  it('serves only what this server has enabled, open to any website', async () => {
    const srv = await startServer({ config: { catalogPath: tmpCatalog(SAMPLE) } });
    const r = await api(srv.url, 'GET', '/v1/catalog', undefined, { Origin: 'https://any-site.example' });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('access-control-allow-origin'), 'https://any-site.example');
    const sg = r.body.countries.find((c: any) => c.code === 'SG');
    // No connector credentials and no face model on this server: both hidden.
    assert.deepEqual(sg.methods.map((m: any) => m.method), ['emrtd_attested']);
    // No Aadhaar key and no wallet trust list on this test server: India has nothing left, so it is left out.
    assert.equal(r.body.countries.find((c: any) => c.code === 'IN'), undefined);
    await srv.close();
  });

  it('shows a connector once it is configured, and filters by country and platform', async () => {
    const srv = await startServer({ connectorRegistry: registry(['singpass']), config: { catalogPath: tmpCatalog(SAMPLE) } });
    const all = await api(srv.url, 'GET', '/v1/catalog?country=sg');
    assert.deepEqual(all.body.countries[0].methods.map((m: any) => m.method), ['emrtd_attested', 'connector:singpass']);
    const win = await api(srv.url, 'GET', '/v1/catalog?country=SG&platform=windows');
    assert.deepEqual(win.body.countries[0].methods.map((m: any) => m.method), ['connector:singpass']);
    assert.deepEqual((await api(srv.url, 'GET', '/v1/catalog?country=FR')).body.countries, []);
    assert.equal((await api(srv.url, 'GET', '/v1/catalog?country=France')).status, 400);
    assert.equal((await api(srv.url, 'GET', '/v1/catalog?platform=ios')).status, 400);
    await srv.close();
  });

  it('a missing or invalid catalog gives 503, and health says so', async () => {
    const missing = await startServer({ config: { catalogPath: path.join(os.tmpdir(), 'no-such-dir', 'countries.json') } });
    const r = await api(missing.url, 'GET', '/v1/catalog');
    assert.equal(r.status, 503);
    assert.equal(r.body.code, 'CATALOG_MISSING');
    assert.equal((await api(missing.url, 'GET', '/v1/health')).body.catalog, 'missing');
    await missing.close();
    const bad = {
      version: 1,
      countries: [{ code: 'sg', name: 'x', region: 'asia', methods: [{ method: 'emrtd_attested', label: 'x', documents: [], needs: ['fax'], privacy: 'secret', platforms: ['android'] }] }],
    };
    const invalid = await startServer({ config: { catalogPath: tmpCatalog(bad) } });
    const r2 = await api(invalid.url, 'GET', '/v1/catalog');
    assert.equal(r2.status, 503);
    assert.equal(r2.body.code, 'CATALOG_INVALID');
    assert.equal(validateCatalog(bad).length, 3);
    await invalid.close();
  });
});

describe('Anon Aadhaar artifacts (4c.1)', () => {
  let srv: TestServer;
  before(async () => {
    srv = await startServer();
    await srv.services.artifacts.ready;
  });
  after(async () => srv.close());

  it('lists every pinned file with its SHA-256, size and a URL on this server', async () => {
    const r = await api(srv.url, 'GET', '/v1/artifacts/manifest', undefined, { Origin: 'https://any.example' });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('access-control-allow-origin'), 'https://any.example');
    const byName = Object.fromEntries(r.body.map((f: any) => [f.name, f]));
    for (const n of ['vkey.json', 'aadhaar-verifier.wasm', 'circuit_final.zkey']) {
      assert.match(byName[n].sha256, /^[0-9a-f]{64}$/);
      assert.equal(byName[n].optional, false);
      assert.equal(byName[n].url, `http://localhost:8080/v1/artifacts/${n}`);
    }
    assert.equal(byName['circuit_final.zkey'].bytes, 612082146);
    assert.equal(r.body.filter((f: any) => f.optional).length, 10);
  });

  it('serves vkey.json and the wasm with the pinned SHA-256', async () => {
    const list = (await api(srv.url, 'GET', '/v1/artifacts/manifest')).body;
    for (const n of ['vkey.json', 'aadhaar-verifier.wasm']) {
      const entry = list.find((f: any) => f.name === n);
      assert.equal(entry.available, true, `${n} must be fetched (npm run fetch-artifacts)`);
      const res = await fetch(`${srv.url}/v1/artifacts/${n}`);
      const bytes = Buffer.from(await res.arrayBuffer());
      assert.equal(res.status, 200);
      assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), entry.sha256);
      assert.equal(res.headers.get('etag'), `"${entry.sha256}"`);
    }
    const head = await fetch(`${srv.url}/v1/artifacts/aadhaar-verifier.wasm`, { method: 'HEAD' });
    assert.equal(head.headers.get('content-type'), 'application/wasm');
  });

  it('supports Range requests on the 612 MB zkey (206), so apps can resume', async () => {
    const res = await fetch(`${srv.url}/v1/artifacts/circuit_final.zkey`, { headers: { Range: 'bytes=612082136-' } });
    assert.equal(res.status, 206);
    assert.equal(res.headers.get('content-range'), 'bytes 612082136-612082145/612082146');
    assert.equal((await res.arrayBuffer()).byteLength, 10);
  });

  it('refuses unknown names and path tricks', async () => {
    assert.equal((await api(srv.url, 'GET', '/v1/artifacts/manifest.json')).status, 404);
    assert.equal((await api(srv.url, 'GET', '/v1/artifacts/..%2Fmanifest.json')).status, 404);
    assert.equal((await api(srv.url, 'GET', '/v1/artifacts/nope.zkey')).body.code, 'ARTIFACT_NOT_FOUND');
  });
});
