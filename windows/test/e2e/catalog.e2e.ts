// The country and method screens built from the REAL server's catalog (PROTOCOL 4d.2), in the
// engine and in the real Electron app. Needs "npm run dev --prefix server" on :8080 and "npm run build".
// The app screenshot goes to docs/windows/screenshots/23-live-catalog-*.png.

import electronPath from 'electron';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { _electron as electron } from 'playwright-core';
import { V18Engine } from '../../src/main/engine.js';
import { HelloKeyProvider } from '../../src/main/keys.js';
import { V18Api } from '../../src/shared/api.js';
import { FakeHelloAddon } from '../helpers/fake-hello.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const shots = path.resolve(root, '..', 'docs', 'windows', 'screenshots');
const BASE = 'http://localhost:8080/v1';
const log = (...a: unknown[]) => console.log('   [catalog]', ...a);

let skip: string | false = false;
try {
  const h = await new V18Api(BASE).health();
  if (h.catalog !== 'ready') skip = `the server's catalog is "${String(h.catalog)}"`;
} catch {
  skip = 'no V18 server on http://localhost:8080';
}

describe('catalog-driven screens against the REAL server', { skip }, () => {
  it('the engine builds countries and methods from GET /v1/catalog (windows + android)', async () => {
    let data: any = { serverUrl: BASE, settings: { firstRunDone: true } };
    const e = new V18Engine({
      debug: true,
      store: { load: () => data, save: (j) => (data = JSON.parse(j)) },
      hello: new HelloKeyProvider(new FakeHelloAddon()),
      testKeys: null,
      makeQr: async () => '',
      onChange: () => undefined,
    });
    await e.init();
    const cat = e.getView().catalog;
    assert.equal(cat.status, 'ok', cat.message);
    const raw = (await new V18Api(BASE).catalog('windows')) as { countries: { code: string }[] };
    log(`server: ${raw.countries.length} countries with a Windows method; app shows ${cat.countries.length} countries (with phone methods)`);
    assert.ok(cat.countries.length > raw.countries.length, 'phone-only countries are listed too');
    const india = cat.countries.find((c) => c.code === 'IN');
    assert.ok(india, 'India is listed');
    log('India:', india.methods.map((m) => `${m.label} [${m.kind}]`).join(', '));
    assert.equal(india.methods[0].kind, 'aadhaar', 'Aadhaar QR first (zero-knowledge)');
    assert.ok(india.methods.some((m) => m.kind === 'phone'), 'passport through the phone');
    const counts = { aadhaar: 0, connector: 0, phone: 0 };
    for (const c of cat.countries) for (const m of c.methods) counts[m.kind]++;
    log('method rows over all countries:', JSON.stringify(counts));
    // Nothing the server didn't enable: health says which methods are ready.
    const h = await new V18Api(BASE).health();
    const ready = h.methods as Record<string, string>;
    for (const c of cat.countries) for (const m of c.methods) assert.equal(ready[m.method], 'ready', `${c.code} ${m.method}`);
    e.shutdown();
  });

  it('the real app shows the live catalog (India: Aadhaar on this PC, passport with your phone)', async () => {
    const profile = mkdtempSync(path.join(tmpdir(), 'v18-e2e-catalog-'));
    const app = await electron.launch({ executablePath: electronPath as unknown as string, args: [root, '--v18-no-protocol', `--v18-profile=${profile}`, '--v18-test-software-key'], cwd: root });
    try {
      const page = await app.firstWindow();
      await page.waitForSelector('#app .win', { timeout: 15000 });
      await page.click('button:has-text("Continue")');
      await page.click('nav >> text=Get age card');
      await page.waitForSelector('button.cbtn:has-text("India")', { timeout: 15000 });
      const countries = await page.locator('button.cbtn').count();
      log(`country buttons in the app: ${countries}`);
      await page.click('button.cbtn:has-text("India")');
      await page.screenshot({ path: path.join(shots, '23-live-catalog-countries.png') });
      await page.click('button:has-text("Continue")');
      await page.waitForSelector('text=On this PC');
      assert.ok(await page.isVisible('text=Aadhaar QR'));
      assert.ok(await page.isVisible('text=With your phone'));
      await page.screenshot({ path: path.join(shots, '24-live-catalog-india.png') });
    } finally {
      await app.evaluate(({ app: a }) => a.exit(0)).catch(() => undefined);
      await app.close().catch(() => undefined);
      rmSync(profile, { recursive: true, force: true });
    }
  });
});
