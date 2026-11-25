// Smoke test: launches the REAL built Electron app (dist/) with playwright-core, clicks through
// the screens, checks the security settings from inside the page, and saves screenshots to
// docs/windows/screenshots/. Run "npm run build" first, then "npm run test:smoke".
//
// Uses a separate profile folder and --v18-no-protocol, so it never touches your real V18 data,
// the v18:// registration or the Windows start-up list. It talks to the protocol mock server
// (test/helpers/mock-server.ts) through the debug-only --v18-test-server flag.
// The Aadhaar part uses the REAL circuit files (from server/assets/artifacts, or V18_ARTIFACTS_DIR)
// and the REAL proof builder in the app's utility process; it is skipped if the files aren't there.
// Windows Hello is never prompted: the flows use --v18-test-software-key.

import electronPath from 'electron';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import QRCode from 'qrcode';
import { _electron as electron, type ElectronApplication, type Page } from 'playwright-core';
import { verifyTicketString } from '../../src/shared/ticket.js';
import { startMockServer, type MockServer } from '../helpers/mock-server.js';
import { makeTestAadhaarQr } from '../helpers/test-aadhaar.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const shots = path.resolve(root, '..', 'docs', 'windows', 'screenshots');
mkdirSync(shots, { recursive: true });
const filesDir = process.env.V18_ARTIFACTS_DIR ?? path.join(root, '..', 'server', 'assets', 'artifacts');
const ARTIFACT_NAMES = ['aadhaar-verifier.wasm', 'circuit_final.zkey', 'vkey.json'];
const haveFiles = ARTIFACT_NAMES.every((n) => existsSync(path.join(filesDir, n)));

const CATALOG = {
  version: 1,
  countries: [
    {
      code: 'IN',
      name: 'India',
      region: 'asia',
      methods: [
        { method: 'anon_aadhaar', label: 'Aadhaar QR', documents: ['Aadhaar letter', 'e-Aadhaar PDF', 'mAadhaar app QR'], needs: ['camera'], privacy: 'zero_knowledge', platforms: ['android', 'windows'] },
        { method: 'emrtd_attested', label: 'Passport (chip)', documents: ['Indian e-passport'], needs: ['nfc'], privacy: 'on_device', platforms: ['android'] },
        { method: 'connector:digilocker', label: 'DigiLocker', documents: ['DigiLocker account'], needs: ['password'], privacy: 'login', platforms: ['android', 'windows'] },
      ],
    },
    {
      code: 'DE',
      name: 'Germany',
      region: 'europe',
      methods: [
        { method: 'emrtd_attested', label: 'Passport or ID card (chip)', documents: ['Reisepass', 'Personalausweis', 'Aufenthaltstitel'], needs: ['nfc'], privacy: 'on_device', platforms: ['android'] },
        { method: 'mdoc_app', label: 'EU wallet', documents: ['German EUDI wallet'], needs: ['wallet'], privacy: 'wallet', platforms: ['android'] },
      ],
    },
    {
      code: 'SG',
      name: 'Singapore',
      region: 'asia',
      methods: [
        { method: 'emrtd_attested', label: 'Passport (chip)', documents: ['Singapore passport'], needs: ['nfc'], privacy: 'on_device', platforms: ['android'] },
        { method: 'connector:singpass', label: 'Singpass (Myinfo)', documents: ['Singpass account'], needs: ['password'], privacy: 'login', platforms: ['android', 'windows'] },
      ],
    },
  ],
};

async function launch(mock: MockServer, extra: string[] = []) {
  const profile = mkdtempSync(path.join(tmpdir(), 'v18-smoke-'));
  const args = [root, '--v18-no-protocol', `--v18-profile=${profile}`, `--v18-test-server=${mock.origin}`, ...extra];
  const app = await electron.launch({ executablePath: electronPath as unknown as string, args, cwd: root });
  const page = await app.firstWindow();
  await page.waitForSelector('#app .win', { timeout: 15000 });
  return { app, page, profile, args };
}

async function shot(page: Page, name: string) {
  await page.waitForTimeout(250);
  await page.screenshot({ path: path.join(shots, `${name}.png`) });
}

async function close(app: ElectronApplication, profile: string) {
  await app.evaluate(({ app: a }) => a.exit(0)).catch(() => undefined);
  await app.close().catch(() => undefined);
  rmSync(profile, { recursive: true, force: true });
}

/** Plays the web browser for a login: follows redirects until the server sends it to v18://. */
async function browse(url: string): Promise<string> {
  for (let i = 0; i < 10; i++) {
    const res = await fetch(url, { redirect: 'manual' });
    const to = res.headers.get('location');
    if (!to) throw new Error(`no redirect from ${url}`);
    if (to.startsWith('v18:')) return to;
    url = new URL(to, url).href;
  }
  throw new Error('too many redirects');
}

async function getStarted(page: Page, country: string) {
  await page.click('nav >> text=Get age card');
  await page.waitForSelector('text=Where is your ID from?');
  await page.click(`button.cbtn:has-text("${country}")`);
  await page.click('button:has-text("Continue")');
  await page.waitForSelector('text=Choose how to make your age card');
}

describe('V18 for Windows (real Electron app)', () => {
  let mock: MockServer;
  before(async () => {
    const artifacts = haveFiles ? Object.fromEntries(ARTIFACT_NAMES.map((n) => [n, readFileSync(path.join(filesDir, n))])) : undefined;
    mock = await startMockServer({ devMode: true, catalog: CATALOG, artifacts, aadhaar: 'ready' });
  });
  after(async () => {
    await mock.close();
  });

  it('first run, home, security settings, catalog screens, and the real Windows Hello check', async () => {
    const { app, page, profile } = await launch(mock);
    try {
      await page.waitForSelector('text=Who uses this PC?');
      await shot(page, '01-welcome');
      await page.click('button:has-text("Continue")');
      await page.waitForSelector('h1:has-text("Home")');
      await page.waitForFunction(() => !document.body.innerText.includes('Checking'), undefined, { timeout: 10000 });
      await shot(page, '02-home-no-card');

      // Security from inside the page: no Node, small bridge, no network, Trusted Types on.
      const probe = await page.evaluate(async (url) => {
        const w = window as unknown as Record<string, unknown>;
        let net = 'allowed';
        try {
          await fetch(url);
        } catch {
          net = 'blocked';
        }
        let tt = 'allowed';
        try {
          document.createElement('div').innerHTML = '<b>x</b>';
        } catch {
          tt = 'blocked';
        }
        let inlineStyle = 'allowed';
        const d = document.createElement('div');
        d.setAttribute('style', 'color: red');
        document.body.appendChild(d);
        if (getComputedStyle(d).color !== 'rgb(255, 0, 0)') inlineStyle = 'blocked';
        d.remove();
        return { require: typeof w.require, process: typeof w.process, module: typeof w.module, bridge: Object.keys(w.v18 as object).sort(), net, tt, inlineStyle };
      }, `${mock.url}/health`);
      assert.deepEqual(probe, { require: 'undefined', process: 'undefined', module: 'undefined', bridge: ['invoke', 'onView'], net: 'blocked', tt: 'blocked', inlineStyle: 'blocked' });
      const refused = await page.evaluate(() => (window as any).v18.invoke('v18:not-a-channel').then(() => 'ran', () => 'refused'));
      assert.equal(refused, 'refused');
      const noSandbox = await app.evaluate(({ app: a }) => a.commandLine.hasSwitch('no-sandbox'));
      assert.equal(noSandbox, false);

      // Country and method screens come from the server's catalog (no list in the app).
      await page.click('nav >> text=Get age card');
      await page.waitForSelector('text=Where is your ID from?');
      for (const name of ['India', 'Germany', 'Singapore']) assert.ok(await page.isVisible(`button.cbtn:has-text("${name}")`), name);
      await page.click('button.cbtn:has-text("India")');
      await shot(page, '03-card-country');
      await page.click('button:has-text("Continue")');
      await page.waitForSelector('text=Choose how to make your age card');
      for (const t of ['On this PC', 'Aadhaar QR', 'DigiLocker', 'With your phone', 'Passport (chip)', 'I already have an age card on my phone']) {
        assert.ok(await page.isVisible(`text=${t}`), t);
      }
      // Nothing that isn't built is shown.
      for (const t of ['NFC reader', 'Face estimate', 'Not available', 'stub', 'coming soon']) assert.equal(await page.isVisible(`text=${t}`), false, t);
      await shot(page, '04-card-methods-india');
      await page.click('button.lnk:has-text("Change")');
      await page.click('button.cbtn:has-text("Germany")');
      await page.click('button:has-text("Continue")');
      await page.waitForSelector('text=With your phone');
      assert.equal(await page.isVisible('text=On this PC'), false);
      await shot(page, '05-card-methods-germany');

      // The real Windows Hello helper. With no Windows Hello this must show the error screen,
      // never a software key. With Windows Hello set up the test doesn't start a prompt.
      const hello = await page.evaluate(() => (window as any).v18.invoke('v18:get-view').then((v: any) => v.hello));
      if (hello.ok) {
        console.log('  Windows Hello is set up on this PC (the smoke test does not start a Hello prompt).');
      } else {
        await page.click('button:has-text("I already have an age card on my phone")');
        await page.waitForSelector('#app .si.err');
        await shot(page, '05b-error-hello-not-set-up');
        console.log(`  Real Windows Hello check: ${hello.code} (${hello.detail ?? ''})`);
      }

      await page.click('nav >> text=Settings');
      await page.waitForSelector('h1:has-text("Settings")');
      const startup = page.locator('button[aria-label="Start V18 when I sign in to Windows"]');
      assert.equal(await startup.getAttribute('aria-pressed'), 'false', 'Start with Windows is off by default');
      await shot(page, '06-settings');
      await page.click('nav >> text=How seals work');
      await shot(page, '07-how-seals-work');
    } finally {
      await close(app, profile);
    }
  });

  it('Aadhaar QR: real seal check, real proof files and the real proof builder in the app', { skip: haveFiles ? false : `no circuit files in ${filesDir}` }, async () => {
    const { app, page, profile } = await launch(mock, ['--v18-test-software-key']);
    try {
      // A fresh TEST QR picture. The file dialog is answered by the test.
      const qrPng = path.join(profile, 'aadhaar-test-qr.png');
      await QRCode.toFile(qrPng, [{ data: makeTestAadhaarQr(), mode: 'numeric' }], { errorCorrectionLevel: 'L', margin: 3, scale: 3 });
      await app.evaluate(({ dialog }, file) => {
        (dialog as unknown as { showOpenDialog: unknown }).showOpenDialog = async () => ({ canceled: false, filePaths: [file] });
      }, qrPng);
      await page.click('button:has-text("Continue")');
      await getStarted(page, 'India');
      await page.click('button:has-text("Aadhaar QR")');
      await page.waitForSelector('text=Scan your Aadhaar Secure QR');
      await shot(page, '08-aadhaar-pick');
      await page.click('button:has-text("Choose file")');
      await page.waitForSelector('text=TEST seal found', { timeout: 15000 });
      await shot(page, '09-aadhaar-read');
      await page.click('button:has-text("Build my proof")');
      await page.waitForSelector('text=Downloading from the V18 server', { timeout: 15000 }).catch(() => undefined);
      await page.waitForSelector('text=Build the zero-knowledge proof on this PC', { timeout: 60000 });
      await page.waitForSelector('text=Combining points', { timeout: 120000 });
      await shot(page, '10-aadhaar-building-proof');
      await page.waitForSelector('text=Your age card is saved', { timeout: 300000 });
      await shot(page, '11-aadhaar-card-saved');
      const seconds = await page.evaluate(() => (window as any).v18.invoke('v18:get-view').then((v: any) => v.lastProofSeconds));
      console.log(`  Real proof built in the app's utility process in ${seconds} s.`);
      assert.equal(mock.aadhaarProofs.length >= 1, true);
      await page.click('nav >> text=Settings');
      await page.waitForSelector('text=Aadhaar proof files');
    } finally {
      await close(app, profile);
    }
  });

  it('TEST key: TEST card, site asks, ticket, phone link, login connector, delete, shared PC mode', async () => {
    const { app, page, profile, args } = await launch(mock, ['--v18-test-software-key']);
    try {
      await page.click('button:has-text("Continue")');
      await page.waitForSelector('text=TEST KEY.');
      await getStarted(page, 'India');
      await page.click('button:has-text("TEST card")');
      await page.waitForSelector('text=Make a TEST card');
      await shot(page, '12-card-test');
      await page.click('button:has-text("Make TEST card")');
      await page.waitForSelector('text=Your age card is saved', { timeout: 15000 });
      await page.click('button:has-text("Go to Home")');
      await page.waitForSelector('text=Age card active');
      await shot(page, '13-home-active');
      await page.emulateMedia({ colorScheme: 'dark' });
      await shot(page, '14-home-active-dark');
      await page.emulateMedia({ colorScheme: 'light' });

      // A site asks: a second launch with the v18:// link hands it to this running app.
      const { sessionId, deepLink } = mock.createSession('https://example-site.test', 'site-challenge-smoke-1');
      const askWindow = app.waitForEvent('window');
      spawn(electronPath as unknown as string, [...args, deepLink], { cwd: root, stdio: 'ignore' });
      const ask = await askWindow;
      await ask.waitForSelector('text=Are you 18+?', { timeout: 15000 });
      assert.equal(await ask.title(), 'V18: a site asks');
      await shot(ask, '15-ask-dialog');
      await ask.click('button:has-text("Send 18+ ticket")');
      await ask.waitForSelector('text=Ticket sent', { timeout: 15000 });
      await shot(ask, '16-ask-ticket-sent');
      const s = mock.sessions.get(sessionId)!;
      assert.equal(s.status, 'approved');
      const v = await verifyTicketString(s.ticket!, mock.issuerJwk as never);
      assert.equal(v.ok, true);
      assert.equal(v.payload?.origin, 'https://example-site.test');
      await ask.click('button:has-text("Back to browser")').catch(() => undefined);

      // A phone-only ID (Germany): the device link, with the picked ID named in the steps.
      await getStarted(page, 'Germany');
      await page.click('button:has-text("Passport or ID card (chip)")');
      await page.waitForSelector('text=Waiting for your phone', { timeout: 15000 });
      assert.ok(await page.isVisible('text=Passport or ID card (chip)'));
      await shot(page, '17-card-phone-qr');
      mock.approveLink([...mock.links.keys()].pop()!);
      await page.waitForSelector('text=Your age card is saved', { timeout: 15000 });

      // A login connector (Singapore, Singpass): the browser is played by the test, and the
      // v18://connect link comes back through a second launch, exactly as Windows hands it over.
      const opened: string[] = [];
      await app.evaluate(({ shell }) => {
        (globalThis as any).__opened = [];
        (shell as unknown as { openExternal: unknown }).openExternal = async (u: string) => void (globalThis as any).__opened.push(u);
      });
      await getStarted(page, 'Singapore');
      await page.click('button:has-text("Singpass (Myinfo)")');
      await page.waitForSelector('text=Sign in with Singpass (Myinfo) in your browser', { timeout: 15000 });
      await shot(page, '18-connector-waiting');
      opened.push(...(await app.evaluate(() => (globalThis as any).__opened as string[])));
      assert.equal(opened.length, 1);
      const back = await browse(opened[0]);
      assert.match(back, /^v18:\/\/connect\?status=ok/);
      spawn(electronPath as unknown as string, [...args, back], { cwd: root, stdio: 'ignore' });
      await page.waitForSelector('text=Your age card is saved', { timeout: 15000 });
      await shot(page, '19-connector-card-saved');

      // Delete the card.
      await page.click('nav >> text=Settings');
      await page.click('button:has-text("Delete age card")');
      await shot(page, '20-settings-delete-dialog');
      await page.click('.dlg button:has-text("Delete")');
      await page.waitForSelector("text=You don't have an age card yet", { timeout: 15000 });

      // Shared PC mode, then a site asks: the phone QR.
      await page.click('nav >> text=Settings');
      await page.click('button[aria-label="Shared PC mode"]');
      await page.click('nav >> text=Home');
      await page.waitForSelector('text=Shared PC mode is on');
      await shot(page, '21-home-shared');
      const second = mock.createSession('https://example-site.test', 'site-challenge-smoke-2');
      const askWindow2 = app.waitForEvent('window');
      spawn(electronPath as unknown as string, [...args, second.deepLink], { cwd: root, stdio: 'ignore' });
      const ask2 = await askWindow2;
      await ask2.waitForSelector('button:has-text("Use my phone")', { timeout: 15000 });
      await ask2.click('button:has-text("Use my phone")');
      await ask2.waitForSelector('text=Scan with your phone');
      await shot(ask2, '22-ask-shared-phone-qr');
    } finally {
      await close(app, profile);
    }
  });
});
