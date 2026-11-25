// Installer test (PROTOCOL 4c.7): the REAL NSIS installer, installed and uninstalled for real.
//   npm run dist:release        (or npm run dist), then
//   npm run test:installer
// It installs silently into a test folder, checks the files, shortcuts and v18:// registration,
// opens a real v18:// link through Windows and checks the INSTALLED app answers it, drives the
// installed app (Start with Windows on/off, proof builder in a utility process), then uninstalls
// silently and checks everything is gone. Afterwards it puts back any v18:// registration that was
// there before (for example a development copy's) and removes the profile file it made.

import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { _electron as electron } from 'playwright-core';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
const installer = process.env.V18_INSTALLER ?? path.join(root, 'release', `V18-Setup-${pkg.version}.exe`);
const dir = path.join(os.tmpdir(), 'v18-install-test');
const exe = path.join(dir, 'V18.exe');
const uninstaller = path.join(dir, 'Uninstall V18.exe');
const PROTO_KEY = 'HKCU\\Software\\Classes\\v18';
const RUN_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
const APPROVED_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run';
const stateFile = path.join(process.env.APPDATA ?? '', 'V18', 'v18-state.json');
const skip = process.platform !== 'win32' ? 'Windows only' : existsSync(installer) ? false : `no installer at ${installer} (run "npm run dist:release")`;

function reg(args: string[]): { ok: boolean; out: string } {
  const r = spawnSync('reg', args, { encoding: 'utf8' });
  return { ok: r.status === 0, out: (r.stdout ?? '') + (r.stderr ?? '') };
}
function regDefault(key: string): string | null {
  const r = reg(['query', key, '/ve']);
  if (!r.ok) return null;
  const m = /REG_SZ\s+(.*)$/m.exec(r.out);
  return m ? m[1].trim() : '';
}
function uninstallEntry(): string | null {
  const r = reg(['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall', '/s', '/f', 'V18', '/d']);
  const m = /^(HKEY_CURRENT_USER\\[^\r\n]+)\r?\n(?:(?!HKEY)[^\n]*\n)*?\s+DisplayName\s+REG_SZ\s+V18\s*$/m.exec(r.out);
  return m ? m[1] : null;
}
function psOut(script: string): string {
  // "exit 0": Get-Process with no match counts as a failure in PowerShell 5.1.
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `${script}; exit 0`], { encoding: 'utf8' }).trim();
}
/** V18 processes started from the test folder. */
function installedProcesses(): { id: number; title: string }[] {
  const json = psOut(
    `Get-Process V18 -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq '${exe.replace(/'/g, "''")}' } | Select-Object Id,MainWindowTitle | ConvertTo-Json -Compress`,
  );
  if (!json) return [];
  const v = JSON.parse(json);
  return (Array.isArray(v) ? v : [v]).map((p: { Id: number; MainWindowTitle: string }) => ({ id: p.Id, title: p.MainWindowTitle }));
}
function killInstalled(): void {
  psOut(`Get-Process V18 -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '${dir.replace(/'/g, "''")}*' } | Stop-Process -Force`);
}
async function until<T>(fn: () => T | null | undefined | false, ms: number, what: string): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 300));
  }
}
const log = (...a: unknown[]) => console.log('   [installer]', ...a);

describe('NSIS installer, for real (silent install, v18:// link, uninstall)', { skip }, () => {
  let prevProtocol: string | null = null;
  let hadState = false;
  let stateBackup = '';

  before(() => {
    killInstalled();
    rmSync(dir, { recursive: true, force: true });
    prevProtocol = regDefault(`${PROTO_KEY}\\shell\\open\\command`);
    hadState = existsSync(stateFile);
    if (hadState) stateBackup = readFileSync(stateFile, 'utf8');
    log('installer:', installer, `(${(readFileSync(installer).length / 1e6).toFixed(1)} MB)`);
    log('v18:// before the test:', prevProtocol ?? '(none)');
  });

  after(() => {
    killInstalled();
    // Put the v18:// registration back the way it was (for example the development copy's).
    if (prevProtocol && !regDefault(`${PROTO_KEY}\\shell\\open\\command`)) {
      reg(['add', PROTO_KEY, '/ve', '/d', 'URL:V18 age check', '/f']);
      reg(['add', PROTO_KEY, '/v', 'URL Protocol', '/d', '', '/f']);
      reg(['add', `${PROTO_KEY}\\shell\\open\\command`, '/ve', '/d', prevProtocol, '/f']);
      log('put back the earlier v18:// registration');
    }
    // The installed app wrote a profile file into %APPDATA%\V18; restore what was there.
    if (hadState) writeFileSync(stateFile, stateBackup);
    else rmSync(stateFile, { force: true });
    rmSync(dir, { recursive: true, force: true });
  });

  it('installs silently into a test folder', () => {
    const t0 = Date.now();
    const r = spawnSync(installer, ['/S', `/D=${dir}`], { stdio: 'ignore', timeout: 300_000 });
    log(`install exit code ${r.status}, ${((Date.now() - t0) / 1000).toFixed(1)} s`);
    assert.equal(r.status, 0);
    for (const f of [exe, uninstaller, path.join(dir, 'resources', 'app.asar'), path.join(dir, 'resources', 'app.asar.unpacked', 'dist', 'native', 'v18_hello.node')]) {
      assert.ok(existsSync(f), f);
    }
  });

  it('registers v18:// for the installed app, and adds shortcuts and an uninstall entry', () => {
    const cmd = regDefault(`${PROTO_KEY}\\shell\\open\\command`);
    log('v18:// after install:', cmd);
    assert.equal(cmd, `"${exe}" "%1"`);
    assert.ok(reg(['query', PROTO_KEY, '/v', 'URL Protocol']).ok);
    const entry = uninstallEntry();
    log('uninstall entry:', entry);
    assert.ok(entry, 'uninstall entry in Settings > Apps');
    const startMenu = path.join(process.env.APPDATA ?? '', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'V18.lnk');
    const desktop = path.join(psOut('[Environment]::GetFolderPath("Desktop")'), 'V18.lnk');
    assert.ok(existsSync(startMenu), startMenu);
    assert.ok(existsSync(desktop), desktop);
  });

  it('a v18:// link opened through Windows starts the INSTALLED app and shows the site-asks dialog', async () => {
    killInstalled();
    const link =
      'v18://verify?session=pair_installertest0000000000&origin=https%3A%2F%2Fshop.example&challenge=installer-test-challenge-0001&minAge=18&server=https%3A%2F%2Fapi.v18.example';
    // "start" hands the link to Windows exactly like a browser does.
    spawn('cmd.exe', ['/c', 'start', '""', link], { stdio: 'ignore', detached: true }).unref();
    const procs = await until(() => {
      const p = installedProcesses();
      return p.some((x) => x.title === 'V18: a site asks') ? p : null;
    }, 30_000, 'the installed V18 to open its site-asks window');
    log('installed V18 processes after the link:', procs.length, 'windows:', procs.map((p) => p.title).filter(Boolean));
    killInstalled();
  });

  it('the installed app runs its proof builder in a utility process and turns "Start with Windows" on and off', async () => {
    killInstalled();
    const profile = mkdtempSync(path.join(os.tmpdir(), 'v18-installed-profile-'));
    const app = await electron.launch({ executablePath: exe, args: [`--v18-profile=${profile}`] });
    try {
      const page = await app.firstWindow();
      await page.waitForSelector('#app .win', { timeout: 20_000 });
      const title = await page.evaluate(() => document.body.innerText);
      assert.match(title, /Welcome to V18|Home/);
      // Release build: only the production server.
      const info = await app.evaluate(async ({ app: a, utilityProcess }) => {
        const prover = (process as unknown as { resourcesPath: string }).resourcesPath + '\\app.asar\\dist\\prover.cjs';
        const answer = await new Promise<unknown>((resolve) => {
          const child = utilityProcess.fork(prover, [], { serviceName: 'V18 proof builder test', stdio: 'ignore' });
          const t = setTimeout(() => resolve('timeout'), 20_000);
          child.on('message', (m: { type: string; code?: string }) => {
            if (m.type === 'error') {
              clearTimeout(t);
              child.kill();
              resolve(m.code);
            }
          });
          child.on('spawn', () =>
            child.postMessage({ type: 'prove', qrText: '12345', certPem: '-----BEGIN CERTIFICATE-----', nullifierSeed: '1', signal: '0x01', wasmPath: 'x', zkeyPath: 'y', vkeyPath: 'z' }),
          );
        });
        return { packaged: a.isPackaged, prover: answer };
      });
      log('installed app:', JSON.stringify(info));
      assert.equal(info.packaged, true);
      assert.equal(info.prover, 'BAD_QR', 'the proof builder loaded from app.asar and answered');

      await page.click('button:has-text("Continue")');
      await page.click('button.navi:has-text("Settings")');
      await page.waitForSelector('text=Start V18 when I sign in to Windows');
      const server = await page.textContent('text=https://api.v18.example/v1');
      assert.ok(server, 'release build uses the production server');
      assert.ok(!(await page.isVisible('text=TEST MODE')));
      const toggle = page.locator('button[aria-label="Start V18 when I sign in to Windows"]');
      assert.equal(await toggle.getAttribute('aria-pressed'), 'false', 'off by default');
      await toggle.click();
      await page.waitForSelector('button[aria-label="Start V18 when I sign in to Windows"][aria-pressed="true"]');
      const run = reg(['query', RUN_KEY, '/v', 'com.v18.desktop']);
      log('Run entry after turning it on:', /REG_SZ\s+(.*)/.exec(run.out)?.[1]);
      assert.ok(run.ok && run.out.includes(exe) && run.out.includes('--v18-hidden'), run.out);
      // Leave it ON, so the uninstall test can check the uninstaller removes it.
    } finally {
      await app.evaluate(({ app: a }) => a.exit(0)).catch(() => undefined);
      await app.close().catch(() => undefined);
      rmSync(profile, { recursive: true, force: true });
    }
  });

  it('uninstalls silently and removes the app, shortcuts, uninstall entry, v18:// and the start-up entry', async () => {
    killInstalled();
    const t0 = Date.now();
    const r = spawnSync(uninstaller, ['/S'], { stdio: 'ignore', timeout: 300_000 });
    assert.equal(r.status, 0);
    // The NSIS uninstaller copies itself to a temp folder and finishes there.
    await until(() => !existsSync(exe) && !uninstallEntry(), 120_000, 'the uninstaller to finish');
    log(`uninstall done in ${((Date.now() - t0) / 1000).toFixed(1)} s; left in the test folder:`, existsSync(dir) ? readdirSync(dir) : '(folder removed)');
    assert.equal(regDefault(`${PROTO_KEY}\\shell\\open\\command`), null, 'v18:// registration removed');
    assert.equal(reg(['query', PROTO_KEY]).ok, false);
    assert.equal(reg(['query', RUN_KEY, '/v', 'com.v18.desktop']).ok, false, 'start-up entry removed');
    assert.equal(reg(['query', APPROVED_KEY, '/v', 'com.v18.desktop']).ok, false);
    assert.ok(!existsSync(path.join(process.env.APPDATA ?? '', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'V18.lnk')));
    assert.ok(!existsSync(path.join(psOut('[Environment]::GetFolderPath("Desktop")'), 'V18.lnk')));
  });
});
