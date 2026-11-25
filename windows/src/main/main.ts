// V18 for Windows: Electron main process.
// - One instance only. v18:// links from the browser arrive as command-line arguments.
// - Every window is sandboxed with contextIsolation on and no Node in the page.
// - All network calls happen here, in the main process, never in a window.

import { app, BrowserWindow, dialog, ipcMain, Menu, nativeImage, nativeTheme, Notification, session, shell, Tray, utilityProcess, type IpcMainInvokeEvent } from 'electron';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import QRCode from 'qrcode';
import { ARTIFACT_SET } from '../shared/artifact-pins.js';
import { findDeepLinkArg } from '../shared/deeplink.js';
import { ArtifactStore } from './artifacts.js';
import { V18Engine } from './engine.js';
import { HelloKeyProvider, TestSoftwareKeyProvider, type HelloAddon } from './keys.js';
import type { SpawnProver } from './prover-host.js';
import type { AskView, ViewState } from './view.js';

declare const __V18_DEBUG__: boolean;

const APP_ID = 'com.v18.desktop';
const PROTOCOL = 'v18';
const TEST_KEY_FLAG = '--v18-test-software-key';
/** Added by "Start V18 when I sign in to Windows": start in the tray, without a window. */
const HIDDEN_FLAG = '--v18-hidden';
/** Automated tests: never touch the v18:// registration or the Windows start-up list. */
const NO_SYSTEM_CHANGES = process.argv.includes('--v18-no-protocol');
const DEBUG = typeof __V18_DEBUG__ === 'boolean' ? __V18_DEBUG__ : true;
// Debug builds only: --v18-test-server=http://127.0.0.1:<port> points the app at a local test
// server (used by the smoke test). Loopback http only. Release builds ignore it.
function testServerFromArgs(): string | null {
  if (!DEBUG) return null;
  const arg = process.argv.find((a) => a.startsWith('--v18-test-server='));
  if (!arg) return null;
  try {
    const u = new URL(arg.slice('--v18-test-server='.length));
    return u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost') ? u.origin : null;
  } catch {
    return null;
  }
}
const TEST_SERVER = testServerFromArgs();
const RENDERER_HTML = path.join(__dirname, 'renderer', 'index.html');
const RENDERER_URL = pathToFileURL(RENDERER_HTML).href;

app.setAppUserModelId(APP_ID);
app.enableSandbox();

// Smoke tests (and anyone who wants a separate profile) can pass --v18-profile=<folder>.
const profileArg = process.argv.find((a) => a.startsWith('--v18-profile='));
if (profileArg) app.setPath('userData', path.resolve(profileArg.slice('--v18-profile='.length)));

// ------------------------------------------------------------------ single instance + protocol

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  start();
}

function registerProtocol(): void {
  // Automated smoke tests run without touching the v18:// registration.
  if (NO_SYSTEM_CHANGES) return;
  if (process.argv.includes('--v18-unregister-protocol')) {
    if (process.defaultApp && process.argv[1]) app.removeAsDefaultProtocolClient(PROTOCOL, process.execPath, [path.resolve(process.argv[1])]);
    else app.removeAsDefaultProtocolClient(PROTOCOL);
    return;
  }
  if (process.defaultApp && process.argv.length >= 2) {
    // Development: "electron.exe <app folder> v18://..."
    app.setAsDefaultProtocolClient(PROTOCOL, process.execPath, [path.resolve(process.argv[1])]);
  } else {
    app.setAsDefaultProtocolClient(PROTOCOL);
  }
}

// ------------------------------------------------------------------ Windows Hello addon

function loadHelloAddon(): { addon: HelloAddon | null; error?: string } {
  const candidates = [
    path.join(__dirname, 'native', 'v18_hello.node').replace('app.asar' + path.sep, 'app.asar.unpacked' + path.sep),
    path.join(__dirname, '..', 'native', 'v18-hello', 'v18_hello.node'),
  ];
  const errors: string[] = [];
  for (const file of candidates) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      return { addon: require(file) as HelloAddon };
    } catch (err) {
      errors.push(`${file}: ${err instanceof Error ? err.message.split('\n')[0] : String(err)}`);
    }
  }
  return { addon: null, error: 'The Windows Hello helper (v18_hello.node) could not be loaded. ' + errors.join(' | ') };
}

// ------------------------------------------------------------------ proof builder (Anon Aadhaar), in a utility process

function electronProverSpawner(): SpawnProver {
  return () => {
    // A separate Node process: a crash or out-of-memory there can't take the app down, and the
    // page (renderer) never sees the QR or the proof inputs.
    const child = utilityProcess.fork(path.join(__dirname, 'prover.cjs'), [], {
      serviceName: 'V18 proof builder',
      stdio: 'ignore',
      execArgv: ['--max-old-space-size=6144'],
    });
    let spawned = false;
    const queue: unknown[] = [];
    child.once('spawn', () => {
      spawned = true;
      for (const m of queue.splice(0)) child.postMessage(m);
    });
    return {
      send: (job) => (spawned ? child.postMessage(job) : void queue.push(job)),
      onMessage: (cb) => void child.on('message', cb),
      onExit: (cb) => void child.on('exit', (code) => cb(code)),
      kill: () => void child.kill(),
    };
  };
}

// ------------------------------------------------------------------ "Start V18 when I sign in to Windows" (off by default)

function loginItem(): { get(): boolean; set(on: boolean): void } {
  if (NO_SYSTEM_CHANGES) {
    let on = false; // automated tests: pretend, and leave Windows alone
    return { get: () => on, set: (v) => void (on = v) };
  }
  // Development copies start as "electron.exe <app folder>"; the installed app is V18.exe.
  const opts = () => (process.defaultApp && process.argv[1] ? { path: process.execPath, args: [path.resolve(process.argv[1]), HIDDEN_FLAG] } : { path: process.execPath, args: [HIDDEN_FLAG] });
  return {
    get: () => app.getLoginItemSettings(opts()).openAtLogin,
    set: (on) => app.setLoginItemSettings({ openAtLogin: on, ...opts() }),
  };
}

// ------------------------------------------------------------------ storage (PROTOCOL 3.10 rules are applied by the engine)

function stateFile(): string {
  return path.join(app.getPath('userData'), 'v18-state.json');
}

const store = {
  load(): unknown {
    try {
      return JSON.parse(readFileSync(stateFile(), 'utf8'));
    } catch {
      return null;
    }
  },
  save(json: string): void {
    const file = stateFile();
    mkdirSync(path.dirname(file), { recursive: true });
    const tmp = file + '.tmp';
    writeFileSync(tmp, json, { encoding: 'utf8', mode: 0o600 });
    renameSync(tmp, file);
  },
};

// ------------------------------------------------------------------ app

function start(): void {
  let engine: V18Engine;
  let mainWin: BrowserWindow | null = null;
  let askWin: BrowserWindow | null = null;
  let tray: Tray | null = null;
  let quitting = false;
  let lastView: ViewState | null = null;
  let pendingLink: string | null = findDeepLinkArg(process.argv);
  const testKeyMode = process.argv.includes(TEST_KEY_FLAG);

  const assetsDir = () => path.join(__dirname, 'assets');
  const icon = () => nativeImage.createFromPath(path.join(assetsDir(), 'icon.png'));

  const overlay = () =>
    nativeTheme.shouldUseDarkColors ? { color: '#202020', symbolColor: '#FFFFFF', height: 40 } : { color: '#F3F3F3', symbolColor: '#1B1B1B', height: 40 };

  function secureWebPreferences(): Electron.WebPreferences {
    return {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: false,
      devTools: DEBUG,
    };
  }

  function createMainWindow(): BrowserWindow {
    const win = new BrowserWindow({
      width: 1040,
      height: 700,
      minWidth: 900,
      minHeight: 620,
      show: false,
      title: 'V18',
      icon: icon(),
      backgroundColor: nativeTheme.shouldUseDarkColors ? '#202020' : '#F3F3F3',
      titleBarStyle: 'hidden',
      titleBarOverlay: overlay(),
      webPreferences: secureWebPreferences(),
    });
    win.removeMenu();
    void win.loadFile(RENDERER_HTML, { query: { view: 'main' } });
    win.once('ready-to-show', () => win.show());
    win.on('close', (e) => {
      // Closing the window keeps V18 in the system tray, so it can answer sites.
      if (!quitting) {
        e.preventDefault();
        win.hide();
      }
    });
    win.on('closed', () => {
      mainWin = null;
    });
    return win;
  }

  function showMain(): void {
    if (!mainWin) mainWin = createMainWindow();
    else {
      if (mainWin.isMinimized()) mainWin.restore();
      mainWin.show();
      mainWin.focus();
    }
  }

  function openAskWindow(): void {
    if (askWin && !askWin.isDestroyed()) {
      askWin.show();
      askWin.focus();
      return;
    }
    askWin = new BrowserWindow({
      width: 500,
      height: 640,
      resizable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      alwaysOnTop: true,
      show: false,
      title: 'V18: a site asks',
      icon: icon(),
      backgroundColor: nativeTheme.shouldUseDarkColors ? '#272727' : '#F9F9F9',
      titleBarStyle: 'hidden',
      titleBarOverlay: { ...overlay(), height: 36, color: nativeTheme.shouldUseDarkColors ? '#272727' : '#F9F9F9' },
      webPreferences: secureWebPreferences(),
    });
    askWin.removeMenu();
    void askWin.loadFile(RENDERER_HTML, { query: { view: 'ask' } });
    askWin.once('ready-to-show', () => {
      askWin?.show();
      askWin?.focus();
    });
    askWin.on('closed', () => {
      askWin = null;
      if (lastView?.ask) engine.askClose();
    });
  }

  function notifyAsk(ask: AskView): void {
    if (!engine.getSettings().notify || !Notification.isSupported()) return;
    const n = new Notification({
      title: ask.host ? `${ask.host} is asking for an age check` : 'A site is asking for an age check',
      body: "Use your age card? You'll confirm with Windows Hello.",
      icon: icon(),
    });
    n.on('click', () => openAskWindow());
    n.show();
  }

  function trayMenu(v: ViewState): Menu {
    const status = v.settings.sharedPc
      ? 'Shared PC mode is on'
      : v.card
        ? v.card.expired
          ? 'Age card expired'
          : `Age card active, until ${v.card.validUntilLabel}`
        : 'No age card yet';
    return Menu.buildFromTemplate([
      { label: 'V18', enabled: false },
      { label: status, enabled: false },
      { type: 'separator' },
      { label: 'Open V18', click: () => showMain() },
      { label: `Shared PC mode: ${v.settings.sharedPc ? 'On' : 'Off'}`, click: () => (showMain(), engine.go('settings')) },
      { label: 'Settings', click: () => (showMain(), engine.go('settings')) },
      { type: 'separator' },
      { label: 'Quit V18', click: () => ((quitting = true), app.quit()) },
    ]);
  }

  function onChange(v: ViewState): void {
    const hadAsk = !!lastView?.ask;
    lastView = v;
    for (const w of [mainWin, askWin]) if (w && !w.isDestroyed()) w.webContents.send('v18:view', v);
    if (tray) {
      tray.setContextMenu(trayMenu(v));
      tray.setToolTip(v.card && !v.settings.sharedPc ? `V18: age card until ${v.card.validUntilLabel}` : 'V18');
    }
    if (hadAsk && !v.ask && askWin && !askWin.isDestroyed()) askWin.close();
  }

  async function makeQr(text: string): Promise<string> {
    const svg = await QRCode.toString(text, { type: 'svg', errorCorrectionLevel: 'M', margin: 1, color: { dark: '#000000', light: '#FFFFFF' } });
    return 'data:image/svg+xml;base64,' + Buffer.from(svg, 'utf8').toString('base64');
  }

  function handleLink(raw: string): void {
    // Coming back from a login in the browser: show the main window with the result.
    if (/^v18:\/\/connect\b/i.test(raw.trim())) showMain();
    void engine.handleDeepLink(raw);
  }

  app.on('second-instance', (_e, argv) => {
    const link = findDeepLinkArg(argv);
    if (link) handleLink(link);
    else showMain();
  });

  app.on('web-contents-created', (_e, contents) => {
    contents.on('will-navigate', (e) => e.preventDefault());
    contents.on('will-redirect', (e) => e.preventDefault());
    contents.on('will-attach-webview', (e) => e.preventDefault());
    contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  });

  app.on('before-quit', () => {
    quitting = true;
    engine?.shutdown();
  });
  app.on('window-all-closed', () => {
    // Stay in the tray.
  });

  void app.whenReady().then(async () => {
    registerProtocol();
    const ses = session.defaultSession;
    ses.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
    ses.setPermissionCheckHandler(() => false);
    // Pages may load only their own local files. The page never talks to the network.
    ses.webRequest.onBeforeRequest((details, cb) => {
      const u = details.url;
      cb({ cancel: !(u.startsWith('file://') || u.startsWith('data:') || u.startsWith('devtools://')) });
    });

    const { addon, error } = process.platform === 'win32' ? loadHelloAddon() : { addon: null, error: 'Windows Hello needs Windows.' };
    engine = new V18Engine({
      debug: DEBUG,
      store,
      hello: new HelloKeyProvider(addon, error),
      testKeys: testKeyMode ? new TestSoftwareKeyProvider() : null,
      ageConsent: addon ? () => addon.ageConsentGroup() : undefined,
      assetsDir: assetsDir(),
      artifacts: new ArtifactStore(path.join(app.getPath('userData'), 'artifacts', ARTIFACT_SET)),
      spawnProver: electronProverSpawner(),
      loginItem: loginItem(),
      // Login connectors (4d.4) open the provider's page in the person's own browser, never in V18.
      openExternal: (url) => shell.openExternal(url),
      localeCountry: (() => {
        try {
          return app.getLocaleCountryCode() || null;
        } catch {
          return null;
        }
      })(),
      extraServerOrigins: TEST_SERVER ? [TEST_SERVER] : undefined,
      serverOverride: TEST_SERVER ? TEST_SERVER + '/v1' : undefined,
      makeQr,
      onChange,
      onAsk: (ask) => {
        openAskWindow();
        notifyAsk(ask);
      },
    });
    registerIpc(engine);

    tray = new Tray(nativeImage.createFromPath(path.join(assetsDir(), 'icon.ico')));
    tray.setToolTip('V18');
    tray.on('click', () => showMain());
    tray.setContextMenu(trayMenu(engine.getView()));

    nativeTheme.on('updated', () => {
      for (const w of [mainWin, askWin]) {
        if (w && !w.isDestroyed()) {
          w.setTitleBarOverlay(w === askWin ? { ...overlay(), height: 36, color: nativeTheme.shouldUseDarkColors ? '#272727' : '#F9F9F9' } : overlay());
          w.setBackgroundColor(nativeTheme.shouldUseDarkColors ? '#202020' : '#F3F3F3');
        }
      }
    });

    // Opened by a link? Answer the site; otherwise show the app.
    // Opened by a site's link: show only the site-asks dialog. Opened normally: show the app.
    if (!pendingLink && !process.argv.includes(HIDDEN_FLAG)) showMain();
    await engine.init();
    if (pendingLink) {
      handleLink(pendingLink);
      pendingLink = null;
    }
  });

  // ------------------------------------------------------------------ IPC (small allowlist; every argument checked)

  function registerIpc(e: V18Engine): void {
    const fromOurPage = (ev: IpcMainInvokeEvent) => {
      const url = ev.senderFrame?.url ?? '';
      return url.split('?')[0] === RENDERER_URL;
    };
    const handle = (channel: string, fn: (ev: IpcMainInvokeEvent, arg: unknown) => unknown) => {
      ipcMain.handle(channel, async (ev, arg) => {
        if (!fromOurPage(ev)) throw new Error('refused');
        return fn(ev, arg);
      });
    };
    const bool = (v: unknown) => v === true;

    handle('v18:get-view', () => e.getView());
    handle('v18:first-run', (_ev, shared) => e.firstRun(bool(shared)));
    handle('v18:go', (_ev, screen) => (typeof screen === 'string' ? e.go(screen) : undefined));
    handle('v18:start-link', (_ev, label) => e.startLink(typeof label === 'string' ? label.slice(0, 80) : undefined));
    handle('v18:start-connector', (_ev, id) => (typeof id === 'string' ? e.startConnector(id) : undefined));
    handle('v18:cancel-connect', () => (e.cancelConnect(), e.go('card-methods')));
    handle('v18:connect-reopen', () => e.connectReopen());
    handle('v18:load-catalog', () => e.loadCatalog());
    handle('v18:cancel-link', () => (e.cancelLink(), e.go('card-methods')));
    handle('v18:test-card', (_ev, kind) => e.issueTestDev(kind === 'under18' ? 'under18' : 'adult'));
    handle('v18:delete-card', (_ev, localOnly) => e.deleteCard(bool(localOnly)));
    handle('v18:settings', (_ev, patch) => {
      if (!patch || typeof patch !== 'object') return;
      const p = patch as Record<string, unknown>;
      return e.setSettings({ notify: p.notify, sharedPc: p.sharedPc, startWithWindows: p.startWithWindows });
    });
    handle('v18:dismiss-notice', () => e.dismissNotice());
    handle('v18:refresh-server', () => e.refreshServer());
    handle('v18:aadhaar-pick', async (ev) => {
      const win = BrowserWindow.fromWebContents(ev.sender) ?? undefined;
      const res = await dialog.showOpenDialog(win!, {
        title: 'Choose your Aadhaar QR',
        properties: ['openFile'],
        filters: [
          { name: 'QR picture or QR text', extensions: ['png', 'jpg', 'jpeg', 'txt'] },
        ],
      });
      if (res.canceled || !res.filePaths[0]) return;
      await e.aadhaarReadFile(res.filePaths[0]);
    });
    handle('v18:aadhaar-build', () => e.aadhaarBuild());
    handle('v18:aadhaar-cancel', () => e.aadhaarCancel());
    handle('v18:aadhaar-reset', () => e.aadhaarReset());
    handle('v18:delete-proof-files', () => e.deleteProofFiles());
    handle('v18:ask-approve', () => e.askApprove());
    handle('v18:ask-phone', () => e.askUsePhone());
    handle('v18:ask-back', () => e.askBackToConfirm());
    handle('v18:ask-retry', () => e.askRetry());
    handle('v18:ask-close', () => e.askClose());
    handle('v18:ask-get-card', () => (e.askGetCard(), showMain()));
    handle('v18:open-main', (_ev, screen) => (showMain(), typeof screen === 'string' ? e.go(screen) : undefined));
    handle('v18:open-hello-settings', () => shell.openExternal('ms-settings:signinoptions'));
  }
}
