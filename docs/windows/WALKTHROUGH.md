# V18 for Windows: walkthrough (protocol v1.3)

V18 for Windows is a desktop app (Electron + TypeScript, no Java, no .NET) in `windows/`.
It keeps a device-bound **age card** on the PC, locked by **Windows Hello**, and answers websites
that ask "are you 18+?" with a one-time, unlinkable **ticket** (RFC 9474 blind signatures).
App ID `com.v18.desktop`, name "V18", deep links `v18://`, version 0.2.0.

Screenshots of the real app are in [`screenshots/`](screenshots/) (made by the smoke test).

---

## 1. Install and run

### From source (developers)

You need Node 22. Rust (`cargo`) and Visual Studio Build Tools are needed only to rebuild the
Windows Hello helper; a built copy is already in `windows/native/v18-hello/v18_hello.node`.

```bash
cd windows
npm install
npm start
```

`npm start` builds everything into `dist/` and opens V18 (a **debug build**: it trusts the dev
server `http://localhost:8080`). It also registers `v18://` for your Windows user, pointing at this
development copy. To remove that later: `npx electron . --v18-unregister-protocol`.

| Command | What it does |
|---|---|
| `npm test` | Unit and flow tests (no server needed) |
| `npm run hello:check` | Tries Windows Hello for real: makes a test key, signs, checks RS256, asks about the TPM, deletes the key |
| `npm run test:smoke` | Opens the real app and clicks through it, saving screenshots (run `npm run build` first) |
| `npm run test:e2e` | Against the real server (`npm run dev --prefix server`; run `npm run build` first). Parts the server can't do yet are skipped with a message |
| `npm run dist:release` | Release installer `release/V18-Setup-0.2.0.exe` (trusts only the production server) |
| `npm run dist` | Debug installer (trusts `localhost:8080` too) |
| `npm run test:installer` | Installs the installer for real, checks it, uninstalls it (section 6) |
| `npm run test:live-connector` | A FranceConnect login through your **system browser**, against its own V18 server on port 8091 (server code, mock provider); see section 8 |
| `npm run typecheck` | TypeScript check |

### Set up Windows Hello (needed once)

V18 keeps its key in Windows Hello. Without it, V18 shows "Windows Hello isn't set up" and saves
nothing. To set it up:

1. Press the Windows key, type **Sign-in options**, and press Enter
   (or open **Settings > Accounts > Sign-in options**).
2. Under "Ways to sign in", choose **PIN (Windows Hello)**, then **Set up**.
3. Type your Windows password if asked, then choose a PIN. Face or fingerprint is optional.
4. In `windows/`, run **`npm run hello:check`**. Approve the two Windows Hello prompts (they may
   open behind other windows). You should see "RS256 check: PASSED" and "All good".

On this PC (2026-11-23) the check passed for real: an RSA-2048 key made by Windows Hello, a 256-byte
RS256 signature that verified, and Windows reported the key as **TPM-backed and attested**.

---

## 2. Using the app

1. **First run: "Who uses this PC?"** "Just me" keeps an age card here. "Family or shared PC" turns
   on **Shared PC mode**: no card is ever saved, and every site visit uses your phone.
2. **Get an age card.** First pick your country. The list of countries, and the IDs that work in
   each, come from the V18 server (`GET /v1/catalog`), so V18 for Windows has **no built-in
   country list**. Your PC's Windows region is pre-selected. Then the app shows, most private first:
   - **On this PC**
     - **Aadhaar QR** (India). Import a picture of your Aadhaar Secure QR (PNG or JPG; for an
       e-Aadhaar PDF, take a screenshot of its QR) or a `.txt` with the QR number. V18 checks
       UIDAI's seal on this PC, then **builds a real Anon Aadhaar zero-knowledge proof** that says
       only "18+". The first time, it downloads the proof files (about 620 MB) from the V18 server
       and checks each one's SHA-256. The proof takes about 20 seconds on this PC; you see each
       step and a progress bar with the time so far, and you can cancel.
     - **Government or bank login** (for example DigiLocker, Singpass, FranceConnect), only when
       the server has that login set up. V18 opens the provider's own page in **your web browser**.
       You sign in there; the browser then asks to open V18, and the card is saved. V18's server
       sees your birth date for a moment to decide "18+" and keeps nothing.
   - **With your phone**: IDs that need the phone (passport or ID card chips, PhilSys QR, My Number
     Card, wallet IDs). Picking one opens the **phone link**: approve Windows Hello, and a QR code
     appears for 2 minutes. On your phone, make an age card with that ID (if you haven't), tap
     **Make a card for a PC**, scan, and approve. The PC saves its own card, bound to its own key.
   - **I already have an age card on my phone**: the same phone link.
   - **TEST card**: only when the server is in TEST MODE (developers).
3. **A site asks.** On a website, choose "This PC" in the V18 widget. The browser opens a
   `v18://verify?...` link and V18 shows a dialog: which site is asking, what it gets ("18+: yes"
   and a one-time ticket) and what it never gets. Click **Send 18+ ticket**, approve Windows Hello,
   and you see **Ticket sent**. No card, or Shared PC mode? V18 shows a QR for your phone instead.
4. **Tray icon.** Closing the window keeps V18 in the system tray, so it can answer sites.
5. **Settings:** delete card (turned off on the server with a signed request, key removed from
   Windows Hello), Shared PC mode, **Start V18 when I sign in to Windows** (off by default; V18
   then starts quietly in the tray), notifications, Windows Hello status, **Aadhaar proof files**
   (delete them to free 620 MB), what V18 never stores, and the server address.
6. **Error screens:** Windows Hello / PC security, ID seal didn't check out, offline, under 18,
   child account, proof couldn't be built, proof files couldn't be downloaded, sign-in didn't finish.

---

## 3. How it works inside

```
 browser --v18://verify | v18://connect--> Windows --> V18 main process (one instance)
                                                        |  checks links, allowlist, sessions
 V18 windows (sandboxed pages) <-- view state only -----+
   buttons --> window.v18.invoke(<fixed channel>) ----> engine (flows)
                                                        |-- Windows Hello (Rust addon): RS256
                                                        |-- proof builder (utility process):
                                                        |     Anon Aadhaar inputs + snarkjs Groth16
                                                        |-- proof files: download, SHA-256, cache
                                                        `-- V18 server (fetch, main process only)
```

| Part | File |
|---|---|
| Windows Hello helper (Rust, napi-rs, `windows` crate) | `windows/native/v18-hello/src/lib.rs` |
| Device keys (Hello provider, TEST software provider) | `windows/src/main/keys.ts` |
| Flows: phone link, Aadhaar, login connectors, TEST card, ticket, delete, catalog | `windows/src/main/engine.ts` |
| Aadhaar QR reading and UIDAI seal check | `windows/src/main/aadhaar.ts`, certificates in `windows/assets/aadhaar/` |
| Proof files (manifest, pins, download, resume, cache) | `windows/src/main/artifacts.ts`, `windows/src/shared/artifact-pins.ts` |
| Proof builder and its host | `windows/src/prover/worker.ts` (bundled as `dist/prover.cjs`), `windows/src/main/prover-host.ts` |
| Country catalog | `windows/src/shared/catalog.ts` |
| Electron main: windows, tray, protocol, start-up item, IPC | `windows/src/main/main.ts` |
| Preload bridge (2 functions, fixed channel list) | `windows/src/preload/preload.ts` |
| Screens | `windows/src/renderer/*.ts`, `v18.css`, `app.css` |
| Protocol v1 client, signing strings, JWK thumbprint, tickets, deep links, allowlist, storage | `windows/src/shared/*.ts` |

### Aadhaar on this PC (PROTOCOL 3.5, 4b, 4c.1)

1. **Read the QR** (`aadhaar.ts`): decode the picture (jsQR), unpack the number, check it is a V2
   Secure QR, and check the RSA seal with Node's crypto against **UIDAI's public key**
   (`uidai-offline-publickey-2021.cer`, the key the Anon Aadhaar v2 circuit accepts). Only when the
   server is in TEST MODE does V18 also trust the **Anon Aadhaar TEST key**
   (`anon-aadhaar-test-certificate.pem`). Under-18 and changed QRs stop here. The QR text stays in
   main-process memory only, for at most 10 minutes, and is dropped as soon as the proof is made
   or you leave the screen.
2. **Proof files** (`artifacts.ts`): `GET /v1/artifacts/manifest`, then each file from
   `GET /v1/artifacts/<name>`. Every file must match the SHA-256 **pinned in the app**, as well as
   the manifest, so a broken or changed server can't make the app run other circuit files:

   | File | Bytes | SHA-256 |
   |---|---|---|
   | `aadhaar-verifier.wasm` | 10,469,686 | `4894923663fafda95beb70abca4112ea97a62058c9a46419a274f04236f10d4f` |
   | `circuit_final.zkey` | 612,082,146 | `0d443ea85279b0370b53202f5e768ca9098cfcb5bb14f8ca8323d2266822c492` |
   | `vkey.json` | 4,388 | `40f2ea24b56ffe2b6e6e3578053cbda15e773cb560697bac883a404077fcf177` |

   These are the official Anon Aadhaar v2.0.0 files; the same hashes were measured independently
   on the server's copy and on downloads from the official host. Files are hashed while they
   download, saved only when the hash matches, resumed with HTTP Range after a break, kept in
   `%APPDATA%\V18\artifacts\anon-aadhaar-v2.0.0\`, and hashed again the first time they are used
   in each run. V18 checks there is enough disk space first.
3. **Windows Hello**: make the card's key (prompt 1), get a challenge, sign the issue-card string
   (prompt 2). Both prompts happen before the long step, so you can walk away during the proof.
4. **Proof** (`prover/worker.ts`, in an Electron **utility process**, never in a window): circuit
   inputs from `generateArgs` of `@anon-aadhaar/core` (reveal only "age above 18", signal =
   `"0x" + hex(SHA-256(challenge + "|" + thumbprint))`, nullifier seed from `/v1/health`), then
   snarkjs `wtns.calculate` and `groth16.prove`, then V18 checks the proof itself with the pinned
   `vkey.json` before sending it. The progress bar follows snarkjs's own stages (calibrated on a
   real run). Time limit 15 minutes; a crash or out-of-memory shows a plain error.
5. `POST /v1/card/issue` with `method: "anon_aadhaar"` and the proof object (the same shape as
   `AnonAadhaarCore`), then the card is saved.

**Measured on this PC:** about **20 seconds** for a proof: 19.7 to 23.7 s in Node over seven runs
(witness about 2 s, Groth16 about 18 to 21 s), 26 to 27 s inside the real app's utility process,
and 20.2 s for the proof the real server accepted.

### Login connectors (PROTOCOL 4d.4)

1. Windows Hello makes the key and signs `v18-card-issue\n<challenge>\n<thumbprint>`.
2. `POST /v1/connect/<id>/start` returns the provider's `authUrl` (and `state`). V18 opens it in the
   **system browser** only if it is `https://` (plain `http://` only to this PC, in debug builds).
3. After the sign-in, the server sends the browser to `v18://connect?status=...`. V18 **does not
   trust that link** (any web page could open one): it asks `GET /v1/connect/session/<state>` and
   saves the card only from the server's answer. It also asks every 2 seconds, so the card arrives
   even if the browser never comes back to V18.
4. Only connectors the server's catalog lists are shown or can be started.

### Windows Hello (PROTOCOL 3.4)

- The Rust addon calls `Windows.Security.Credentials.KeyCredentialManager`:
  `RequestCreateAsync` (RSA-2048), `RetrievePublicKey`, `RequestSignAsync` (**RS256**), `DeleteAsync`
  and `GetAttestationAsync` (TPM). Windows shows its own prompt for key creation and **every**
  signature. V18 checks every Hello signature with the public key before sending it.
- **No silent fallback.** A software key exists only with `--v18-test-software-key`, and then every
  window shows a red **TEST KEY** banner.
- Fixed: deleting a key that Windows had already removed returned a raw Windows error
  (`0x8009000D`); it now counts as "already gone". Found by the real-helper test.

### Security settings

- Every window: `contextIsolation`, `sandbox` (plus `app.enableSandbox()`), no Node, no webview,
  navigation and new windows blocked, all permission requests refused, every non-`file:` request
  cancelled, strict CSP with Trusted Types and no inline scripts or styles.
- The preload exposes only `window.v18.invoke(channel, arg)` for a fixed list of channels and
  `window.v18.onView(cb)`. The main process checks the sender and every argument.
- All network calls are made by the main process. The proof builder is a separate process.
- **Server allowlist** (PROTOCOL 3.10, 4b item 9, 4c.7): the production server URL comes from the
  build (`V18_PRODUCTION_SERVER`, default placeholder `https://api.v18.example`). **Release builds
  trust only that URL. Debug builds trust `http://localhost:8080` plus that URL.**

### What is stored (PROTOCOL 3.10)

`%APPDATA%\V18\v18-state.json`: card ID, method, valid-until date, the Hello key's name, the server
URL, and settings (first run done, Shared PC mode, notifications). It is rebuilt from an allowlist
before every save. The public Aadhaar proof files are cached in `%APPDATA%\V18\artifacts\`. No
names, birth dates, ID data, QR codes, proofs, tickets or site history are ever stored or logged.

---

## 4. Release build

```bash
cd windows
set V18_PRODUCTION_SERVER=https://api.your-domain.example   # optional; default https://api.v18.example
npm run dist:release
```

The build refuses a production URL that isn't a plain `https://` origin. The installer is
`release/V18-Setup-0.2.0.exe` (121.9 MB). It installs for the current user only (no admin), adds
Start menu and desktop shortcuts, registers `v18://` (`build/installer.nsh`), and its uninstaller
removes `v18://` and the "start with Windows" entry.

---

## 5. Code signing (needs a certificate you buy)

The installer is **not code-signed**, so Windows SmartScreen warns ("Windows protected your PC";
choose "More info", then "Run anyway"). To sign it:

1. **Buy a code-signing certificate.** Options: an OV certificate (about USD 200 to 400 a year;
   since June 2023 the key must live on a hardware token or a cloud HSM), an EV certificate
   (dearer, builds SmartScreen trust faster), or Microsoft's Azure Trusted Signing (monthly fee;
   identity checks apply). The certificate must be in the name of a person or company that the
   issuer verifies.
2. **Install signtool**: it comes with the Windows SDK ("Windows SDK Signing Tools for Desktop Apps").
3. **Sign during the build** (recommended, so `V18.exe`, the uninstaller and the installer are all
   signed): with the token plugged in, add to `windows/electron-builder.yml`:

   ```yaml
   win:
     signtoolOptions:
       certificateSubjectName: "Your Name or Company"   # as written in the certificate
       signingHashAlgorithms: [sha256]
       rfc3161TimeStampServer: http://timestamp.digicert.com
   ```

   then run `npm run dist:release`.
4. **Or sign by hand** afterwards:

   ```bash
   signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a release\win-unpacked\V18.exe
   ```

   then rebuild the installer, and sign `release\V18-Setup-0.2.0.exe` the same way.
5. **Check it:** `signtool verify /pa /v release\V18-Setup-0.2.0.exe`, or right-click the file >
   Properties > Digital Signatures.

Never put the certificate or its password in the project folder.

---

## 6. Installer test (done for real)

`npm run test:installer` (`windows/test/installer/installer.test.ts`) uses the real release
installer. Result on this PC (2026-11-23, run three times, the last on the final release build),
**5 of 5 passed** each time:

| Step | What happened |
|---|---|
| Silent install | `V18-Setup-0.2.0.exe /S /D=%TEMP%\v18-install-test`, exit code 0 in 7.9 to 8.5 s. `V18.exe`, `app.asar`, the unpacked Hello helper and `Uninstall V18.exe` are there |
| Registration | `HKCU\Software\Classes\v18\shell\open\command` = `"...\v18-install-test\V18.exe" "%1"`; Start menu and desktop shortcuts; uninstall entry in Settings > Apps |
| `v18://` link | A `v18://verify?...` link opened through Windows (`start`) started the **installed** V18, which opened its "V18: a site asks" window |
| Installed app | It reports `isPackaged: true`; its proof builder starts from inside `app.asar` in a utility process and answers; Settings shows only the production server and no TEST MODE; "Start V18 when I sign in to Windows" is off by default, and turning it on wrote `"...\V18.exe" --v18-hidden` to `HKCU\...\Run` (value `com.v18.desktop`) |
| Silent uninstall | `Uninstall V18.exe /S`, exit 0, finished in 4.8 to 5.0 s: app folder, shortcuts, uninstall entry, `v18://` key and the start-up entry are all gone |

The test then puts back the `v18://` registration that was there before (the development copy's).

---

## 7. Auto-update plan (not built)

1. Use `electron-updater` with the **generic HTTPS provider**: the release build publishes
   `latest.yml`, the installer and its `.blockmap` (already generated) to a static folder on the
   V18 domain, for example `https://downloads.v18.example/windows/`.
2. V18 checks at start and every 6 hours, downloads in the background (block map = only the
   changed parts), shows "Update ready: restart V18", and installs when V18 quits.
3. Only **code-signed** builds: electron-updater checks that the new installer is signed by the same
   publisher (`publisherName`) before running it. So this waits for section 5.
4. The update feed adds no tracking: no device ID is sent.

---

## 8. Tests (real counts, final run 2026-11-24, dev server 0.3.0 / protocol 1.3)

| Suite | Result |
|---|---|
| `npm test` (unit and flow tests, incl. real-helper tests of Windows Hello without prompts) | **130 of 130 passed** |
| `npm run test:smoke` (real app; Aadhaar with the real files and the real proof builder in the app; Singpass round trip through a second launch, against the protocol mock) | **3 of 3 passed** (proof in the app: 22 to 27 s) |
| `npm run test:e2e` against the **real dev server** | **15 of 15 passed** (details below) |
| `npm run test:live-connector` (FranceConnect through the system browser) | **2 of 2 passed** |
| `npm run test:installer` (real install, `v18://`, uninstall; final release build) | **5 of 5 passed** (install 8.4 s, uninstall 4.9 s) |
| `npm run hello:check` (real Windows Hello: key, RS256 signature, TPM) | **Passed** (key in 9.3 s, RS256 verified, TPM-backed and attested) |

**Live e2e, 15 tests:**
- `aadhaar.e2e.ts` (3): a real proof checked by `@anon-aadhaar/core`'s `verify()`; the real server
  **accepted** a real proof (21.7 s) and issued an `anon_aadhaar` card (assurance `test`, TEST QR),
  which made a ticket that verified with the JWKS, then a signed delete; and the whole app flow
  (files downloaded from `GET /v1/artifacts/*` and checked, proof, card, ticket, delete) in 23.1 s.
- `catalog.e2e.ts` (2): the engine and the real app build the country and method screens from the
  live `GET /v1/catalog`. The server's `?platform=windows` answer has 1 country (India, Aadhaar);
  joined with `?platform=android`, the app shows **49 countries**, 1 "on this PC" row and 66
  "with your phone" rows, and every row is a method `GET /v1/health` says is `ready`.
- `app.e2e.ts` (1) and `server.e2e.ts` (9): the phase 1 checks (TEST card with RS256 and ES256,
  ticket verified and delivered once, device link, under 18, signed delete, Shared PC mode revoke,
  revoked card refused, tampered link refused, and the real app answering a `v18://verify` link).

**Live connector (`test/live/connector.live.ts`):** the shared dev server has no connector
credentials (connectors stay hidden until a provider registration exists), so the test starts its
**own** V18 server on `127.0.0.1:8091` from `server/src` (in-memory database, temp folder) with the
real FranceConnect connector from `@v18/connectors`, pointed at the
`oidc-provider` mock, exactly as the server's own tests do. The shared :8080 server is not touched.
The real app picked France > FranceConnect and opened the login with the real `shell.openExternal`:
the **default web browser** ran the login (the mock signed in a made-up adult), the server issued a
`connector:franceconnect` card, and the app saved it **2.6 s** after the click. Nobody answered the
browser's "open V18?" prompt during the run, so the app's session poll finished the login (the
designed fallback). The card then made a ticket that verified with the JWKS. When "Open" was
clicked later, after the test had ended, Windows started the normal V18, which refused the link
because it wasn't waiting for a login: the forged-link protection, seen for real.

---

## 9. Not in v1 (removed from the Windows app, PROTOCOL 4c)

- **USB NFC reader** for passports and ID cards: there's no vetted JavaScript eMRTD library. Windows
  users add passports and chip ID cards through the phone link.
- **Face estimate on the PC**: no hardware attestation on Windows in v1.
- **Phone wallet ID inside the PC app**: wallets are a website widget feature (`mdoc_wallet`).
- **Webcam QR scanning**: import a picture of the QR instead.
- **Reading the e-Aadhaar PDF directly**: it is password-protected; take a screenshot of its QR.
- **Choosing the card length** (6 or 12 months): the server decides (PROTOCOL 4b item 11).
- **Auto-update** (planned, section 7) and **code signing** (needs a certificate, section 5).

---

## 10. Not tested yet

- **A real (non-TEST) Aadhaar QR.** Only TEST QRs (Anon Aadhaar TEST key) were used, as the
  protocol requires; the production path uses the same code with UIDAI's key.
- **A real government or bank login.** Every connector needs the user's own registration with the
  provider; the live test used FranceConnect's mock. The browser-to-V18 hand-over after a login was
  tested with a second launch (smoke test); in the live run the poll finished first.
- **The full Aadhaar flow with the real Windows Hello prompts** in one run (the e2e tests use RS256
  keys in memory; `V18_REAL_HELLO=1 npm run test:e2e` uses the real Windows Hello, with prompts).
  Windows Hello itself was exercised for real by `npm run hello:check`.
- **A real phone** for the device link (the tests play the phone).
- **Code signing and auto-update** (see above).

---

## 11. Design notes (where the protocol was unclear, and what the Windows app did)

1. **Connect start signing string (4d.4)** isn't given. Windows signs the issue-card string
   `v18-card-issue\n<challenge>\n<thumbprint>`, as `link/start` does (3.9).
2. **`/v1/catalog?platform=windows` (4d.2)** drops phone-only methods (confirmed live: it lists
   only India). Windows asks for `platform=windows` and `platform=android` and joins them, so
   phone-only IDs are listed as "with your phone". Web-only methods are not shown on the PC.
   The catalog can list one method twice with different documents (France: `emrtd_attested` as
   "Passport (chip)" and "ID card (chip)"); the app keeps both (a bug found by the live catalog).
3. **Catalog draft**: VN, PK, LK, SA and KW have no methods yet, so the PC hides them (4d.2 says
   every chip-passport country gets `emrtd_attested`).
4. **`v18://connect` (4d.4)** can be opened by any web page, so the app treats it only as "check
   now" and takes the card from `GET /v1/connect/session/:state`. The server hands the card out
   once (later `cardDelivered: true`); if that answer is lost, the app says so and asks to try
   again. Error codes (`NULLIFIER_OVERUSED`, `MISSING_BIRTHDATE`, ...) are shown in plain words.
   On the shared dev server no connector is configured, so live connector tests need their own
   server (section 8).
5. **Artifact pins (4c.1)**: besides the manifest's hashes, the app pins the three hashes itself.
6. **UIDAI's key**: the bundled certificate (the one Anon Aadhaar v2 accepts) expired as a
   certificate in Feb 2024, but its key is what the circuit checks. If UIDAI changes its key, the
   app, the circuit files and the server all need an update together.
7. **The 5-minute challenge (3.3)** must cover the proof time. About 20 s here; a very slow PC could
   run out, and then V18 says so plainly.
8. **Debug allowlist (4b item 9)**: Windows now trusts only `http://localhost:8080` in debug builds
   (the Android emulator address `10.0.2.2:8080` was removed).
9. Earlier notes from phase 1 still apply: `server=` with or without `/v1`; verify links without
   `server=` use the saved server; the PC never polls a pairing session (the ticket is handed out
   once); ticket key = lowest `v18_min_age` at or above the site's age, current, newest.
