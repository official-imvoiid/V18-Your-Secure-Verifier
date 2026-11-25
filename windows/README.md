# V18 for Windows

Electron + TypeScript desktop app. Keeps an age card locked by **Windows Hello** and sends
websites one-time 18+ tickets (RFC 9474 blind signatures). It can make the age card on this PC
from an **Aadhaar QR** (a real Anon Aadhaar zero-knowledge proof, built here) or a **government
or bank login**, or get it from the phone (device link). The full guide is
[`docs/windows/WALKTHROUGH.md`](../docs/windows/WALKTHROUGH.md).

```bash
npm install
npm start               # build and run (debug build, trusts http://localhost:8080)
npm test                # unit and flow tests
npm run hello:check     # try Windows Hello for real (make key, sign, TPM check, delete)
npm run build && npm run test:smoke   # drives the real app, saves screenshots to docs/windows/screenshots
npm run build && npm run test:e2e     # against the real server (npm run dev --prefix server)
npm run dist:release    # release installer: release/V18-Setup-0.2.0.exe (production server only)
npm run test:installer  # installs it for real, checks v18://, uninstalls
```

| Folder | What |
|---|---|
| `native/v18-hello/` | Rust (napi-rs + `windows` crate) Windows Hello helper: `KeyCredentialManager` keys, RS256 signing, TPM attestation, Windows age group |
| `src/shared/` | Protocol v1: API client, signing strings, JWK thumbprint, tickets, deep links, allowlist, storage rules, catalog, artifact pins |
| `src/main/` | Electron main process: flows (`engine.ts`), keys, Aadhaar QR reading, proof files, proof builder host, windows, tray, IPC |
| `src/prover/` | The proof builder (`dist/prover.cjs`): Anon Aadhaar inputs + snarkjs Groth16, run in a utility process |
| `src/preload/` | The two-function bridge the page gets (`window.v18`) |
| `src/renderer/` | Screens |
| `assets/aadhaar/` | UIDAI's public seal certificate and the Anon Aadhaar TEST certificate |
| `test/` | Unit and flow tests, protocol mock server, smoke, e2e and installer tests, TEST fixtures |
| `build/` | Installer icon and NSIS include (`v18://` and start-up entry) |

Flags: `--v18-test-software-key` (TEST key, no Windows Hello, red banner), `--v18-profile=<folder>`
(separate data folder), `--v18-no-protocol` (automated tests: don't touch the `v18://`
registration or the start-up list), `--v18-unregister-protocol` (remove `v18://`),
`--v18-hidden` (start in the tray; added by "Start V18 when I sign in to Windows"), and in debug
builds only `--v18-test-server=http://127.0.0.1:<port>` (used by the smoke test).
