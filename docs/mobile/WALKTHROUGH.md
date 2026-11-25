# V18 Android app (Flutter): walkthrough (protocol v1.3)

The app lives in `mobile/`: Flutter for Android, application ID `com.v18.app`, name "V18",
built in Material 3 with the V18 teal theme. Protocol: `PROTOCOL.md`
sections 3, 4b, 4c and 4d. Release builds and the signing key: [RELEASE.md](RELEASE.md).

## 1. Status at a glance

| Part | Status |
|------|--------|
| Country and method screens | **From the server's `GET /v1/catalog?platform=android`.** No country list in the app. Methods sorted by privacy (4d.1); a method shows only if the catalog lists it AND this phone and build can really do it |
| `anon_aadhaar`: real zero-knowledge proof on the phone | **Built and run on the emulator.** Native Rust prover (ark-circom + ark-groth16) with the official Anon Aadhaar v2 files from `GET /v1/artifacts/*`, SHA-256 checked and cached. Proof made on the emulator in **12 to 14 seconds** (12.0 s in the last full app run); snarkjs and `@anon-aadhaar/core` `verify()` accept it; the dev server issued a card |
| `emrtd_attested` (passports, ID cards, residence permits) | **Built.** MRZ (camera OCR or typed) or the card's 6-digit CAN for PACE; dmrtd reads the chip (PACE or BAC); passive authentication up to a CSCA from the bundled **BSI CSCA Master List** (609 country certificates, 121 countries); Active Authentication (EC) checked; attested Keystore keys; nullifier through the server's deterministic blind signature. **Run on the emulator with the TEST chip simulator** (no NFC there). A real chip read needs a real phone |
| `mdoc_app` (a wallet ID on the same phone) | **Built** (Android Credential Manager, asks only `age_over_18`). Tested with a fake wallet in widget tests. **Not run end to end**: no wallet app with an ID exists on the emulator |
| Login connectors (`connector:<id>`) | **Built** (Custom Tab + `v18://connect` + server poll). Shown only when the catalog lists one; the dev server has none configured, so none show. Tested against the fake server |
| `philsys_qr_attested` | **Not in the app.** PSA gives its public key and QR format only to relying parties on request; they are not publicly documented (4d.3 says to leave it out then) |
| `mynumber_attested` | **Not in the app** (section 5). The server's catalog lists it for Japan; the app hides it, so Japan shows the passport only |
| `face_estimate` | **Removed.** No face model meets the safety bar (PROTOCOL.md 4c.6). The app never shows face; the gate (`AppCapabilities.faceModel`) is off |
| Play Integrity | **Off and hidden** (4c.3). No screen, no switch. Only a build with `--dart-define=V18_PLAY_INTEGRITY` could turn it on, and the v1 server does not check verdicts |
| `test_dev` card, website tickets (QR or `v18://verify`), device link, delete card, settings | Run on the emulator against the dev server (section 2) |
| Release build | APK (120 MB) and AAB (89 MB), signed with the upload key in `C:\Users\voiid\.v18-keys\`, R8 on, server URL set at build time |
| "stub", "coming soon", "not available yet" in the UI | **None left** |

## 2. Checks that were run

From `mobile/`:

```
flutter analyze                                   -> No issues found
flutter test                                      -> 198 passed, 15 skipped (the 14 live-server tests
                                                     and the PC prover check need extra setup, below)
V18_LIVE_SERVER=http://localhost:8080 (+ prover vars) flutter test test/integration -> 14 passed
flutter drive --driver=test_driver/integration_test.dart \
  --target=integration_test/app_flow_test.dart -d emulator-5554       -> 9 of 9 passed
flutter test integration_test/aadhaar_prover_test.dart -d emulator-5554 -> 1 passed
flutter build apk --release / flutter build appbundle --release       -> built, signed
```

**Emulator:** Android 16 (API 36) Google APIs x86_64 image, AVD `v18_api36` (Pixel 7 profile,
8 GB RAM, 8 cores), installed with Google's `sdkmanager`. Hardware acceleration: Windows
Hypervisor Platform (WHPX). The emulator has a TEST screen-lock PIN (`1234`); during the
automated run `tool/emulator_unlock_helper.sh` types it whenever Android shows its unlock
screen, because a test cannot tap that system screen.

**What ran on the emulator against the real dev server (`http://10.0.2.2:8080`)**, in
`integration_test/app_flow_test.dart` (screenshots in [screenshots/](screenshots/)):

1. Onboarding (3 pages) to the empty home screen, with the TEST MODE strip.
2. Countries and methods built from the server's catalog; India shows Aadhaar QR and
   Passport (chip), and the chip method says "This phone has no NFC" on the emulator.
3. A `test_dev` card: real Android Keystore key, real unlock prompt, card issued.
4. A website ticket through a `v18://verify` deep link from a real pairing session: unlock,
   blind signature, submit; the test then checks the ticket like a website (RSA-PSS
   signature with the JWKS key, origin, challenge, `minAge`).
5. A device link: the test plays the PC (software key), the phone approves, the server
   hands the PC its card.
6. **Aadhaar with a real proof:** the official files downloaded from the server
   (622 MB in 66 s over the emulator's link to the PC), each SHA-256 checked, proof made on the phone, card issued by the
   server's real Groth16 verifier (TEST UIDAI key, dev mode).
7. **Passport through the TEST chip:** dmrtd's real BAC and secure messaging, passive
   authentication against the app's real trust (BSI master list + the V18 TEST CSCA, which is
   trusted only because the server is in dev mode), Active Authentication, a nullifier from the
   server's blind-signing service with its own attested key, then an attested
   `emrtd_attested` card (the server accepted the emulator's attestation in dev mode).
8. Delete the card (signed `DELETE`); the server then says `revoked`.
9. Error screens: under 18 (the real server answers `UNDER_AGE`), and offline.

**What only a real phone can do:** read a real chip over NFC (passports, ID cards, residence
permits), strong hardware attestation (TEE or StrongBox; the emulator's is software-level and a
production server refuses it), scanning a QR with the camera, and `mdoc_app` with a real
wallet ID. The code for these is built and unit-tested, but not run on a real device.

**Timings of the Aadhaar proof** (official v2 circuit, TEST QR):

| Where | Witness | Load proving key | Prove | Total |
|-------|---------|------------------|-------|-------|
| Emulator (x86_64, 8 cores, WHPX), `integration_test/aadhaar_prover_test.dart` | 6.1 s | 2.2 s | 3.4 s | 12.8 s |
| Emulator, inside the app (last full run, "made on this phone in") | | | | 12.0 s |
| PC (Windows, host build of the same Rust code) | 5.3 s | 0.5 s | 1.7 s | 7.5 s |

A phone's speed will differ (arm64 instead of x86_64; phones have fewer fast cores). The proof
from the emulator was checked on the PC with snarkjs and `@anon-aadhaar/core` `verify()`
(`tool/aadhaar_verify/verify.js`): both accept it, and a changed public value is refused.

**Live-server tests from the PC** (`test/integration/`, real HTTP to the 0.3.0 dev server,
software device keys): the 9 phase 1 tests, plus catalog, artifact manifest pins, nullifier
determinism through the real blind-signing service, an `emrtd_attested` card from the TEST chip
(and a proof with an extra field is refused with `PROOF_INVALID`), and an `anon_aadhaar` card
with a **real proof** bound to that request's challenge.

### What running on a device found (and was fixed)

1. **An unlock prompt at every app start.** flutter_secure_storage switched to its biometric mode
   because of the AES key-wrapping option chosen in phase 1. Now it uses its standard mode.
2. **Nearly invisible headings.** The theme replaced Material's text styles with styles that had no
   colour. Fixed, with a test for both themes.
3. **Server: `emrtd_attested` cards gave 500.** The dev database had an early copy of a migration
   with an old list of allowed methods. Fixed on the server with migration 004.
4. Test harness only: the emulator boots to a PIN lock screen once, and lists build lazily
   (the test searches for India instead of scrolling).

### Test files

| File | Tests | What it covers |
|------|-------|----------------|
| `test/crypto/rfc9474_test.dart` | 43 | Every RFC 9474 Appendix A vector, including A.4 **PSSZERO-Deterministic** (the nullifier variant) |
| `test/crypto/blindrsa_ts_crosstest_test.dart` | 11 | Same outputs as the server's `@cloudflare/blindrsa-ts` |
| `test/aadhaar/secure_qr_test.dart` | 13 | TEST QR, seal, age, circuit inputs; a prover answer that reveals more than 18+ is refused |
| `test/aadhaar/prover_host_test.dart` | 1 | The real Rust prover on the PC with the official files (skipped unless the files are given) |
| `test/passport/csca_test.dart` | 4 | **Real data:** the BSI master list; all 596 CSCA certificates whose issuer is in the list verify with the phone's code (RSA, RSA-PSS, ECDSA named and explicit curves), 0 failures |
| `test/passport/chip_reader_test.dart` | 9 | The TEST chip: BAC, secure messaging, passive auth to the CSCA, Active Authentication, under 18, wrong MRZ, copied chip, changed DG1, untrusted country, DS dates |
| `test/passport/passport_test.dart` | 18 | MRZ OCR parsing (ICAO specimens), synthetic EF.SOD signatures |
| `test/widgets/methods_flow_test.dart` | 12 | Aadhaar (download + SHA-256 + proof + card), passport (nullifier with its own attested key, two attestation challenges), under 18, CAN page, wallet ID, connectors |
| `test/widgets/screens_test.dart`, `test/flows/flows_test.dart`, `test/protocol/*`, `test/storage_test.dart` | | Screens, catalog-driven lists, flows, deep links, storage |
| `integration_test/app_flow_test.dart` | 9 | On the emulator (above) |
| `integration_test/aadhaar_prover_test.dart` | 1 | Real proof on the emulator, printed so the PC can verify it |

## 3. How the main new parts work

### Anon Aadhaar proof (`lib/aadhaar/`, `native/v18_prover/`)

- `ArtifactStore` reads `GET /v1/artifacts/manifest`, downloads `aadhaar-verifier.wasm`,
  `circuit_final.zkey` (612 MB) and `vkey.json`, hashes each with SHA-256 **while it downloads**,
  and keeps a file only if the hash and size match. Files are stored under their SHA-256 in the
  app's private storage. The download happens on its own screen, **before** the server
  challenge is fetched, so the 5-minute challenge never covers the download.
- `libv18_prover.so` (Rust, built with the NDK) runs the official witness program with wasmer
  (through ark-circom), reads the official proving key, makes the Groth16 proof with
  ark-groth16 (`CircomReduction`, so snarkjs-compatible), checks that the key's verifying key
  equals the official `vkey.json`, and verifies the new proof before returning it. Dart calls
  it through `dart:ffi` in a background isolate and shows the stage and the seconds.
- Fast key loading: ark-circom checks every curve point while reading the 612 MB key (about 56 s
  on a PC). V18's reader (`fastzkey.rs`, derived from ark-circom's) skips those checks because
  the file's SHA-256 is pinned, the verifying key is compared with `vkey.json`, and every proof
  is verified: 0.5 s on the PC, 2.2 s on the emulator.
- The QR data is wiped from memory after the inputs are built; the inputs are wiped after the
  prover copies them.

### Chip documents (`lib/passport/`)

- **Unlock:** passports use the MRZ (BAC, or PACE with the MRZ). ID cards and residence permits
  ask for the **CAN** (6 digits printed on the card) for PACE, or the MRZ.
- **Passive authentication** (`passive_auth.dart`, `csca.dart`): data-group hashes match
  EF.SOD; EF.SOD is signed by its Document Signer (DS) certificate; the DS certificate is
  signed by a CSCA from the bundled master list (name and key-identifier match, signature, the
  CSCA valid when the DS was issued, the DS valid today).
- **The master list:** `assets/csca/master_list.ml`, the German BSI CSCA Master List exactly as
  BSI signed it (file `DE_ML_2026-10-01-11-50-52.ml`, SHA-256 pinned in the app and in
  `assets/csca/master_list.json`). **To update it:** download
  `GermanMasterList.zip` from
  https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html,
  run `python -I tool/master_list/update_master_list.py <zip>` (it checks BSI's CMS signature and
  that the signer chains to the German CSCA inside the list), then update
  `CscaTrust.bundledSha256` in `lib/passport/csca.dart` to the new SHA-256 it prints. BSI allows
  the list's use; see its page for the terms.
- **Copy test:** Active Authentication with EC keys (DG14 names the hash; plain r‖s signature)
  is checked on the phone. RSA Active Authentication (ISO 9796-2) is **not** checked in this
  version; such chips get `chipAuth: "none"`. Chip Authentication: dmrtd has none, so `"none"`.
- **What is sent** (PROTOCOL 4c.4 + 4d.3): `{over18, docExpiry, issuingState, docType,
  passiveAuth, chipAuth, nullifier, nullifierKeyId}` and the attestation chain. No name, birth
  date or document number. The name and birth date are dropped as soon as they are checked; the
  document number lives only until the nullifier request.
- **Nullifier** (4c.2): message `v18-doc-v1|<state>|<number>`, RFC 9474
  `RSABSSA-SHA384-PSSZERO-Deterministic` (prepare = identity, blind, server signs, finalize),
  nullifier = base64url(SHA-256(signature)). The request uses **its own short-lived attested
  key** made with that request's challenge, deleted right after; the card gets a second key
  made with the card request's challenge (see Design notes 9).

### Wallet IDs (`mdoc_app`, `lib/ui/screens/wallet_id.dart`, `WalletChannel.kt`)

`POST /v1/wallet/app-request {challenge}` returns the Digital Credentials request (nonce = the
challenge). The app hands it **unchanged** to Credential Manager (`GetDigitalCredentialOption`);
the wallet's encrypted answer goes **unchanged** to `POST /v1/card/issue` as `proof`. On a
dev-mode server the app also adds its Credential Manager origin
(`android:apk-key-hash:...`), as the server's API doc allows.

### Login connectors (`lib/flows/connect.dart`, `lib/ui/screens/connector.dart`)

New device key → `v18-card-issue` proof of possession → `POST /v1/connect/:id/start` → the
`authUrl` (must be HTTPS; plain http only to the local mock providers in debug builds) opens
in a Custom Tab → `v18://connect?...` or coming back to the app makes the app read
`GET /v1/connect/session/:state`. The app never trusts what the link itself says.

### Catalog and capabilities (`lib/catalog/catalog.dart`)

`AppCapabilities.whyNot()` decides per method: Aadhaar needs the prover to load (64-bit
phones), chip methods need NFC hardware, `mdoc_app` needs Credential Manager, connectors need
a browser, face needs a shippable model (never in v1), and methods this app does not know
(PhilSys, My Number) are hidden. A method the phone cannot do is shown greyed with the reason
("This phone has no NFC"), never as "coming soon".

### Storage

`flutter_secure_storage` in its standard mode (Keystore-wrapped key, AES-GCM data). Phase 1
used AES key wrapping, which switched the library into its biometric mode and made the app
ask for an unlock on every start; the emulator run found it, and it is fixed.

## 4. Run it

1. Start the dev server on the PC: `npm run dev --prefix server` (port 8080).
2. Emulator: `C:\Android\sdk\emulator\emulator.exe -avd v18_api36`. Set a TEST PIN once:
   `adb shell locksettings set-pin 1234`.
3. From `mobile/`: `C:\Android\flutter\bin\flutter.bat run -d emulator-5554`.
   The app's debug default server is `http://10.0.2.2:8080` (the PC as the emulator sees it).
4. End-to-end tests with screenshots: start `bash tool/emulator_unlock_helper.sh 1234` in one window,
   then `flutter drive --driver=test_driver/integration_test.dart --target=integration_test/app_flow_test.dart -d emulator-5554`.
   After the emulator boots, unlock it once with the PIN (Android asks for it after every restart).
5. A real phone: see section 3 of the phase 1 notes below (`adb reverse tcp:8080 tcp:8080`, then
   Settings > Server > `http://localhost:8080`).

## 5. Not in v1

- **Face estimate:** removed (no face model meets the safety bar).
- **PhilSys QR:** the PSA signature format and key are not public.
- **My Number Card (JPKI):** left out, because it cannot be made trustworthy by V18 today:
  1. J-LIS's public CPS (https://www.jpki.go.jp/ca/pdf/sign_cps.pdf) says the signature certificate
     holds the date of birth in its subjectAltName, but gives no field identifier (OID); the full
     certificate profile is not published.
  2. The CPS says the revocation list (CRL) of signature certificates is access-restricted
     ("アクセス制限を行う"): only certified verifiers get it. So the phone could not tell that a card
     was reported lost or stolen.
  3. The Digital Agency says private companies use JPKI as, or through, a minister-certified platform
     operator (https://www.digital.go.jp/policies/mynumber/private-business/jpki-introduction).
  Ready for later: the three official J-LIS signature-CA certificates (signca01-03.cer from
  https://www.jpki.go.jp/ca/ca_rules3.html) were downloaded and their SHA-256 fingerprints match
  J-LIS's published list (19645405..., 79679c33..., d227f6cd...). The card's commands are known
  (JPKI AID D392F000260100000001, signature password file 001B, signature certificate 0001).
- **RSA Active Authentication** (ISO 9796-2) and **Chip Authentication:** not checked; the card
  request honestly says `chipAuth: "none"` for such chips.
- **Play Integrity:** off (needs a Play Console project, and the server does not check it).
- **Child-account detection:** Android has no public API; the app never treats "unknown" as adult
  (every ticket still needs the owner's unlock).
- **32-bit phones:** the app installs only on 64-bit phones (the Aadhaar prover needs them).

## 6. Design notes (unclear or wrong places, closest reading followed)

1. **Aadhaar signal** (adopted by the server): `"0x" + hex(SHA-256(challenge|thumbprint))`.
2. **Nullifier seed** comes from `GET /v1/health` (`aadhaarNullifierSeed`).
3. **Server URL form:** with or without `/v1`; the app strips it.
4. **Ticket lifetime:** 300 seconds, not the designs' 2 hours.
5. **`GET /v1/card/link/:linkId`** is unauthenticated; the phone never calls it.
6. **Shared-device mode:** card in memory only; all keys deleted at the next start.
7. **Ticket key choice:** valid now, lowest enough `v18_min_age`, newest.
8. **4c.6 "bundles the model":** there is no model to bundle; face is removed, not hidden behind a switch.
9. **One attestation challenge per request (4c.3) vs two requests (4c.2 + 4c.4):** an Android key's
   attestation challenge is fixed when the key is made, and every request uses up its own
   challenge. So the phone makes a short-lived attested key for the nullifier request and the
   card's own attested key for card issue. The server uses this design
   (docs/server/API.md section 12).
10. **`keyAttestation` encoding:** "base64" read as standard base64 with padding (the server
    accepts both).
11. **Connector start signing string:** 4d.4 names none; the server chose the card-issue proof of
    possession, and the app uses it.
12. **`mdoc_app` request:** 4d.3 names no endpoint; the server's `POST /v1/wallet/app-request`
    (nonce = the challenge) is used, and `origin` is added only on dev-mode servers.
13. **Deep links from the server name its public URL** (`http://localhost:8080`). On the emulator
    the same server is `http://10.0.2.2:8080`, so the emulator tests swap the `server=` value.
    On a USB phone, `adb reverse` makes `localhost` work as is.
14. **4d.3 "PhilSys only if public":** not public, so left out (above).
15. **4d.3 `mynumber_attested`:** cannot be made trustworthy without the certificate profile, the
    revocation list and certification (section 5). The app hides it; the catalog still lists it for JP,
    which it should not while no client can do it.

## 7. File map (`mobile/`)

```
lib/aadhaar/        Secure QR, UIDAI keys, circuit inputs, artifacts.dart (download + SHA-256),
                    native_prover.dart (dart:ffi to libv18_prover.so)
lib/catalog/        catalog.dart: /v1/catalog model and AppCapabilities
lib/passport/       mrz_reader, chip_reader (CAN/MRZ, PACE/BAC), passive_auth, csca (master list),
                    active_auth                                  (NEEDS SECURITY REVIEW)
lib/flows/          flows.dart (card issue with attestation, nullifier, tickets, link, delete),
                    connect.dart (login connectors)
lib/device/         device_key (Keystore + attestation), wallet (Credential Manager), checks
lib/crypto/         rfc9474.dart (NEEDS SECURITY REVIEW), jwk, b64
lib/ui/screens/     country (catalog), aadhaar, passport, wallet_id, connector, card_flow, ...
native/v18_prover/  Rust prover (ark-circom, ark-groth16, fastzkey.rs)
android/app/src/main/kotlin/com/v18/app/  DeviceKeyChannel (attestation), WalletChannel, PlatformChannel
android/app/src/main/jniLibs/            libv18_prover.so (arm64-v8a, x86_64)
assets/csca/        BSI master list (+ master_list.json), test/v18-test-csca.der (TEST)
integration_test/   emulator tests; test_driver/ saves screenshots
test/helpers/       fakes (fake server), test_chip.dart (TEST chip simulator)
tool/               master_list updater, TEST document maker, aadhaar_verify (snarkjs check),
                    emulator_unlock_helper.sh (TEST PIN typer for the emulator)
```

## 8. Other things to know

- **My Number Card:** see section 5 (not trustworthy without the certificate profile, the
  revocation list, and certification). Nothing about it shows in the app.
- **dmrtd** is LGPL-3.0, from GitHub (pinned commit). Check the licence before publishing.
- **Sizes:** release APK 120 MB (ML Kit models, the 7-8 MB prover per ABI, the 0.9 MB master
  list). The Aadhaar files (622 MB) are downloaded once, only by people who choose Aadhaar.
- **Memory:** proving needs about 2 GB of free memory. Very low-memory phones may stop the
  app while proving; it then says the proof could not be made.
- `minSdk` 28 (Android 9).
