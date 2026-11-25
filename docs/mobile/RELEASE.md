# V18 Android app: release builds and the upload key

## The upload key (kept OUTSIDE the project)

| What | Where |
|------|-------|
| Key store (PKCS12, RSA-4096, valid until 2056) | `C:\Users\voiid\.v18-keys\v18-upload.p12` |
| Passwords and alias (read by Gradle) | `C:\Users\voiid\.v18-keys\upload-key.properties` |
| Key alias | `v18-upload` |
| Certificate name | `CN=V18 upload key, O=V18` (no personal details) |

Both files are readable only by the Windows account `voiid` (set with `icacls`).
Nothing about the key is inside `mobile/`. `mobile/android/app/build.gradle.kts` reads
`%USERPROFILE%\.v18-keys\upload-key.properties`, or the file named by the environment
variable `V18_UPLOAD_KEY_PROPERTIES`. A release build **stops with an error** if the key is
missing; it never falls back to the debug key.

### Upload certificate SHA-256 (for the server)

```
14:47:A2:A7:52:B9:97:FA:76:8F:2F:19:8C:B8:E1:C9:0E:E0:C8:BA:81:49:B9:4A:12:AB:36:EA:2B:4E:DA:E3
```

Without colons (for `V18_ANDROID_CERT_DIGESTS`):

```
1447a2a752b997fa768f2f198cb8e1c90ee0c8ba8149b94a12ab36ea2b4edae3
```

The server's key-attestation check (PROTOCOL 4c.3) must list the SHA-256 of the certificate
that **signs the APK the phone runs**:
- If you install the APK built here (side-loading, or a store that keeps your signature),
  that is the upload certificate above.
- If you publish on Google Play with Play App Signing (the default), Google re-signs the app
  with its own **app signing key**. Then add Google's app signing certificate SHA-256 too
  (Play Console > Test and release > App integrity > App signing). Listing both is fine.

Check it yourself at any time:

```
C:\Android\jdk\jdk-17.0.20.1+1\bin\keytool.exe -list -v -keystore C:\Users\voiid\.v18-keys\v18-upload.p12 -alias v18-upload
```

(it asks for the store password from `upload-key.properties`).

### Back up the key now

If this key is lost, you can never publish an update to the same app listing without asking
Google to reset the upload key (and outside Play, users would have to uninstall and reinstall).
If it is stolen, someone could sign fake updates. So:

1. Copy **both** files in `C:\Users\voiid\.v18-keys\` to two places that are not this PC,
   for example an encrypted USB stick kept at home, and a password manager's secure file
   attachment (Bitwarden, 1Password, KeePassXC).
2. Store the password (inside `upload-key.properties`) in your password manager as well.
3. Never put the key in Git, Google Drive without encryption, chat or email.
4. Test the backup once: copy it to another folder, point `V18_UPLOAD_KEY_PROPERTIES` at the
   copy (after fixing `storeFile` in it) and run a release build.

## Build

From `mobile/`:

```
C:\Android\flutter\bin\flutter.bat build apk --release --dart-define=V18_SERVER_URL=https://api.v18.example
C:\Android\flutter\bin\flutter.bat build appbundle --release --dart-define=V18_SERVER_URL=https://api.v18.example
```

- `V18_SERVER_URL` is the production server (an `https` origin). Until the project owns a
  domain it is the protocol's placeholder `https://api.v18.example`. Release builds accept
  only this server: plain `http` and the PC dev server work in debug builds only.
- R8 is on (code shrinking and obfuscation for the Kotlin/Java side, resource shrinking).
  Rules: `mobile/android/app/proguard-rules.pro`.
- Only 64-bit phones (`arm64-v8a`; `x86_64` for emulators): the Aadhaar prover needs them.
- Outputs: `build/app/outputs/flutter-apk/app-release.apk` and
  `build/app/outputs/bundle/release/app-release.aab`.

Play Integrity stays off (PROTOCOL 4c.3). A build may pass `--dart-define=V18_PLAY_INTEGRITY=<project>`
only once the server checks Play Integrity verdicts; v1 does not.

## The native Aadhaar prover

`android/app/src/main/jniLibs/<abi>/libv18_prover.so` is built from `mobile/native/v18_prover`
(Rust). Rebuild after changing it:

```
cd mobile\native\v18_prover
set ANDROID_NDK_HOME=C:\Android\sdk\ndk\28.2.13676358
cargo ndk -t x86_64 -t arm64-v8a -P 28 -o ..\..\android\app\src\main\jniLibs build --release --lib
```

(`cargo install cargo-ndk --locked` once.) Delete any extra `libark_circom-*.so` that cargo-ndk
copies next to it; `libv18_prover.so` needs only Android's own `libc`, `libm` and `libdl`.
