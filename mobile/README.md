# V18 Android app (Flutter)

Prove you are 18+ without saying who you are. Protocol: `docs/PROTOCOL.md`.

- How to run it, what works, what is stubbed: `../docs/mobile/WALKTHROUGH.md`
- Checks: `flutter analyze`, `flutter test`, `flutter build apk --debug`
- Live tests against a running dev server:
  `V18_LIVE_SERVER=http://localhost:8080 flutter test test/integration`

Security review needed: `lib/crypto/rfc9474.dart` and `lib/passport/passive_auth.dart`.
