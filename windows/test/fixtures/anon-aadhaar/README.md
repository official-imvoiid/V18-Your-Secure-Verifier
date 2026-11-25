# Anon Aadhaar TEST files (test only, no real person's data)

These files come from the Anon Aadhaar project's own public test assets
(`https://github.com/anon-aadhaar/anon-aadhaar`, folder `packages/circuits/assets/`).
The project publishes them so that apps can make **TEST** Aadhaar QR codes.

| File | Source file | SHA-256 |
|---|---|---|
| `anon-aadhaar-test-private-key.pem` | `testPrivateKey.pem` (the published TEST signing key) | `b442d1b4b4b848be9657c7dd984ddce8267a72e5e170d8bfcb8a9fd711403640` |
| `anon-aadhaar-sample-qr.txt` | `testQRData` from `dataInput.json` (UIDAI's sample person, signed with the TEST key) | `827d4719f869c53ddfb63369e14d4c0f8fc1f3fba97d5f7608f6f4e490693c93` |

`test/helpers/test-aadhaar.ts` re-stamps the sample with the current time (and, if asked, a
different birth date) and signs it again with the TEST key. The real Anon Aadhaar circuit
accepts these, and the proof says "TEST key" (`pubkeyHash` = Anon Aadhaar's `testPublicKeyHash`),
so only a dev-mode V18 server accepts them. They can never pass as a real Aadhaar.

The matching TEST certificate the app uses in TEST MODE is `windows/assets/aadhaar/anon-aadhaar-test-certificate.pem`
(`testCertificate.pem`, SHA-256 `a025f6e83f50885299d91a881ab667fe08aa8206062ea560e81d06a59bfdaae6`).
