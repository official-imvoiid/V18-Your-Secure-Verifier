# UIDAI public keys for Anon Aadhaar (PROTOCOL.md 3.5, 4c.1)

The server accepts an Anon Aadhaar proof only if its `pubkeyHash` (the Poseidon hash of the RSA
key that signed the Aadhaar Secure QR) matches one of these certificates. The hashes are
computed from the files at start-up, so a new UIDAI key can be added by dropping its
certificate into `production/`.

- `production/uidai_offline_publickey_26022021.cer`: UIDAI's Secure QR / offline e-KYC signing
  certificate ("DS UNIQUE IDENTIFICATION AUTHORITY OF INDIA 05", valid 2021-02-26 to
  2024-02-27). Taken from the official Anon Aadhaar repository
  (packages/circuits/assets/), because uidai.gov.in refused connections from the build
  machine. Its hash, 18063425702624337643644061197836918910810808173893535653269228433734128853484,
  equals `productionPublicKeyHash` in `@anon-aadhaar/core` 2.4.3, and the server test checks this.
  The circuit checks only the key, not the certificate dates, which is how Anon Aadhaar itself
  works. If UIDAI starts signing QR codes with a new key, add its certificate here.
- `test/anon-aadhaar-testCertificate.pem`: the Anon Aadhaar project's TEST key. Accepted ONLY when
  `V18_DEV_MODE=1`, and cards made with it get `assuranceLevel: "test"`.
