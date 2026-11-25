# IACA trust list for phone wallet IDs (PROTOCOL.md 4c.5, 4d.3)

Put the root certificates (IACA) of the mobile driving licence and EU PID issuers that this
deployment trusts in THIS folder, one PEM or DER file per issuer (`.pem`, `.crt`, `.cer`, `.der`).
The server loads every certificate file directly in this folder at start-up. With no file here,
`mdoc_wallet` and `mdoc_app` are "not_configured" and hidden from the catalog.

Where to get them (the operator must check each one, the server cannot):
- US/Canada mDLs: the AAMVA Digital Trust Service VICAL.
- EU PID and wallets: the EU trusted list for PID providers, once published by the Commission.
- National mDL apps: the issuing authority's published IACA certificate.

`test/` is made by a DEV-MODE server: a V18 TEST IACA and document signer (with a TEST private
key) for `npm run dev-wallet` and the web test wallet. It is gitignored, never in the Docker
image, and a production server never reads it.
