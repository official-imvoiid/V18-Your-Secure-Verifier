# V18 country catalog

`catalog/countries.json` is the single list of which IDs work in which country
(PROTOCOL.md 4d.2). The server serves it at `GET /v1/catalog`, filtered to what that server has
switched on. The Android and Windows apps build their country and method screens from it.
**A wrong entry shows people a method that won't work, so every entry needs a source.**

| File | What it is |
|------|------------|
| `catalog/countries.json` | The catalog itself |
| `catalog/schema.json` | JSON Schema for the file |
| `catalog/test_catalog.py` | Tests. Run `python -m pytest catalog` from the project folder |
| `docs/catalog/SOURCES.md` | The source for every entry, plus the "Not included" and "Unconfirmed" lists |

## What is in it now

- **54 countries:** all 27 EU countries; Iceland, Liechtenstein and Norway; the UK (`GB`) and
  Switzerland; and 22 Asian countries.
- **123 methods:** chip passports in 53 countries, chip ID cards in 28, residence permits in 29,
  12 login connector entries (10 different connectors in 10 countries), and Aadhaar (India).
- **Sri Lanka has no methods,** because it's unconfirmed whether it issues chip passports yet. The
  server hides countries with no methods.
- **No wallet IDs yet.** No launched wallet was found that gives apps or websites an mDL or EU PID
  with `age_over_18` today. Japan's My Number Card in Apple and Google Wallet uses a Japanese
  document type that the V18 server doesn't accept, and Apple supports it in apps only. See
  "Not included" and "Unconfirmed" in SOURCES.md.
- **Not in v1 (PROTOCOL.md 4d.4b), so not in the file:** `mynumber_attested` (Japan's My Number
  Card chip) and `face_estimate`. The test fails if either is added.

## The shape of one entry

```json
{ "method": "emrtd_attested", "label": "ID card (chip)",
  "documents": ["Polish ID card (e-dowód) issued since 4 March 2019"],
  "docTypes": ["I"], "needs": ["nfc"], "privacy": "on_device", "platforms": ["android"],
  "since": 2019, "note": "The app reads the chip with the code printed on the card: ..." }
```

| Field | Rule |
|-------|------|
| `method` | A name from PROTOCOL.md 4d: `anon_aadhaar`, `emrtd_attested`, `philsys_qr_attested`, `mdoc_app`, `mdoc_wallet`, or `connector:<id>` with one of the 12 ids in `docs/connectors/README.md`. (`mynumber_attested` and `face_estimate` are 4d names but not in v1) |
| `label` | Short button text in plain English |
| `documents` | Real names of the documents people can use |
| `docTypes` | Only for `emrtd_attested`: the first MRZ letter. Passports `["P"]`, ID cards `["I"]`, residence permits `["A","C","I"]`. Passports always get their own entry |
| `needs` | From `camera`, `nfc`, `wallet`, `password` |
| `privacy` and `platforms` | Fixed by the method (see the table below). The test checks them |
| `since` | Optional. The year this document type started being issued. Use it when older documents without a chip are still around |
| `note` | Optional. One plain-English sentence for the user |

| Method | privacy | platforms | needs |
|--------|---------|-----------|-------|
| `anon_aadhaar` | `zero_knowledge` | `android`, `windows` | `camera` |
| `emrtd_attested`, `philsys_qr_attested` | `on_device` | `android` | `nfc` (PhilSys: `camera`) |
| `mdoc_app` | `wallet` | `android` | `wallet` |
| `mdoc_wallet` | `wallet` | `web` | `wallet` |
| `connector:<id>` | `login` | `android`, `windows` | `password` |

Country codes are ISO 3166-1 two-letter codes: the UK is `GB` and Greece is `GR`. `region` is
`europe` or `asia`.

## How to add or update a country

1. **Find a source first.** Use an official government or standards page if you can. A
   news report or the card maker's page is acceptable if it's all there is, but say so. If you
   can't confirm it, **don't add it**. Put it under "Unconfirmed" in SOURCES.md instead. Never
   guess.
   - Chip passport: add it only if the country really issues ICAO chip passports (the chip symbol
     on the cover). It needs no source, but add `since` and a `note` if older passports without a
     chip are still valid.
   - Chip ID card or residence permit: the chip must follow ICAO 9303 and be readable over NFC
     with the MRZ or the CAN. A chip used only for signing or government logins doesn't count.
   - Wallet ID: the wallet must give an mDL (`org.iso.18013.5.1.mDL`) or EU PID
     (`eu.europa.ec.eudi.pid.1`) with `age_over_18` to apps (`mdoc_app`) or websites
     (`mdoc_wallet`). Those are the only two the V18 server accepts.
   - Connector: it must be one of the 12 in `docs/connectors/README.md`, and the provider must
     give a birth date or an 18+ answer.
2. **Edit `catalog/countries.json`.** Add the country (or method) in the shape above. Keep the
   wording plain: the user is a student.
3. **Edit `docs/catalog/SOURCES.md`.** Under `### XX Country name`, add one line per non-passport
   method: `` - `key` - what the source says. https://... ``. The key is the method name, or
   `emrtd_attested[I]` / `emrtd_attested[A,C,I]` for ID cards and residence permits. A shared
   source can be cited as `[S:EU-ID]`, for example. If you remove an entry, remove its source
   line too.
4. **Run the tests:** `python -m pytest catalog`. They fail if a source is missing, a method name
   or platform is wrong, a coverage country is missing, or something listed as "Not included"
   or "Unconfirmed" is in the file.
5. The server re-reads the file when it changes. There's no need to restart it. Check with
   `GET /v1/catalog?country=XX`.

## Things to check again later

- **24 December 2026:** the EU deadline for every country to offer an EU digital identity wallet.
  Check which wallets then give out a PID or mDL to apps and websites, and add `mdoc_app` /
  `mdoc_wallet` entries.
- **Estonia, Finland and Liechtenstein ID cards:** they probably work, but no source confirmed it
  (see "Unconfirmed").
- **Sri Lanka:** add the passport once a source confirms e-passports are issued.
- **Japan's My Number Card in a wallet:** this needs the V18 server to accept Japan's document type
  (Apple names the namespace `org.iso.23220.1.jp`), and Apple must support websites if it's for
  `mdoc_wallet`. Only then add `mdoc_app` / `mdoc_wallet` for JP.
- **itsme:** its coverage page lists about 30 European countries. PROTOCOL.md 4d.4 lists only BE,
  NL and LU, so only those are in the catalog.
