# Catalog sources

This file backs up every entry in `catalog/countries.json` that is **not** a chip passport.
Chip passports (`emrtd_attested` with `docTypes ["P"]`) need no source here (PROTOCOL.md 4d.2).
Their start years and notes are sourced below anyway where the file gives them.

Checked on 2026-11-23 and 2026-11-24 by reading the pages listed. When an official site blocked
automated reading, that is noted and the source used instead is named.

**How `catalog/test_catalog.py` reads this file:**
- Each country has a heading `### XX Name` (ISO code first).
- Each non-passport method in `countries.json` needs a line under its country that starts with
  `` - `key` ``. The key is the method name, for example `` `connector:itsme` ``. For chip
  documents other than passports it is `emrtd_attested[...]` with the docTypes, for example
  `` `emrtd_attested[I]` `` or `` `emrtd_attested[A,C,I]` ``.
- That line must contain a web link (`https://...`) or a shared source tag like `[S:EU-ID]` from
  the "Shared sources" list.
- Lines under "Not included" and "Unconfirmed" look like `` - **XX** `key` - reason ``. The test
  checks that none of them appear in `countries.json`.

## Shared sources

- [S:EU-ID] Council Regulation (EU) 2025/1208 on the security of ID cards (it replaces Regulation 2019/1157, which the Court of Justice declared invalid in case C-61/22 on 21 March 2024 but kept in force until the new rule). Art. 3(1): ID-1 format with an MRZ, "based on the specifications ... set out in ICAO Document 9303". Art. 3(5) and 3(6): a storage medium with the face and two fingerprints, "accessible in contactless form". Recital 9: countries don't have to introduce ID cards. Recital 47: Denmark is not bound. Recital 48: Ireland opted in. Art. 2(c) and 7(1): residence cards for family members of EU citizens use the 1030/2002 card format. Art. 5: older cards that don't meet the rules expire by 3 Aug 2026 or 3 Aug 2031. https://eur-lex.europa.eu/eli/reg/2025/1208/oj/eng
- [S:EU-RP] Regulation (EU) 2017/1954, amending Regulation 1030/2002 (the uniform residence permit format for non-EU citizens). Annex field 20: "An RF chip shall be used as a storage medium". Field 5: the card access number (CAN). Field 17: the MRZ follows ICAO Document 9303. Recitals 6 and 7: Denmark, Ireland and the UK are not bound. Recitals 9 to 11: Iceland, Norway, Switzerland and Liechtenstein apply it as part of the Schengen rules. https://eur-lex.europa.eu/eli/reg/2017/1954/oj/eng
- [S:ITSME] itsme claims: `birthdate` and `age_gte_18` ("meant to be used for age verification"), https://belgianmobileid.github.io/doc/claims/ . itsme coverage page listing Belgium, Luxembourg and the Netherlands among its countries: https://www.itsme-id.com/en-be/coverage

**About the residence-permit letters `A, C, I`.** PROTOCOL.md 4d.3 sets `docType` to the first MRZ
letter (`P`, `I`, `A` or `C`). Residence permits are TD1 cards, and different countries use
different first letters. The exact letter for each country was **not** confirmed. The ICAO
Doc 9303 Part 5 PDF (https://www.icao.int/publications/Documents/9303_p5_cons_en.pdf) blocked
automated reading. So the catalog lists all three card letters `A`, `C` and `I` for residence
permits. The letters only tell the app which kind of card to expect. Security comes from the
chip check, not from the letter.

**About PRADO.** The EU's PRADO document register (consilium.europa.eu/prado) shows a bot check
to automated readers. Where a PRADO page is cited below, its text was read through a search
engine's copy of the page, not directly.

## Countries

### AT Austria
- `emrtd_attested[I]` - New ID card since 2 August 2021, with "the chip for biometric data already known from the passport". PRADO lists a "contactless microchip" (no fingerprints). https://www.staatsdruckerei.at/allgemein/new-id-card-presented-by-federal-ministry-of-interior , https://www.consilium.europa.eu/prado/en/AUT-BO-03001/index.html , [S:EU-ID]
- `emrtd_attested[A,C,I]` - EU-format residence permit with RF chip. [S:EU-RP]

### BE Belgium
- `emrtd_attested[I]` - The eID has a contact chip (signing) and a contactless chip for travel-document use, with fingerprints added in 2020. Sources are the card makers, not a government page: https://peopleid.zetes.com/sites/default/files/references/pdf/CAS%20BE%20eID%20EN%20HRES.pdf , https://thalesgroup.com/en/node/2730264 , [S:EU-ID]
- `emrtd_attested[A,C,I]` - [S:EU-RP]
- `connector:itsme` - [S:ITSME]

### BG Bulgaria
- `emrtd_attested[I]` - New-generation ID cards with a chip holding two fingerprints and a photo, issued since 17 June 2024. Older cards have no chip. Source: the state news agency BTA. https://www.bta.bg/en/news/bulgaria/689215-interior-ministry-starts-issuing-new-generation-identity-cards , https://www.bnt.bg/en/a/new-id-cards-will-have-a-chip-with-biometrics-electronic-signature-and-identity
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### HR Croatia
- `emrtd_attested[I]` - Second-generation eID (eOI) since 2 August 2021, adding a contactless chip with the face and two fingerprints. The Interior Ministry brochure says the biometrics follow ICAO standards. https://www.gov.hr/en/second-generation-electronic-identity-cards/2312 , https://www.akd.hr/datastore/file/972/brosura-OI_gen-2-v-2.pdf
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### CY Cyprus
- `emrtd_attested[I]` - New-generation electronic ID cards with biometrics, issued from 17 August 2020 by the Civil Registry and Migration Department, built to the EU rule. https://csca.crmd.moi.gov.cy/Electronic_documents , https://www.cyprusprofile.com/articles/cyprus-starts-fingerprinting-id-card-applicants
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### CZ Czechia
- `emrtd_attested[I]` - Since 2 August 2021, ID cards store the face and fingerprints on a contactless chip (ISO 14443) and follow ICAO 9303. https://mv.gov.cz/clanek/nove-obcanky-s-biometrickymi-udaji-zacnou-urady-vydavat-jiz-od-srpna.aspx , https://www.lupa.cz/aktuality/nove-bezkontaktni-eobcanky-budou-komunikovat-i-s-nekterymi-nfc-cteckami/
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### DK Denmark
- `connector:mitid` - MitID through the Signaturgruppen broker: the `age_verify:18` scope gives a yes/no 18+ answer. https://signaturgruppen-a-s.github.io/signaturgruppen-broker-documentation/idps/mitid-age-verification.html

### EE Estonia
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### FI Finland
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### FR France
- `emrtd_attested[I]` - New ID card (CNIe) in the bank-card format, trialled from 15 March 2021 and issued everywhere since 2 August 2021, with a contactless chip holding biometric and identity data. https://www.interieur.gouv.fr/actualites/actualites-du-ministere/nouvelle-carte-nationale-didentite/foire-aux-questions-nouvelle , https://www.info.gouv.fr/actualite/tout-ce-qu-il-faut-savoir-sur-la-nouvelle-carte-nationale-d-identite
- `emrtd_attested[A,C,I]` - [S:EU-RP]
- `connector:franceconnect` - The `birthdate` scope gives the birth date as YYYY-MM-DD, as part of the "identité pivot". https://docs.partenaires.franceconnect.gouv.fr/fs/fs-technique/fs-technique-scope-fc/ . **Who may use it:** private companies only if a regulation requires them to check their users' identity: https://docs.partenaires.franceconnect.gouv.fr/fs/devenir-fs/pilotage-eligibilite/

### DE Germany
- `emrtd_attested[I]` - ID card in the bank-card format since 1 November 2010, with a chip and a 6-digit access number (CAN) printed on the front. BSI: the RF chip is protected with PACE, even when the CAN is used. https://www.bsi.bund.de/EN/Themen/Verbraucherinnen-und-Verbraucher/Informationen-und-Empfehlungen/Digitale-Verwaltung/Der-Personalausweis/der-personalausweis.html , https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Elektronische-Ausweisdokumente/Sicherheitsmechanismen/PACE/pace.html , [S:EU-ID]
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### GR Greece
- `emrtd_attested[I]` - New ID cards issued since September 2023, with an RFID chip holding the photo and two fingerprints, and an MRZ, to EU and ICAO rules. Old cards stopped working for travel on 3 August 2026. Sources are news reports (no Greek government page could be read): https://www.biometricupdate.com/202309/greece-starts-issuing-new-id-cards-as-conspiracy-theories-spread , https://greekcitytimes.com/2026/01/11/greece-unveils-10-year-rfid-enabled-digital-id-cards/
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### HU Hungary
- `emrtd_attested[I]` - e-ID card (eSzemélyi) since 1 January 2016, with a contactless chip holding fingerprints, also usable as an electronic travel document. https://haga.mfa.gov.hu/en/e-identity-card , https://www.biometricupdate.com/201601/hungary-begins-issuing-biometric-id-cards
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### IE Ireland

### IT Italy
- `emrtd_attested[I]` - CIE 3.0 (since 2016): the contactless microchip follows ICAO 9303, like passports. https://www.cartaidentita.interno.gov.it/en/cie/cie-features/ , https://www.cartaidentita.interno.gov.it/en/cie/physical-identification/
- `emrtd_attested[A,C,I]` - [S:EU-RP]
- `connector:spid` - SPID attribute `dateOfBirth` (xs:date, YYYY-MM-DD) in AgID's attribute table. https://www.agid.gov.it/sites/default/files/repository_files/tabella_attributi_v.1.3.pdf
- `connector:cie` - Entra con CIE returns `dateOfBirth` (YYYY-MM-DD) among the eIDAS minimum attributes, and its spec covers private service providers (`<Private/>`). https://docs.italia.it/italia/cie/cie-eid-saml-docs/it/versione-corrente/protocolli.html , https://docs.italia.it/italia/cie/cie-eid-saml-docs/it/versione-corrente/federazione.html

### LV Latvia
- `emrtd_attested[I]` - Latvia's immigration office (PMLP): the eID card has an "integrated no-contact microchip just like the new passports", with two fingerprint images. eID cards are issued since 2 April 2012, and the exact start year of the chip was not stated. https://www.pmlp.gov.lv/en/frequently-asked-questions-and-answers , https://pmlp.gov.lv/en/article/eid-card-convenient-and-safe-personal-identity-document
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### LT Lithuania
- `emrtd_attested[I]` - PRADO: current ID card first issued 1 June 2021, a travel document in the EU and Schengen. The earlier model already had a "contactless microchip" with the face and a fingerprint. https://www.consilium.europa.eu/prado/en/LTU-BO-03001/index.html , https://www.consilium.europa.eu/prado/en/LTU-BO-02001/index.html , [S:EU-ID]
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### LU Luxembourg
- `emrtd_attested[I]` - The ID card's electronic chip holds biometric data, with two fingerprints added for cards from 2 August 2021. The pages don't say "contactless", which comes from the EU rule. https://guichet.public.lu/en/citoyens/actualites/2021/aout/02-du-nouveau-pour-la-carte-d-identite.html , https://gouvernement.lu/fr/actualites/toutes_actualites/communiques/2021/07-juillet/08-loi-carte-identite-luxembourgeoise.html , [S:EU-ID]
- `emrtd_attested[A,C,I]` - [S:EU-RP]
- `connector:itsme` - [S:ITSME]

### MT Malta
- `emrtd_attested[I]` - New ID cards (launched September 2020) are contactless, and their data is reachable only with the Card Access Number printed on the front. Identity Malta's reader guide lists contactless readers. https://www.pressreader.com/malta/malta-independent/20200929/281496458729144 , https://identita.gov.mt/wp-content/uploads/2023/10/Malta-Identity-Card-and-Card-Reader-Windows-Installation-and-User-Guide_v1.8.pdf
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### NL Netherlands
- `emrtd_attested[I]` - The Dutch ID card is an electronic travel document with a chip readable with an NFC phone. The 6-digit CAN has been on the front since 4 January 2021, and the CSCA certificate is at npkd.nl. https://www.rijksoverheid.nl/vraag-en-antwoord/paspoort-en-identiteitskaart/wat-is-een-elektronisch-reisdocument-en-welke-gegevens-bevat-de-chip-hierin , https://rvig.nl/sites/default/files/2025-05/Kenmerkenbrochure%20identiteitskaart%20model%202021%20EN.pdf
- `emrtd_attested[A,C,I]` - [S:EU-RP]
- `connector:itsme` - [S:ITSME]

### PL Poland
- `emrtd_attested[I]` - Every ID card issued after 4 March 2019 is an e-dowód: a contactless (NFC) chip with its own CAN printed on the photo page, an ICAO travel document. https://www.gov.pl/web/e-dowod
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### PT Portugal
- `emrtd_attested[I]` - New Citizen Card since June 2024, with a contact and contactless chip, a CAN on the front, and use as a travel document. Older cards are contact-only. https://portugal.gov.pt/gc24/comunicacao/noticias/novo-cartao-de-cidadao-a-partir-de-11-de-junho , https://portugal.gov.pt/gc24/comunicacao/noticias/340-mil-portugueses-ja-tem-cartao-de-cidadao-contactless
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### RO Romania
- `emrtd_attested[I]` - Electronic ID card (CEI) issued since 20 March 2025, with a chip and usable as a travel document in the EU. The simple ID card (CIS) has no chip and is not a travel document. Sources are news reports (carteadeidentitate.gov.ro was not read): https://www.romania-insider.com/electronic-id-cards-romania-march-2026 , https://www.bzi.ro/cartea-de-identitate-simpla-nu-e-document-de-calatorie-anuntul-mai-5334468
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### SK Slovakia
- `emrtd_attested[I]` - Biometric ID cards since 1 December 2022, with a dual-interface chip readable contactlessly (NFC) and holding the face and two fingerprints. Sources are news reports, because the Interior Ministry press release was not found: https://www.podnikajte.sk/technologie/biometricky-obciansky-preukaz , https://touchit.sk/biometricke-obcianske-preukazy-s-bezkontaktnym-cipom-su-uz-realitou/456967/ , https://sita.sk/ministerstvo-je-pripravene-vydavat-biometricke-obcianske-preukazy-uz-od-decembra/
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### SI Slovenia
- `emrtd_attested[I]` - Biometric ID cards since 28 March 2022, with a dual-interface chip holding the face and two fingerprints, readable with an NFC phone. https://www.gov.si/en/news/2022-12-29-the-eosebna-mobile-app-makes-it-easier-to-use-your-electronic-identity-card/ , https://www.gov.si/assets/ministrstva/MNZ/SOJ/Novice/2023/3-Marec/BOI_nagrada_08032023/The-new-Slovene-biometric-identity-card_brochure_2023.pdf
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### ES Spain
- `emrtd_attested[I]` - DNI 3.0 is the only DNI issued since December 2015. FNMT's NFC guide: the DNIe 3.0 works over NFC with the CAN, "tiene una estructura de datos equivalente al pasaporte" and works at automatic border gates. https://www.dnielectronico.es/PortalDNIe/PRF1_Cons02.action?pag=REF_103&id_menu=1 , https://www.dnielectronico.es/PDFs/Implementacion_NFC_FNMT.pdf
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### SE Sweden
- `emrtd_attested[I]` - The national ID card's chip stores personal data, the photo and fingerprints (fingerprints required since 2 August 2021). https://www.swedenabroad.se/en/about-sweden-non-swedish-citizens/iceland/going-to-sweden/services-for-swedes/swedish-passports-and-national-identity-cards/ , https://polisen.se/en/services-and-permits/passport-and-national-id-card/ , [S:EU-ID]
- `emrtd_attested[A,C,I]` - [S:EU-RP]
- `connector:bankid_se` - `collect` returns `completionData.user.personalNumber`, which is 12 digits YYYYMMDDNNNN and so starts with the birth date. https://www.bankid.com/utvecklare/guider/teknisk-integrationsguide/graenssnittsbeskrivning/collect , https://www.bankid.com/utvecklare/guider/teknisk-integrationsguide/tekniska-krav
- `connector:freja` - Freja's OIDC guide lists the scope `https://frejaeid.com/oidc/scopes/birthdate` (YYYY-MM-DD). https://frejaeid.atlassian.net/wiki/spaces/DOC/pages/33423361

### IS Iceland
- `emrtd_attested[I]` - New biometric ID cards since 5 March 2024, following ICAO 9303 and usable for travel in the EU/EFTA. Registers Iceland's pages were read through a search engine (island.is blocks automated reading). https://skra.is/english/people/passport-and-id-card/id-card/various-information-on-id-cards/security-of-icelandic-id-cards , https://www.skra.is/library/Samnyttar-skrar-/Nafnskirteini/ID_CARD_ICELAND_folder_eng_03_2024.pdf , https://www.biometricupdate.com/202403/iceland-updates-id-cards-as-frontex-warns-of-document-fraud-in-eu
- `emrtd_attested[A,C,I]` - [S:EU-RP]

### LI Liechtenstein
- `emrtd_attested[A,C,I]` - Biometric residence card. https://llv.li/en/national-administration/migration-and-passport-office/residence-permits/biometric-residence-card , [S:EU-RP]

### NO Norway
- `emrtd_attested[I]` - National ID card since 30 November 2020. Police control guide: the chip is fully ICAO 9303 compliant and is read with the CAN on the front and the MRZ on the back. https://www.politiet.no/globalassets/tjenester-admin/pass-og-id-kort/control-guide-national-id-card.pdf , https://udi.no/en/word-definitions/national-id-card
- `emrtd_attested[A,C,I]` - [S:EU-RP]
- `connector:bankid_no` - BankID OIDC userinfo includes `birthdate` (from the BankID certificate). https://confluence.bankidnorge.no/confluence/x/dRqrBQ

### GB United Kingdom

### CH Switzerland
- `emrtd_attested[I]` - Optional ID card with a chip (face and two fingerprints, like the passport) since 2 November 2026. The card without a chip is still issued. The sources don't say how the chip is opened (CAN or MRZ). https://www.fedpol.admin.ch/en/current-projects , https://idtechwire.com/switzerland-sets-november-2-start-for-its-biometric-identity-card/
- `emrtd_attested[A,C,I]` - Biometric foreigner's ID card (Ausländerausweis) for non-EU citizens. https://www.sem.admin.ch/sem/de/home/themen/aufenthalt/biometr_auslaenderausweis.html , [S:EU-RP]

### IN India
- `anon_aadhaar` - Anon Aadhaar checks the UIDAI RSA signature in the Aadhaar secure QR inside a zero-knowledge proof. Its docs warn that it is "still under development". UIDAI: the secure QR is digitally signed and holds the date of birth. It is printed on the Aadhaar letter, the PVC card and e-Aadhaar, and shown in mAadhaar and the Aadhaar app. https://documentation.anon-aadhaar.pse.dev/docs/intro , https://www.uidai.gov.in/images/OVSE_Playbook.pdf , https://www.uidai.gov.in/en/ecosystem/authentication-devices-documents/qr-code-reader.html
- `connector:digilocker` - DigiLocker partner API (OAuth 2.0, PKCE): the access-token response includes the DigiLocker ID and user details (with the date of birth). https://img1.digitallocker.gov.in/assets/img/Digital%20Locker%20Authorized%20Partner%20API%20Specification%20v1.11.pdf , https://cf-media.api-setu.in/resources/Requester-MeriPehchaan-APISpecification-V2_3.pdf
- Passport start year (no source required): pilot from April 2024, and every passport issued since 28 May 2025 is an e-passport. Existing passports stay valid until they expire. https://theprint.in/diplomacy/80-lakh-e-passports-issued-since-may-all-passports-by-may-2035-to-be-chipped-mea-official/2786961

### PH Philippines

### JP Japan

### SG Singapore
- `connector:singpass` - Myinfo data item `dob` (for citizens, PRs and FIN holders). Note: Singpass says a date of birth can be partial (YYYY-MM or YYYY). https://docs.developer.singpass.gov.sg/docs/data-catalog-myinfo/catalog/personal , https://docs.developer.singpass.gov.sg/docs/data-catalog-myinfo/catalog/start-here

### KR South Korea

### VN Vietnam
- `emrtd_attested[I]` - The chip ID card (CCCD gắn chip, from 2021, and the Căn cước card from 1 July 2024) follows ICAO 9303, with data groups DG1, DG2 and DG13 readable over ISO 14443 NFC. Sources are technical write-ups, plus the ministry's official reader rules (contactless ISO 14443). No Public Security Ministry page saying "ICAO" could be read. https://didit.me/blog/vietnam-cccd-chip-nfc-verification/ , https://viblo.asia/p/quy-trinh-truy-xuat-du-lieu-tu-cccd-2oKLn1eQJQO , https://vpubnd.daklak.gov.vn/CMS/Content/1091-QD-BTTTT_Phu%20luc.pdf
- Passport start year (no source required): chip passports since 1 March 2023, optional. https://hatinh.gov.vn/vi/bai-viet/tu-13-trien-khai-cap-ho-chieu-pho-thong-gan-chip-dien-tu

### ID Indonesia

### MY Malaysia

### TH Thailand

### PK Pakistan
- Passport start year (no source required): e-passports from 2022 (soft launch), at all field offices since 16 August 2023. https://dgip.gov.pk/eServices/epassport.php

### BD Bangladesh

### LK Sri Lanka
- Sri Lanka has no methods. Whether it issues chip passports is unconfirmed (see "Unconfirmed"), and no other method applies. The server hides countries with no methods.

### NP Nepal
- Passport start year (no source required): e-passports since 17 November 2021. https://kathmandupost.com/national/2021/11/17/nepal-to-start-issuing-e-passports-from-today

### AE United Arab Emirates

### SA Saudi Arabia
- Passport start year (no source required): e-passport launched 10 February 2022, and replacing an older passport is optional. https://www.arabnews.com/saudi-arabia/saudi-arabia-introduces-new-e-passport-2022371

### QA Qatar
- Passport start year (no source required): first e-passport in the Gulf, in 2008, and Qatar shares its passport keys through the ICAO PKD. https://www.gulf-times.com/story/599874/qatar-hands-e-passport-public-key-to-icao

### KW Kuwait
- Passport (no source required): e-passport system launched in 2016. https://www.biometricupdate.com/201605/kuwait-launching-new-e-passport-system-by-september , https://identityweek.net/kuwait-marks-launch-of-epassport-issuance

### CN China

### HK Hong Kong

### TW Taiwan

### IL Israel

### TR Turkey
- `emrtd_attested[I]` - New ID card (T.C. Kimlik Kartı) issued nationwide since 2 January 2017, with separate contact and contactless chips. The ID card regulation defines the face biometrics to ICAO 9303 and allows travel with the card, and NVI's instruction covers travel with it. https://nvi.gov.tr/kurumlar/nvi.gov.tr/mevzuat/nufusmevzuat/talimat/kimlikkartiislemleri/29072021_105247-81-il-Valiligi_TCKK-ile-Seyahat-_On-bes-yasini-tamamlamayanlar_.pdf , https://www.lexpera.com.tr/mevzuat/yonetmelikler/turkiye-cumhuriyeti-kimlik-karti-yonetmeligi , https://www.turkiyegazetesi.com.tr/gundem/yeni-kimlik-kartlari-taklidi-imkansiz-kilacak-350843

## Not included (checked: it doesn't work)

- **GB** `emrtd_attested[A,C,I]` - UK biometric residence permits: issuing stopped on 31 October 2024, most cards expired on 31 December 2024, and they were replaced by eVisas. V18 refuses expired documents. https://homeofficemedia.blog.gov.uk/2024/12/04/media-factsheet-evisas
- **PH** `philsys_qr_attested` - PSA signs the PhilID QR with EdDSA, but gives the public key and QR documentation only to relying parties who apply with a signed letter. They are not public, so 4d.3 says to leave this out. https://psa.gov.ph/content/provision-philsys-check-public-key-and-documentation-qr-code-scanner-interested-relying
- **AE** `connector:uaepass` - UAE PASS's public docs list no birth-date attribute, so V18 can't decide 18+ without the provider's help (see `docs/connectors/uaepass.md`).
- **NL** `connector:digid` - Logius connects only government bodies and organisations with a legal public task, and DigiD gives a BSN, not a birth date (see `docs/connectors/digid.md`).
- **JP** `mynumber_attested` - Not in v1 (PROTOCOL.md 4d.4b): J-LIS publishes no OID for the birth-date field, gives revocation lists only to certified verifiers, and the Digital Agency requires a certified platform operator. https://www.digital.go.jp/policies/mynumber/private-business/jpki-introduction
- **JP** `mdoc_app` - My Number Card in Google Wallet (Android): it is a Japanese photo-ID mdoc, not an mDL or EU PID, and the V18 server accepts only `org.iso.18013.5.1.mDL` and `eu.europa.ec.eudi.pid.1`. Apple says Japan defines its own namespace `org.iso.23220.1.jp`. The Digital Agency gives the specs out only on request, and verifiers need certification. https://www.digital.go.jp/en/policies/mynumber/mynumbercard-mdoc , https://developer.apple.com/wallet/get-started-with-verify-with-wallet/
- **JP** `mdoc_wallet` - My Number Card in Apple Wallet: Apple documents it for apps only. For websites, Apple says it "intend[s] to support" the W3C request API, so web use has not shipped. It also has the document-type problem above. https://developer.apple.com/wallet/get-started-with-verify-with-wallet/
- **DK** `emrtd_attested[I]` - Denmark has no national ID card with a chip, and it is not bound by the EU ID card rule. [S:EU-ID]
- **IE** `emrtd_attested[I]` - Ireland issues no national ID card. [S:EU-ID]
- **GB** `emrtd_attested[I]` - The UK has no national ID card.

## Unconfirmed (left out of the file until a source confirms it)

- **EE** `emrtd_attested[I]` - The ID card has had a contactless interface since the December 2018 card generation, but the documents read (the card's PKI application spec on id.ee, and RIA's NFC note) show only the signing and login application. No source showed an ICAO travel-document application.
- **FI** `emrtd_attested[I]` - Fingerprints have been stored on the card since 2 August 2021 (Act 694/2021), but no source confirmed the chip can be read contactlessly. poliisi.fi blocks automated reading, and PRADO entries disagree (contact vs contactless).
- **LI** `emrtd_attested[I]` - llv.li mentions a new ID card with a "high-security encrypted chip" for biometrics (project page, July 2024), but its start date was not confirmed, and llv.li blocks automated reading.
- **DK** `emrtd_attested[A,C,I]` - Denmark is not bound by the EU residence permit rule, and no Danish source was checked.
- **IE** `emrtd_attested[A,C,I]` - Ireland is not bound by the EU residence permit rule, and its IRP card was not confirmed to have a chip.
- **DK** `mdoc_app` - Denmark's AltID wallet (launched 3 June 2026) has an ID card and an age proof, but its format and how apps request it are not published, and V18 accepts only an mDL or EU PID. https://www.digst.dk/it-loesninger/altid/
- **IT** `mdoc_app` - IT-Wallet: whether a PID or mDL can be presented to private apps or websites, and in which format, could not be confirmed.
- **FR** `mdoc_app` - France Identité is live but not certified as an EU wallet, and remote presentation of an mDL or PID was not confirmed.
- **GB** `mdoc_wallet` - The Google Wallet ID pass uses doc types `com.google.wallet.idcard.1` or `org.iso.23220.photoid.1`, which the V18 server doesn't accept. UK availability was not confirmed either. https://developers.google.com/wallet/identity/verify/accepting-ids-from-wallet-online
- **EU** `mdoc_app` - Wallet IDs in every other EU/EEA country (and `mdoc_wallet` everywhere): no launched wallet was found that gives apps or websites an mDL or EU PID with `age_over_18` today. The EU deadline for wallets is 24 December 2026, so check again then. https://www.eideasy.com/blog/eu-digital-identity-wallets-july-2026
- **EU** `mdoc_wallet` - The EU age verification app: the Commission called it technically ready on 15 April 2026, and countries are to roll it out by the end of 2026. It gives a proof-of-age attestation, not an mDL or EU PID, so the V18 server can't accept it as built. No country's launch was confirmed. https://commission.europa.eu/news-and-media/news/commission-urges-fast-rollout-age-verification-app-2026-04-29_en
- **LK** `emrtd_attested[P]` - Sri Lanka chip passports: unclear. A Department of Immigration notice of 27 July 2024 planned e-passports from 1 January 2025, but no source confirms issuance began. A Sunday Times headline of 11 October 2026 says Sri Lanka "still awaits e-passports" (the article page could not be opened). The department's own site (updated 20 November 2026) doesn't mention e-passports. https://www.adaderana.lk/news/100809/notice-on-issuing-new-e-passports- , https://www.immigration.gov.lk/pages_e.php?id=65
- **AE** `emrtd_attested[I]` - Emirates ID, and also the national ID cards of IL, SA, QA, KW, PK, BD, NP, CN, HK, TW, KR, MY, TH, ID and IN: no source shows an ICAO 9303 chip that anyone can read with NFC, so none are listed.
