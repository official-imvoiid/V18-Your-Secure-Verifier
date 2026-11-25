# V18: Your Secure Verifier

**Prove you are 18+ without saying who you are.**

> **Final-year project prototype.** V18 is a privacy-first age check that any website can add in
> two lines. It was built as a final-year engineering project by a team of four students in India,
> as a working prototype of what a lawful, privacy-preserving age check could look like.

Most age checks today ask for a photo of your ID or a face scan, and send it to a company's server.
V18 does the opposite. Your own phone or PC checks your ID (an Aadhaar QR, a passport or ID-card
chip, a phone wallet ID, or a government login), and the website receives only a one-time ticket
that says "18+". The website never learns your name, birthday, photo or ID number, and V18 cannot
tell which websites you visit.

## What is in this repository

| Part | Folder | What it does | Tests |
|------|--------|--------------|-------|
| Server | `server/` | Issues device-bound age cards, signs one-time tickets with RFC 9474 blind signatures, checks Aadhaar zero-knowledge proofs and Android hardware attestation. Node.js, SQLite or PostgreSQL | 200 |
| Login connectors | `connectors/` | 12 government and bank logins (Singpass, DigiLocker, UAE PASS, BankID, MitID, itsme, FranceConnect, SPID, CIE, DigiD, Freja) | 161 |
| Website kit | `sdk-web/` | The 2-line widget, ticket checkers for Node and Python, and a demo shop | 195 |
| Android app | `mobile/` | Flutter app: Aadhaar proofs on the phone, passport and ID-card chip checks, fingerprint approval | 198 |
| Windows app | `windows/` | Electron app: Aadhaar proofs on the PC, Windows Hello approval, card from the phone | 130 |
| Country catalog | `catalog/` | 54 countries in Europe and Asia, with the ways each one can prove age and a source for each | 12 |
| Product tests | `tests/` | End-to-end tests of the real server, real cryptography and real website checks, in production mode and through whole user journeys | 20 |
| Specification | `docs/PROTOCOL.md` | The protocol between apps, server and websites, and every design decision | |

Each part's own guide is in `docs/<part>/`. In total, **916 automated tests** pass
(`npm run test:all`).

## Ways to prove age

- **Aadhaar** (India): a zero-knowledge proof made on the phone or PC. Nothing but "18+" leaves the device.
- **Passports, chip ID cards and residence permits**: the phone reads and checks the chip itself,
  and proves it is a genuine, unmodified V18 app with Android hardware attestation.
- **Phone wallet IDs** in the browser (digital ID wallets and mobile driving licences). Built and
  tested with test credentials; they switch on when real wallet issuers' certificates are added.
- **Government and bank logins** in 12 countries. These appear once each provider has registered
  the operator.
- **Card from your phone**: the Windows app gets its own age card from the phone.

**Not in this prototype:** a face-based age estimate (the best properly licensed model let 5.17% of
under-18s through, over the 5% safety limit), Japan's My Number Card (it needs Japanese government
certification), the Philippines' PhilSys QR (its signature format is not public), USB passport
readers on Windows, and zero-knowledge passport proofs.

## Try it

On Windows, double-click **`SETUP.bat`**. It asks for administrator rights, installs everything V18
needs (Git, Node.js, Python, Rust, Microsoft C++ Build Tools, and for the Android app also Java,
Flutter and the Android SDK), then builds V18 and runs every test. Then double-click
**`START-V18.bat`** to start the server and the demo shop at http://localhost:3000.

Or by hand:

```
npm run build             # build every part
npm run start:server      # V18 server on http://localhost:8080 (test mode)
npm run start:demo        # demo shop on http://localhost:3000
npm run start:windows     # Windows app
npm run test:all          # every test, with one summary table
```

Run the Android app from `mobile/` with Flutter (`flutter run`). The Android emulator reaches the
server at `http://10.0.2.2:8080`.

## Test mode and production mode

**Test mode** (`npm run start:server`) exists so that anyone can try V18 without a real ID document.
It adds one extra method, a **test identity**, and every app shows a red **TEST MODE** banner while
it talks to a test-mode server. Everything after the age card (device keys, blind signatures,
tickets and the website's checks) is the same real code the product uses.

**Production mode** (`npm run start:server:prod`) is the real product: test identities are refused,
and only real documents work. It needs its own secrets (`V18_KEK`, `V18_NULLIFIER_SECRET` and
`V18_AADHAAR_NULLIFIER_SEED`), keeps its signing keys encrypted in the database, and can use
PostgreSQL. `docs/server/DEPLOY.md` explains it. The product tests in `tests/` start the server in
production mode and check that it refuses test identities and protects its data.

## From prototype to live product

The code is complete. Putting V18 in front of real users needs things only the operator can get:

- a domain and hosting for the server (`docs/server/DEPLOY.md`)
- a Google Play developer account for the Android app
- a code-signing certificate for the Windows installer
- registration with each government or bank login provider
- an independent security review of the cryptography, a licence for the code, and legal review
  for each country's age-check law

---

## 1. The problem

Age laws are arriving everywhere:

| Where | Law |
|-------|-----|
| UK | Online Safety Act. Strong age checks have been enforced since 25 July 2025 |
| EU | Digital Services Act. The EU's own age app was declared "technically ready" in April 2026 |
| USA | Many state laws. The Supreme Court upheld Texas's law in *Free Speech Coalition v. Paxton* (June 2025) |
| Australia | Under-16 social media ban, in force since 10 December 2025 |
| India | DPDP Rules 2025. Parental consent is needed for users under 18 (Rule 10, reported to apply from 13 May 2027) |
| California | AB 1043. Phones and PCs must give apps an age bracket, from 1 January 2027 |

Today most sites check age by asking for **a photo of your ID** or **a face scan**, and sending it to
a company server. That is a privacy disaster waiting to happen. In September 2025, a support
vendor used by Discord was hacked, and Discord says government ID photos of about **70,000 users**
were exposed.

This project started as a face-based age estimator running on a server. It had the same problem:
people do not want to send their face to a server, and a face estimate is a guess, not proof.
So the project changed direction and became V18.

## 2. The idea in one line

**Prove the fact (18+), not the identity.**

The website learns only "18+ yes". Nobody, including us, learns who the person is or which sites they
visit.

## 3. How it works, as the user sees it

1. A website adds our small code, about 2 lines.
2. The user taps **Verify age**.
3. Our app (Android or Windows) checks their ID **on their own device**: a passport, ID card,
   Aadhaar or a phone wallet ID.
4. The app sends our server a **proof** that says "this person is 18+" and nothing else.
5. Our server checks the proof and gives back an **anonymous 18+ ticket**.
6. The website checks the ticket and lets them in.

## 4. Architecture

```
  WEBSITE                     USER'S DEVICE                  V18 SERVERS
  -------                     -------------                  ---------------
  [Verify age] ----(1)---->   V18 app
  + fresh challenge number    - reads ID chip or QR
                              - builds the proof
                              - stores nothing   ----(2)---->  check the proof
                                                               check the government seal  <-- trust lists
                                                               check the ID is not overused <-- secure storage
                              18+ ticket         <----(3)----  seal the ticket with our key
  website SERVER  <---(4)---  ticket
  checks our seal with our public key  ->  lets the user in
```

- **(1)** The website asks for a check and includes a one-time random number (the challenge).
- **(2)** Only the proof goes to our servers. The ID data never leaves the device.
- **(3)** Our servers send back a ticket sealed with our private key.
- **(4)** The website's **server** checks the seal. It never calls us for this, so tickets still
  work if our servers are down.

## 5. Two layers: age card and tickets

Think of a cinema membership:

| How often | Cinema | V18 |
|-----------|--------|---------|
| Once | Show ID at the counter, get a **membership card** | Scan your ID once, get an **age card** saved in the phone's secure chip, valid for 6 to 12 months |
| Every visit | Use the card to get a **ticket** | Touch your fingerprint, the phone makes a **one-time ticket** |

- Today: scan Aadhaar or a passport, the age card is saved, touch your fingerprint, and you are into website A.
- Tomorrow: just touch your fingerprint, get a new ticket, and you are into website A or B.
- After 6 to 12 months: the age card expires, so scan your ID again.

Every ticket looks different (blind signatures), so websites cannot tell it is the same person coming
back. Each ticket works once, so it cannot be copied or shared.

## 6. Why it is hard to cheat

The phone can always be hacked. That is fine, because **the phone cannot fake anything that matters.**

**Digital signatures (seals).** Each one has a secret **private key** that only its owner holds, and a
**public key** that everyone can see and use to check it. Nobody can make a valid seal without the
private key.

| Attack | Why it fails |
|--------|--------------|
| Change the date of birth | The ID is sealed by the government. Changed data breaks the seal, so our server rejects it |
| Make a fake Aadhaar QR | The hacker cannot make UIDAI's seal |
| Use copied passport data | Passport and ID chips have a key that cannot be copied (chip authentication). Only the real card can answer |
| Replay an old proof | Every check has a fresh random challenge, like a bank OTP. An old proof has the old number |
| Run a fake V18 server | Its tickets do not carry our seal, so the website rejects them |
| Switch off the check in the browser | Websites must check tickets **on their own server**, not in the browser |
| Make unlimited tickets from one ID | **Nullifiers** limit how many age cards one ID can make, without revealing which ID it is |

**What a hacked phone can still try (we say this openly):**

| Trick | Fix | How strong |
|-------|-----|------------|
| Use a real adult's ID, such as a parent's passport | The chip must be physically present (chip authentication), and every ticket needs the card owner's fingerprint or PIN on their own device | Medium: a parent who hands over both can still be misused |
| Run a modified app on a rooted phone | Android hardware attestation: the server accepts chip results only from a genuine V18 app on a locked, verified phone | Strong |
| Give the ticket to someone else | Ticket locked to that phone plus fingerprint, single use | Strong |

**In short:** faking an age is impossible because of the maths. Using someone else's real ID is hard but possible.
Every age-check system has that second problem, including the ones that collect your data.

## 7. When a child picks up an adult's phone

- **Fingerprint, face unlock or PIN** is needed for every ticket (Windows Hello on PC). The check happens only on the device.
- **Tickets are short-lived:** one session, a few hours at most.
- **Child accounts are refused:** if the phone or PC account is a child account (Google Family
  Link, Apple Family Sharing, the OS age signal), the app will not make a ticket.
- **Shared device mode:** on a family PC nothing is remembered, and every visit needs a fresh check.

**Limit:** if a child knows the parent's PIN, or the parent unlocks the phone for them, no system can stop that.

## 8. What we store and what we never store

| Never stored, anywhere | Stored safely (encrypted, copied to 2+ regions, backed up daily) |
|------------------------|----------------------------------------------------|
| ID scans and photos | Signing keys, inside a cloud key vault (KMS/HSM) |
| Name, date of birth, ID number | Nullifier list: anonymous hashes that stop ID reuse |
| Faces | Trust lists: the government issuer public keys |
| Who visited which site | Country rules: legal age and allowed methods |
| | Anonymous stats for audits, like "1,200 passport checks passed today" |

**If something goes wrong:**
- A server crashes: servers in another region keep working.
- The database is lost: a replica in another region takes over, and daily backups are restore-tested every month.
- A crash happens mid-check: the user taps "try again". No personal data is lost because none was saved.
- V18 is down: tickets people already have still work, because websites check them offline.

## 9. Which IDs work where

`catalog/countries.json` lists, for 54 countries in Europe and Asia, every way people there can
prove age with V18, with a source for each entry. A few examples:

| Where | Ways to prove age |
|-------|-------------------|
| India | Aadhaar QR (zero-knowledge proof), e-passport chip, DigiLocker login |
| Singapore | Singpass login, passport chip |
| Germany | Chip ID card, passport chip, residence permit |
| France, Italy | Chip ID card, passport chip, residence permit, and a national login (FranceConnect; SPID or CIE) |
| Most other countries | Passport chip |

The full table is in `docs/web/INTEGRATION.md`.

## 10. How it is built

| Part | Built with |
|------|------------|
| Server | Node.js 22, TypeScript, Express, SQLite or PostgreSQL, `@cloudflare/blindrsa-ts` (RFC 9474), snarkjs (Anon Aadhaar proofs), `@peculiar/x509` (Android attestation) |
| Android app | Flutter 3.47 and Dart, a Rust prover for Anon Aadhaar (Groth16), `dmrtd` for passport chips, Android Keystore with BiometricPrompt |
| Windows app | Electron and TypeScript, a Rust helper for Windows Hello keys, snarkjs for Aadhaar proofs |
| Website kit | TypeScript widget with no framework, verify libraries for Node.js and Python |
| Login connectors | TypeScript, `openid-client` and `jose` |

## 11. Adding V18 to a website

In the page:

```html
<script src="https://cdn.v18.example/v18-1.0.0.min.js" integrity="sha384-..." crossorigin="anonymous" data-v18-server="https://api.v18.example"></script>
<button data-v18-min-age="18">Verify age</button>
```

On the website's own server (Node.js; Python works the same way):

```js
const verifier = new V18Verifier({ serverUrl: V18_SERVER, origin: SITE_ORIGIN, minAge: 18 });
const result = await verifier.verifyTicket(req.body.ticket, { expectedChallenge: challengeForThisVisit });
```

`docs/web/INTEGRATION.md` is the full guide for website owners.

## 12. Honest limits

- A parent unlocking the phone for a child, or a child who knows the PIN.
- VPNs. UK porn traffic fell after the law, but VPN use jumped, and Ofcom says no method fully stops getting around checks.
- People with no ID document, no smartphone and no supported login cannot prove their age yet.
- Reading a real passport chip has been tested with recorded chip data; it needs a real Android phone with NFC to try live.
- Government and bank logins need the operator to register with each provider.
- Meeting a specific law (Ofcom "highly effective", DPDP authorised tokens) still needs legal review and
  probably certification, such as ISO/IEC 27566-1 or the UK Age Check Certification Scheme.

## 13. Research and sources

**Papers**
- Frigo & shelat, *Anonymous Credentials from ECDSA*, IACR ePrint 2024/2010 (the basis of Google's library)
- Paquin, Policharla & Zaverucha, *Crescent: Stronger Privacy for Existing Credentials*, [ePrint 2024/2013](https://eprint.iacr.org/2024/2013)
- Kaviani & Setty, [*Vega: Low-Latency Zero-Knowledge Proofs over Existing Credentials*](https://www.microsoft.com/en-us/research/wp-content/uploads/2026/05/Vega_Low-Latency-Zero-Knowledge-Proofs-over-Existing-Credentials.pdf) (Microsoft Research)
- Rosenberg et al., *zk-creds: Flexible Anonymous Credentials from zkSNARKs and Existing Identity Infrastructure*, IEEE S&P 2023
- Camenisch & Lysyanskaya (2001), the original anonymous credentials paper
- Chaum (1982), blind signatures
- NIST IR 8525 (2024), *Face Analysis Technology Evaluation: Age Estimation and Verification*

**Projects and reports**
- [Anon Aadhaar: how it works](https://documentation.anon-aadhaar.pse.dev/docs/how-does-it-work) and [GitHub](https://github.com/privacy-scaling-explorations/anon-aadhaar)
- [Google: open-sourcing zero-knowledge proofs for age assurance](https://blog.google/technology/safety-security/opening-up-zero-knowledge-proof-technology-to-promote-privacy-in-age-assurance/)
- [Microsoft Crescent library](https://www.microsoft.com/en-us/research/blog/crescent-library-brings-privacy-to-digital-identity-systems/)
- [EU age verification app declared ready (April 2026)](https://thenextweb.com/news/eu-age-verification-app-children-social-media)
- [Ofcom report on the use of age assurance (2026)](https://www.ofcom.org.uk/siteassets/resources/documents/online-safety/information-for-industry/age-assurance-report-2026/report-on-the-use-of-age-assurance.pdf)
- [DPDP Rules, Rule 10 text](https://www.dpdpa.com/dpdparules/rule10.html)
- [California AB 1043 FAQ](https://www.kelleydrye.com/viewpoints/blogs/ad-law-access/faq-digital-age-assurance-act-california-youth-safety-on-the-internet)
- [Discord ID breach](https://www.biometricupdate.com/202510/discord-partners-manual-age-verification-data-breach-includes-selfies)

## 14. Words used in this README

| Word | Meaning |
|------|---------|
| Seal / digital signature | Maths stamp that proves who made something and that nobody changed it |
| Private key | The secret seal. Only its owner has it |
| Public key | What the seal looks like. Everyone can see it and use it to check seals |
| Zero-knowledge proof | Proving something is true ("over 18") without showing the data behind it |
| Challenge | A one-time random number, like an OTP, so old proofs cannot be reused |
| Nullifier | An anonymous code that stops one ID being used too many times, without revealing the ID |
| Blind signature | We seal a ticket without seeing it, so we cannot link it to the person later |
| Enclave | A locked area of a server whose memory even its owners cannot read |
| NFC | The tap-to-read radio used for passport and ID-card chips |
