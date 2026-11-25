# Add V18 age checks to your website

V18 lets your visitors prove they are 18 or older **without telling you who they are**. Your site
learns one thing: "18+: yes". You never see a name, a birthday, an ID number or a face.

You add **two lines** to your page and **two routes** to your server. That's it.

> Status: web kit release 1.0.0 (files in `sdk-web/release/`). It was tested against the dev V18
> server (`npm run dev --prefix server`, port 8080) with real tickets. There is no production V18
> server yet: `https://api.v18.example` and `https://cdn.v18.example` below are placeholders.

---

## How it works (in plain words)

1. A visitor presses **Verify age** on your page. The V18 widget opens.
2. The widget asks **your server** for a one-time number, called a **challenge**.
3. The visitor proves their age in one of these ways:
   - **Their phone**: they scan a QR code with the V18 app, which checks their ID.
   - **V18 for Windows**: the age card saved on their PC, unlocked with Windows Hello.
   - **A phone wallet ID**: their browser asks the ID in their phone's wallet (a mobile driving
     licence or an EU digital identity) for one fact, "over 18". This option shows only in
     browsers that can do it, and only if the V18 server accepts wallet IDs.
4. V18 seals a **one-time ticket** that names your site and your challenge. The widget gives it
   to **your server**.
5. Your server checks the seal with a small library (Node or Python). If it passes, the visitor
   is 18+. Save that in their session, like a login.

Every way ends in the same kind of ticket, so your server code is the same for all of them.

Your server checks the ticket **offline** with V18's public key. It does not call V18 for each
visitor.

**Never trust the browser alone.** Anyone can change what runs in their own browser. Only your
server's check counts.

---

## 1. Two lines in your page

```html
<script src="https://cdn.v18.example/v18-1.0.0.min.js" integrity="sha384-tcKbdf6aC+sdgJWk92+rILbbF4VcEv1EQedM0Dx4XyzEkRg/bkIK3xYpzUrm0BOy" crossorigin="anonymous" data-v18-server="https://api.v18.example"></script>
<button data-v18-min-age="18" data-v18-redirect="/members">Verify age</button>
```

- **`integrity`** is the file's fingerprint (Subresource Integrity). The browser refuses to run the
  script if even one byte differs, so a hacked CDN can't change it. The value for each release is
  in `sdk-web/release/SRI.txt`, and `sdk-web/release/embed.html` has these two lines ready to copy.
  If you host the file yourself, copy it **byte for byte**.
- **`data-v18-server`** is the V18 server. Always set it. Without it the widget uses the
  placeholder `https://api.v18.example`.
- While developing: use `data-v18-server="http://localhost:8080"`. The demo site shows the same
  embed working with SRI (section 8).

When someone presses the button, the widget:

- asks your server for a challenge with `POST /v18/challenge`,
- runs the check (QR code for a phone, V18 for Windows, or a phone wallet ID),
- sends the ticket to your server with `POST /v18/verify` and the body `{"ticket": "..."}`,
- if your server says yes (any 2xx reply), shows "You're verified as 18+", then goes to
  `data-v18-redirect` (or reloads the page).

### Button options

| Attribute | What it does | Default |
|-----------|--------------|---------|
| `data-v18-min-age` | The age you need. This also turns the button into a V18 button | `18` |
| `data-v18-challenge-url` | Where the widget gets a challenge (POST, returns `{"challenge": "..."}`) | `/v18/challenge` |
| `data-v18-challenge` | A challenge your server already put in the page. Then no challenge request is made | (none) |
| `data-v18-verify-url` | Where the widget sends the ticket. `none` means you handle it yourself | `/v18/verify` |
| `data-v18-redirect` | Where to go after success | reload the page |
| `data-v18-server` | The V18 server. Can also go on the `<script>` tag | `https://api.v18.example` (placeholder) |
| `data-v18-theme` | `auto` (follows the visitor's system), `light` or `dark` | `auto` |

### Events

The button fires two events you can listen to:

- `v18:verified`: your server accepted the ticket. `event.detail` is `{ticket, response}`.
  Call `event.preventDefault()` to stop the redirect or reload.
- `v18:error`: something went wrong. `event.detail.error` says what.

### JavaScript instead of a button

For single-page apps:

```js
V18.verify({
  minAge: 18,
  serverUrl: 'https://api.v18.example',
  challengeUrl: '/v18/challenge',  // or: challenge: '<one your server made>'
  verifyUrl: '/v18/verify',        // leave out to send the ticket yourself in onSuccess
  onSuccess: (ticket, yourServersReply) => router.push('/members'),
  onError: (err) => console.warn(err),
});
```

If you bundle your own JavaScript, install the widget package instead of using a script tag:
`npm install ./v18-widget-1.0.0.tgz` (from `sdk-web/release/`), then `import V18 from '@v18/widget'`.

---

## 2. Two routes on your server

Both libraries check every rule of the V18 protocol (listed in section 4). They also include a
`ChallengeStore` that makes and remembers one-time challenges for you.

The packages are not on npm or PyPI yet. Install them from `sdk-web/release/`:

```bash
npm install ./v18-verify-1.0.0.tgz
```

```bash
pip install v18_verify-1.0.0-py3-none-any.whl
```

### Node.js (Express)

Library: `@v18/verify`. It uses only Node's built-in `crypto` and needs Node 20 or newer.
This code was run against the dev V18 server with a real ticket.

```js
// server.js: a small Express site with V18 (npm install express cookie-parser ./v18-verify-1.0.0.tgz)
const express = require('express');
const cookieParser = require('cookie-parser');
const { V18Verifier, ChallengeStore } = require('@v18/verify');

const SITE_ORIGIN = 'http://localhost:4000';      // exactly what the browser shows
const V18_SERVER = 'http://localhost:8080';       // the V18 server (dev)

const verifier = new V18Verifier({ serverUrl: V18_SERVER, origin: SITE_ORIGIN, minAge: 18 });
const challenges = new ChallengeStore();          // in memory: one process
const adults = new Map();                         // visit ID -> "18+ until" (ms)

const app = express();
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

// 1. Every browser gets a random visit ID in an HttpOnly cookie.
app.use((req, res, next) => {
  let id = req.cookies.visit;
  if (!id) {
    id = ChallengeStore.newVisitId();
    res.cookie('visit', id, { httpOnly: true, sameSite: 'lax' /* , secure: true on HTTPS */ });
  }
  req.visitId = id;
  next();
});

// 2. Refuse POSTs from other websites.
app.use((req, res, next) => {
  const o = req.get('origin');
  if (req.method === 'POST' && o && o !== SITE_ORIGIN) return res.status(403).end();
  next();
});

// 3. The widget asks for a fresh challenge for this visit.
app.post('/v18/challenge', (req, res) => {
  res.json(challenges.create(req.visitId));
});

// 4. The widget sends the ticket. Check it HERE, on your server.
app.post('/v18/verify', async (req, res) => {
  const result = await verifier.verifyTicket(req.body.ticket, {
    expectedChallenge: challenges.checker(req.visitId), // uses the challenge up (one time only)
  });
  if (!result.valid) return res.status(403).json({ ok: false, code: result.code, error: result.error });
  adults.set(req.visitId, Date.now() + 60 * 60 * 1000); // 18+ for one hour
  res.json({ ok: true, minAge: result.ticket.minAge });
});

// 5. Protect your 18+ pages.
app.get('/members', (req, res) => {
  if (!(adults.get(req.visitId) > Date.now())) return res.redirect('/');
  res.send('<h1>Welcome in</h1>');
});

app.listen(4000);
```

A fuller example is the demo site: `sdk-web/demo-site/src/server.ts`.

### Python (Flask)

Library: `v18_verify`. It uses the `cryptography` package and needs Python 3.9 or newer.
The complete, runnable file is `sdk-web/verify-python/examples/flask_site.py`; this is the part
that matters. It was run against the dev V18 server with a real ticket.

```python
import time
from flask import Flask, abort, jsonify, request, session
from v18_verify import ChallengeStore, V18Verifier

SITE_ORIGIN = "http://localhost:5000"
app = Flask(__name__)
app.secret_key = "set-a-long-random-secret"
verifier = V18Verifier(server_url="http://localhost:8080", origin=SITE_ORIGIN)
challenges = ChallengeStore()

def visit_id():
    if "visit" not in session:
        session["visit"] = ChallengeStore.new_visit_id()
    return session["visit"]

@app.before_request
def refuse_cross_site_posts():
    if request.method == "POST" and request.headers.get("Origin") not in (None, SITE_ORIGIN):
        abort(403)

@app.post("/v18/challenge")
def v18_challenge():
    return jsonify(challenges.create(visit_id()).to_dict())

@app.post("/v18/verify")
def v18_verify():
    ticket = (request.get_json(silent=True) or {}).get("ticket")
    result = verifier.verify_ticket(ticket, expected_challenge=challenges.checker(visit_id()), min_age=18)
    if not result.valid:
        return jsonify(ok=False, code=result.code, error=result.error), 403
    session["adult_until"] = int(time.time()) + 3600
    return jsonify(ok=True, minAge=result.ticket.min_age)
```

Django, FastAPI and others work the same way: one route that returns a challenge, one route
that calls `verify_ticket` and then marks the session as 18+.

### Any other language

There is no library for other languages yet, but the rules in section 4 are the whole recipe.
The signature is a standard RSA-PSS signature (SHA-384, MGF1-SHA-384, salt length 48), which most
crypto libraries can check. Copy the test cases in `sdk-web/test-vectors/v1-tickets.json`: your
code must give the same answer for every case.

---

## 3. Challenges: the one-time numbers

A challenge is a random number your server makes for **this visit**. The visitor's ticket must
contain it. It stops someone from reusing a ticket they copied from another visitor or another
day, the same way a bank OTP only works once.

The rules:

- **Make a new one for each check.** `challenges.create(visitId)` gives 64 random hex characters.
- **Keep it on your server, tied to the visit** (session cookie, session store). The browser
  never gets to choose it.
- **Use it once.** `challenges.checker(visitId)` removes it when a ticket uses it.
- **Short life.** It stops working after 5 minutes (you can change `ttlSeconds`).
- A visit can hold up to 5 open challenges (two tabs, a "Try again"). Older ones are dropped.

**More than one server or worker process?** `ChallengeStore` keeps challenges in memory, so it
only works inside one process. With several (for example gunicorn with 4 workers, or several
machines), keep the challenge in your shared session store instead, and pass the string:

```python
session["v18_challenge"] = secrets.token_hex(32)          # in /v18/challenge
...
expected = session.pop("v18_challenge", None)            # in /v18/verify: pop = use once
result = verifier.verify_ticket(ticket, expected_challenge=expected)
```

**Putting the challenge in the page** also works: render it into the button as
`data-v18-challenge="..."`. The widget then needs no challenge route. Make a fresh one each time
you render the page.

---

## 4. What the libraries check

A ticket is accepted only if **all** of these are true (V18 protocol version 1):

| # | Check | If not, the code is |
|---|-------|---------------------|
| 1 | The ticket's key is in V18's key list (`/v1/keys`) and expired no more than 10 minutes ago | `UNKNOWN_KEY`, `KEY_EXPIRED` (also `KEY_NOT_YET_VALID`) |
| 2 | V18's seal (RSA-PSS SHA-384 signature) is valid | `INVALID_SIGNATURE` |
| 3 | The ticket says version 1 | `UNSUPPORTED_VERSION` |
| 4 | The ticket was made for **your** origin (exactly, e.g. `https://example.com`) | `ORIGIN_MISMATCH` |
| 5 | The ticket has the challenge you gave this visit | `CHALLENGE_MISMATCH`, `CHALLENGE_REQUIRED` |
| 6 | V18's key certifies at least your age. The library uses the **key's** age, never the age written inside the ticket | `AGE_INSUFFICIENT` |
| 7 | The ticket is fresh: at most 5 minutes long, and now is inside its time window (1 minute of clock drift allowed) | `TICKET_EXPIRED`, `TICKET_NOT_YET_VALID`, `TICKET_LIFETIME_INVALID` |
| 8 | The ticket was not used before | `REPLAY_DETECTED` |

Other codes: `INVALID_FORMAT` and `MALFORMED_PAYLOAD` (not a V18 ticket), `KEYS_UNAVAILABLE`
(could not download V18's keys; try again later), `CONFIG_ERROR` (your code passed a bad
origin or age).

What to show visitors: for any refusal, "That didn't work. Please try again." The widget already
shows your server's `error` text and offers "Try again". Don't show visitors a code as if it were
their fault: most codes mean a stale or copied ticket.

The libraries never throw for a bad ticket. They return `{valid: false, code, error}`.

---

## 5. Phone wallet IDs

Some browsers can ask the ID saved in a phone's wallet for one fact. V18 uses this to ask
**only "over 18: yes or no"** (`age_over_18`), from a mobile driving licence (ISO 18013-5 mDL) or
an EU digital identity (PID).

**You don't need to do anything for it.** The widget handles it, and your server gets the same
ticket as for the phone app. Things worth knowing:

- **When the option shows.** "Use a phone wallet ID" appears only when both are true: the
  visitor's browser has the Digital Credentials API (on an HTTPS page), and the V18 server says it
  accepts wallet IDs (`GET /v1/health` reports `methods.mdoc_wallet: "ready"`). Otherwise the
  option is simply not there.
- **What happens.** The widget asks V18 for the question to send (`POST /v1/wallet/request`),
  hands it to the browser, and the browser shows its own screen (often a QR code to scan with the
  phone that holds the wallet). The wallet's answer goes back to V18
  (`POST /v1/wallet/verify`), which checks the ID's digital seal against the list of ID issuers it
  trusts, checks that the answer was made just now for your site, and then gives the widget a
  normal one-time ticket.
- **What V18 sees.** With the phone app and V18 for Windows, V18 seals the ticket without seeing
  it. With a wallet ID, V18 checks the wallet's answer itself and makes the ticket, then forgets
  the answer. Your site still learns only "18+: yes". The widget tells the visitor this.
- **Which IDs work** depends on which issuers the V18 server trusts, not on your site.
- **If your page puts the widget inside an iframe**, the iframe needs
  `allow="digital-credentials-get"`. The normal script tag on your own page needs nothing.

---

## 6. Which IDs work in which country

This list is made from V18's country catalog (`catalog/countries.json`). It says which ways to
prove age the **V18 apps** support in each country. Whatever your visitors use, your site gets
the same ticket. What a particular V18 server offers can be smaller (for example, logins appear
only once V18 has an agreement with that provider): `GET /v1/catalog` on the V18 server lists what
it really supports. Phone wallet IDs in the browser (section 5) are not listed by country: they
depend on the ID issuers the V18 server trusts.

To refresh this section after the catalog changes, run `npm run countries --prefix sdk-web`.

<!-- COUNTRIES:START (made by sdk-web/scripts/country-table.mjs from catalog/countries.json; do not edit by hand) -->

54 countries and 124 ways to prove age, from catalog version 1 (updated 2026-11-24).

### Europe

| Country | Way to prove age | IDs it accepts | How private | Works on | Needs |
|---------|------------------|----------------|-------------|----------|-------|
| Austria (AT) | ID card (chip) | Austrian ID card (Personalausweis) issued since 2 August 2021 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Austrian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Austrian residence permit for non-EU citizens, Austrian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Belgium (BE) | ID card (chip) | Belgian eID card | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Belgian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Belgian residence permit for non-EU citizens, Belgian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | itsme | itsme app | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
| Bulgaria (BG) | ID card (chip) | Bulgarian ID card (лична карта) issued since 17 June 2024 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Bulgarian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Bulgarian residence permit for non-EU citizens, Bulgarian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Croatia (HR) | ID card (chip) | Croatian ID card (osobna iskaznica) issued since 2 August 2021 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Croatian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Croatian residence permit for non-EU citizens, Croatian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Cyprus (CY) | ID card (chip) | Cypriot ID card issued since August 2020 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Cypriot passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Cypriot residence permit for non-EU citizens, Cypriot residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Czechia (CZ) | ID card (chip) | Czech ID card (občanský průkaz) issued since 2 August 2021 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Czech passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Czech residence permit for non-EU citizens, Czech residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Denmark (DK) | Passport (chip) | Danish passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | MitID | MitID app | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
| Estonia (EE) | Passport (chip) | Estonian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Estonian residence permit for non-EU citizens, Estonian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Finland (FI) | Passport (chip) | Finnish passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Finnish residence permit for non-EU citizens, Finnish residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| France (FR) | ID card (chip) | French ID card (carte nationale d'identité) in the bank-card format, issued since 2021 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | French passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | French residence permit for non-EU citizens, French residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | FranceConnect | A FranceConnect login, for example impots.gouv.fr or ameli.fr | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
| Germany (DE) | ID card (chip) | German ID card (Personalausweis) issued since 1 November 2010 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | German passport (Reisepass) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | German residence permit for non-EU citizens, German residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Greece (GR) | ID card (chip) | Greek ID card (new type with chip, issued since 2023) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Greek passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Greek residence permit for non-EU citizens, Greek residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Hungary (HU) | ID card (chip) | Hungarian e-ID card (eSzemélyi) issued since 1 January 2016 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Hungarian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Hungarian residence permit for non-EU citizens, Hungarian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Iceland (IS) | ID card (chip) | Icelandic ID card (nafnskírteini) issued since March 2024 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Icelandic passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Icelandic residence permit for non-EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Ireland (IE) | Passport (chip) | Irish passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Italy (IT) | ID card (chip) | Italian electronic ID card (CIE 3.0) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Italian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Italian residence permit for non-EU citizens, Italian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | CIE (Entra con CIE) | Italian electronic ID card (CIE) with the CieID app | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
|  | SPID | SPID digital identity | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
| Latvia (LV) | ID card (chip) | Latvian eID card | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Latvian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Latvian residence permit for non-EU citizens, Latvian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Liechtenstein (LI) | Passport (chip) | Liechtenstein passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Liechtenstein residence permit for non-EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Lithuania (LT) | ID card (chip) | Lithuanian ID card | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Lithuanian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Lithuanian residence permit for non-EU citizens, Lithuanian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Luxembourg (LU) | ID card (chip) | Luxembourg ID card | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Luxembourg passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Luxembourg residence permit for non-EU citizens, Luxembourg residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | itsme | itsme app | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
| Malta (MT) | ID card (chip) | Maltese ID card (new type with CAN, issued since 2020) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Maltese passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Maltese residence permit for non-EU citizens, Maltese residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Netherlands (NL) | ID card (chip) | Dutch ID card (identiteitskaart) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Dutch passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Dutch residence permit for non-EU citizens, Dutch residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | itsme | itsme app | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
| Norway (NO) | ID card (chip) | Norwegian national ID card (nasjonalt ID-kort) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Norwegian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Norwegian residence permit for non-EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | BankID | Norwegian BankID | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
| Poland (PL) | ID card (chip) | Polish ID card (e-dowód) issued since 4 March 2019 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Polish passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Polish residence permit for non-EU citizens, Polish residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Portugal (PT) | ID card (chip) | Portuguese Citizen Card (Cartão de Cidadão) issued since June 2024, with a CAN on the front | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Portuguese passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Portuguese residence permit for non-EU citizens, Portuguese residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Romania (RO) | ID card (chip) | Romanian electronic ID card (carte electronică de identitate, CEI) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Romanian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Romanian residence permit for non-EU citizens, Romanian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Slovakia (SK) | ID card (chip) | Slovak ID card (občiansky preukaz) issued since 1 December 2022 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Slovak passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Slovak residence permit for non-EU citizens, Slovak residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Slovenia (SI) | ID card (chip) | Slovenian biometric ID card (osebna izkaznica) issued since 28 March 2022 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Slovenian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Slovenian residence permit for non-EU citizens, Slovenian residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Spain (ES) | ID card (chip) | Spanish ID card (DNIe 3.0 or newer) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Spanish passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Spanish residence permit for non-EU citizens, Spanish residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Sweden (SE) | ID card (chip) | Swedish national ID card (nationellt id-kort) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Swedish passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Swedish residence permit for non-EU citizens, Swedish residence card for family members of EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | BankID | Swedish BankID app | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
|  | Freja eID | Freja eID app | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
| Switzerland (CH) | ID card (chip) | Swiss ID card with chip (optional, issued since 2 November 2026) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Swiss passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Residence permit (chip) | Swiss residence permit for non-EU citizens | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| United Kingdom (GB) | Passport (chip) | UK passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |

### Asia

| Country | Way to prove age | IDs it accepts | How private | Works on | Needs |
|---------|------------------|----------------|-------------|----------|-------|
| Bangladesh (BD) | Passport (chip) | Bangladeshi e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| China (CN) | Passport (chip) | Chinese e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Hong Kong (HK) | Passport (chip) | HKSAR e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| India (IN) | Aadhaar QR | Aadhaar letter, Aadhaar PVC card, e-Aadhaar PDF, mAadhaar app QR | Zero-knowledge proof: nothing about you leaves your device | Android phone, Windows PC | camera |
|  | Passport (chip) | Indian e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | DigiLocker | DigiLocker account | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
| Indonesia (ID) | Passport (chip) | Indonesian e-passport (paspor elektronik) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Israel (IL) | Passport (chip) | Israeli biometric passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Japan (JP) | My Number Card (chip) | My Number Card (マイナンバーカード) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone), your login password |
|  | Passport (chip) | Japanese passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Kuwait (KW) | Passport (chip) | Kuwaiti e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Malaysia (MY) | Passport (chip) | Malaysian passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Nepal (NP) | Passport (chip) | Nepali e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Pakistan (PK) | Passport (chip) | Pakistani e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Philippines (PH) | Passport (chip) | Philippine e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Qatar (QA) | Passport (chip) | Qatari e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Saudi Arabia (SA) | Passport (chip) | Saudi e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Singapore (SG) | Passport (chip) | Singapore passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Singpass | Singpass app (Myinfo) | Login: V18 sees your birth date for a moment and keeps nothing | Android phone, Windows PC | your login password |
| South Korea (KR) | Passport (chip) | South Korean e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Sri Lanka (LK) | no ways listed in the catalog | | | | |
| Taiwan (TW) | Passport (chip) | Taiwan (ROC) e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Thailand (TH) | Passport (chip) | Thai e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Turkey (TR) | ID card (chip) | Turkish ID card (T.C. Kimlik Kartı) issued since 2017 | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Turkish e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| United Arab Emirates (AE) | Passport (chip) | UAE e-passport | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
| Vietnam (VN) | ID card (chip) | Vietnamese chip ID card (Căn cước công dân gắn chip, since 2021), Vietnamese ID card (Căn cước, since 1 July 2024) | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |
|  | Passport (chip) | Vietnamese passport with chip | Checked on your phone: only "18+" leaves it | Android phone | NFC (tap the ID on the phone) |

<!-- COUNTRIES:END -->

---

## 7. Before you go live

- **HTTPS**, and set `origin` to exactly what the browser's address bar shows:
  `https://www.example.com` is not `https://example.com`.
- **Set `data-v18-server`** to the production V18 server, and keep the `integrity` value that
  matches the widget file you load.
- **CORS is already handled by V18.** The widget's V18 endpoints (`/v1/health`, `/v1/keys`,
  `/v1/pairing/...` and `/v1/wallet/...`) accept requests from any website, without cookies. V18
  checks that the page's `Origin` matches the site the ticket is for.
- **Content Security Policy.** If your site has one, allow:
  - `script-src` the widget's address (for example `https://cdn.v18.example`),
  - `connect-src` the V18 server (for example `https://api.v18.example`),
  - `style-src 'unsafe-inline'`: the widget draws itself with its own styles inside a Shadow DOM.
  The demo site runs with a strict policy like this, including a nonce for its own scripts.
- **Several processes or servers?** Share the replay cache (rule 8) and the challenges. In Node,
  pass `replayCache` with your own `checkAndRemember`. In Python, pass `replay_cache` with your
  own `check_and_remember`. Redis `SET ticketId 1 NX EXAT <time>` does the job.
- **Keep the 18+ session short**, like a login (the demo uses one hour).
- **Don't log tickets.** They are anonymous, but there is no reason to keep them.
- **If V18 is down**, keys your server already downloaded keep working, so visitors with
  tickets can still get in. New checks need V18.

---

## 8. Try it on your computer

Start the V18 server, build the web kit, and start the demo site:

```bash
npm run dev --prefix server
```

```bash
npm run build --prefix sdk-web
```

```bash
npm start --prefix sdk-web/demo-site
```

Open http://localhost:3000 (use `localhost`, not `127.0.0.1`: tickets are locked to one origin).
In this **dev mode** the demo site has a **Browser test wallet** that acts as the V18 phone app
inside the browser, so you can try everything without a phone. It shows only when the V18 server
is in dev mode.

To see what a real site would look like, run the demo in **production mode**: no test wallet, no
developer tools, and the release widget with its `integrity` hash. Build the release first:

```bash
npm run release --prefix sdk-web
```

```bash
V18_SERVER=http://localhost:8080 SITE_ORIGIN=http://localhost:3000 npm run start:prod --prefix sdk-web/demo-site
```

Production mode needs `V18_SERVER` and `SITE_ORIGIN`. `docs/web/DEPLOY-DEMO.md` shows the same
in PowerShell, and covers the Dockerfile.
