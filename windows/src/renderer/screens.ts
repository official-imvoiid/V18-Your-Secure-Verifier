// Main window screens, adapted from the V18 design mock-ups.
// Buttons carry data-act="<action>" (and data-arg). app.ts turns those into IPC calls.

import type { CatalogCountryView, CardView, ViewState } from '../main/view.js';
import type { PcMethod } from '../shared/catalog.js';
import { html, raw, type Raw } from './html.js';
import { icon, LOGO } from './icons.js';

export interface LocalUi {
  welcomePick: 'me' | 'shared';
  /** Country code picked on the country screen ("" = not picked yet). Never saved. */
  country: string;
  countrySearch: string;
  testKind: 'adult' | 'under18';
  confirmDelete: boolean;
  confirmShared: boolean;
}

const ok = (t: string | Raw) => html`<li>${raw(icon('check', 'ic y'))}<span>${t}</span></li>`;
const no = (t: string | Raw) => html`<li>${raw(icon('x', 'ic n'))}<span>${t}</span></li>`;

export function titleBar(v: ViewState, label = 'V18'): Raw {
  return html`<div class="tb drag">${raw(LOGO)}<span>${label}</span>${v.testMode ? raw('<span class="badge b-warn tb-badge">TEST MODE</span>') : ''}${
    v.testKey ? raw('<span class="badge b-err tb-badge">TEST KEY</span>') : ''
  }</div>`;
}

export function testBanners(v: ViewState): Raw {
  return html`${
    v.testMode
      ? html`<div class="testbar" role="status">${raw(icon('flask', 'ic s16'))}<span><b>TEST MODE.</b> This V18 server is a development server. Cards and tickets from it are for testing only.</span></div>`
      : ''
  }${
    v.testKey
      ? html`<div class="testbar err" role="status">${raw(icon('warn', 'ic s16'))}<span><b>TEST KEY.</b> Started with --v18-test-software-key: Windows Hello is OFF and keys are kept in memory only. Never use this for real.</span></div>`
      : ''
  }`;
}

function nav(v: ViewState): Raw {
  const s = v.screen;
  const sel = (on: boolean) => (on ? 'sel' : '');
  const shared = v.settings.sharedPc;
  return html`<nav class="nav" aria-label="V18">
<button class="navi ${sel(s === 'home')}" data-act="go" data-arg="home">${raw(icon('home'))}Home</button>
${shared ? '' : html`<button class="navi ${sel(s.startsWith('card-'))}" data-act="go" data-arg="card-country">${raw(icon('idcard'))}Get age card</button>`}
<button class="navi ${sel(s === 'seals')}" data-act="go" data-arg="seals">${raw(icon('shieldInfo'))}How seals work</button>
<span class="sp"></span>
<button class="navi ${sel(s === 'settings')}" data-act="go" data-arg="settings">${raw(icon('gear'))}Settings</button>
</nav>`;
}

function steps(cur: number, allDone = false): Raw {
  const names = ['Country', 'Method', 'Read ID', 'Build proof', 'Send proof', 'Saved'];
  return html`<div class="steps" aria-label="Steps">${names.map((n, i) => {
    const done = i < cur || allDone;
    const cls = done ? 'done' : i === cur ? 'cur' : '';
    return html`${i ? raw('<span class="ln"></span>') : ''}<span class="st ${cls}"><span class="n">${done ? raw(icon('check')) : String(i + 1)}</span>${n}</span>`;
  })}</div>`;
}

function notice(v: ViewState): Raw {
  if (!v.notice) return raw('');
  return html`<div class="ibar ok notice" role="status">${raw(icon('info'))}<span class="grow">${v.notice}</span><button class="x sm" data-act="dismiss-notice" aria-label="Dismiss">${raw(icon('x', 'ic s16'))}</button></div>`;
}

function helloWarning(v: ViewState): Raw {
  if (v.hello.ok || v.testKey || v.settings.sharedPc || v.hello.code === 'CHECKING') return raw('');
  const notSetUp = v.hello.code === 'HELLO_NOT_SET_UP';
  return html`<div class="ibar warn" role="status">${raw(icon('warn'))}<span class="grow"><span class="b">${notSetUp ? "Windows Hello isn't set up on this PC." : "Windows Hello isn't working."}</span> ${
    notSetUp ? 'V18 needs it to keep an age card here. Set up a PIN, face or fingerprint in Windows Settings.' : v.hello.detail ?? ''
  }</span>${notSetUp ? html`<button class="btn sm-btn" data-act="open-hello-settings">${raw(icon('external'))}Sign-in options</button>` : ''}</div>`;
}

function ageCard(c: CardView): Raw {
  return html`<div class="agecard ${c.testKey || c.method === 'test_dev' ? 'test' : ''}" role="img" aria-label="Your age card: 18+, ${c.methodLabel}, valid until ${c.validUntilLabel}">
<div class="row jb"><span class="row g8">${raw(LOGO)}<span class="b6">Age card</span></span><span class="meta">${c.method === 'test_dev' ? 'TEST card' : 'Holds one fact'}</span></div>
<div class="big">18+</div>
<div class="row jb"><span class="meta">${c.methodLabel}</span><span class="meta">${c.expired ? 'Expired ' : 'Valid until '}${c.validUntilLabel}</span></div>
</div>`;
}

function protectionLabel(c: CardView): string {
  switch (c.protection) {
    case 'tpm':
      return "This PC's security chip (TPM)";
    case 'hello':
      return 'Windows Hello (no TPM proof)';
    case 'test-software':
      return 'Memory only (TEST key)';
    default:
      return c.testKey ? 'Memory only (TEST key)' : 'Windows Hello';
  }
}

// ------------------------------------------------------------------ screens

function welcome(v: ViewState, ui: LocalUi): Raw {
  const me = ui.welcomePick === 'me';
  return html`<main class="main solo g14">
<div class="seal">${raw(LOGO)}</div>
<h1 class="h1 mt10">Welcome to V18</h1>
<p class="p mw520">Prove you're 18+ on any website, without sharing who you are. First, one quick question.</p>
<h2 class="h3 mt4">Who uses this PC?</h2>
<div class="row g12 welcome-opts">
<button class="opt tall ${me ? 'on' : ''}" data-act="welcome-pick" data-arg="me" aria-pressed="${String(me)}">
<span class="row w100"><span class="oi">${raw(icon('pc'))}</span><span class="rad ${me ? 'on' : ''} ml-auto"></span></span>
<span class="t">Just me</span><span class="d">Keep an age card on this PC. Unlock it with Windows Hello each time.</span>
</button>
<button class="opt tall ${!me ? 'on' : ''}" data-act="welcome-pick" data-arg="shared" aria-pressed="${String(!me)}">
<span class="row w100"><span class="oi">${raw(icon('people'))}</span><span class="badge b-acc">Best for family PCs</span><span class="rad ${!me ? 'on' : ''} ml-auto"></span></span>
<span class="t">Family or shared PC</span><span class="d">Nothing is remembered. Every site visit needs a fresh check.</span>
</button>
</div>
<p class="sm">You can change this any time in Settings.</p>
<button class="btn pri mw200" data-act="first-run">Continue</button>
<p class="sm row g6">${raw(icon('chip', 'ic s16'))}V18 checks that Windows Hello (and the TPM security chip, if there is one) can lock your card before it saves anything.</p>
</main>`;
}

function homeEmpty(v: ViewState): Raw {
  return html`<h1 class="h1">Home</h1>
${notice(v)}${helloWarning(v)}
<div class="card row g36 pad-lg">
<div class="seal ml9">${raw(LOGO)}</div>
<div class="col grow g8">
<h2 class="h2">You don't have an age card yet</h2>
<p class="p">An age card lets you prove you're 18+ on any site, without sharing who you are. You make it once from your ID, and it stays locked on this PC.</p>
<div class="row g8 mt8"><button class="btn pri" data-act="go" data-arg="card-country">${raw(icon('plus'))}Get an age card</button><button class="btn" data-act="go" data-arg="seals">How it works</button></div>
</div>
</div>
<div class="grid3">
<div class="card col g8"><span class="oi">${raw(icon('idcard'))}</span><span class="h3">Made once</span><span class="p">Make it one time. A card lasts up to 6 months.</span></div>
<div class="card col g8"><span class="oi">${raw(icon('finger'))}</span><span class="h3">Locked to you</span><span class="p">Every use needs Windows Hello: your face, fingerprint or PIN.</span></div>
<div class="card col g8"><span class="oi">${raw(icon('eyeOff'))}</span><span class="h3">Nothing stored</span><span class="p">No name, no birthday, no photo. Not on this PC, not on our servers.</span></div>
</div>
<div class="ibar">${raw(icon('info'))}<span class="p">No age card? You can still check your age with your phone each time a site asks.</span></div>`;
}

function homeActive(v: ViewState, c: CardView): Raw {
  return html`<div class="row"><h1 class="h1">Home</h1>${
    c.expired ? html`<span class="badge b-warn">${raw(icon('clock'))}Age card expired</span>` : html`<span class="badge b-ok">${raw(icon('check'))}Age card active</span>`
  }</div>
${notice(v)}${helloWarning(v)}
<div class="row g20 ai-stretch">
${ageCard(c)}
<div class="card grow col g0 facts">
<div class="fact"><span class="p">Made with</span><span class="b">${c.methodLabel}</span></div>
<div class="fact"><span class="p">Valid until</span><span class="b">${c.validUntilLabel}${c.expired ? ' (expired)' : ` (${c.daysLeft} days left)`}</span></div>
<div class="fact"><span class="p">Unlock with</span><span class="b">${c.testKey ? 'Nothing (TEST key)' : 'Windows Hello'}</span></div>
<div class="fact last"><span class="p">Kept in</span><span class="b">${protectionLabel(c)}</span></div>
</div>
</div>
<div class="card row g16 ai-start">
<span class="oi">${raw(icon('eyeOff'))}</span>
<span class="col g4"><span class="h3">Nothing about you is stored</span><span class="p">Your age card holds only one fact: 18+. No name, no birthday, no ID number, no photo. V18 keeps no list of the sites you visit.</span></span>
</div>
<div class="row g8">
<button class="btn" data-act="go" data-arg="card-country">${raw(icon('refresh'))}${c.expired ? 'Renew card' : 'Make a new card'}</button>
<button class="btn dng" data-act="go" data-arg="settings">${raw(icon('trash'))}Delete age card</button>
<button class="btn" data-act="go" data-arg="settings">${raw(icon('people'))}Shared PC mode</button>
</div>
<p class="sm">When a site asks for an age check, you'll get a notification. Approve it with Windows Hello.</p>`;
}

function homeShared(v: ViewState): Raw {
  return html`<div class="row"><h1 class="h1">Home</h1><span class="badge b-acc">${raw(icon('people'))}Shared PC mode</span></div>
${notice(v)}
<div class="card row g28 pad-md">
<span class="si">${raw(icon('people'))}</span>
<span class="col g6"><h2 class="h2">Shared PC mode is on</h2><p class="p">Nothing is remembered on this PC. No age card is saved here, and every site visit needs a fresh check.</p></span>
</div>
<h2 class="h3">How to check your age on this PC</h2>
<div class="grid2">
<div class="card col g8"><span class="oi">${raw(icon('phone'))}</span><span class="h3">With your phone (best)</span><span class="p">When a site asks, V18 shows a code. Scan it with V18 on your phone. Nothing stays on this PC.</span></div>
<div class="card col g8"><span class="oi">${raw(icon('finger'))}</span><span class="h3">Your phone keeps the card</span><span class="p">Your age card stays on your phone, locked by your fingerprint or face. This PC only shows the code.</span></div>
</div>
<div class="ibar ok">${raw(icon('heart'))}<span>Good for family PCs: a child who uses this PC later can't reuse anything you did.</span></div>
<div class="row g8"><button class="btn" data-act="go" data-arg="settings">${raw(icon('gear'))}Change in Settings</button></div>`;
}

function home(v: ViewState): Raw {
  const child =
    v.childAccount === 'yes'
      ? html`<div class="ibar">${raw(icon('heart'))}<span class="p">Windows says this account belongs to someone under 18, so V18 won't make 18+ tickets here.</span></div>`
      : raw('');
  if (v.settings.sharedPc) return html`${homeShared(v)}${child}`;
  return v.card ? html`${homeActive(v, v.card)}${child}` : html`${homeEmpty(v)}${child}`;
}

function methodRow(act: string, arg: string, ico: string, title: Raw | string, desc: string, warn = false): Raw {
  return html`<button class="opt" data-act="${act}" data-arg="${arg}"><span class="oi ${warn ? 'w' : ''}">${raw(icon(ico))}</span><span class="grow"><span class="t">${title}</span><span class="d">${desc}</span></span>${raw(icon('chevR', 'ic chev'))}</button>`;
}

const REGION_NAMES: Record<string, string> = {
  asia: 'Asia',
  europe: 'Europe',
  eu: 'Europe',
  middle_east: 'Middle East',
  africa: 'Africa',
  americas: 'Americas',
  north_america: 'North America',
  south_america: 'South America',
  oceania: 'Oceania',
};
const regionName = (r: string) => REGION_NAMES[r] ?? r.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());

/** The country the person picked, or this PC's Windows region if the catalog has it. */
export function pickedCountry(v: ViewState, ui: LocalUi): CatalogCountryView | null {
  const list = v.catalog.countries;
  return list.find((c) => c.code === ui.country) ?? (ui.country ? null : list.find((c) => c.code === v.localeCountry) ?? null);
}

function catalogProblem(v: ViewState): Raw {
  return html`<div class="card col g12 pad-md" role="alert">
<span class="h3">${v.catalog.status === 'loading' ? 'Getting the list of IDs…' : "V18 couldn't get the list of IDs"}</span>
${
  v.catalog.status === 'loading'
    ? raw('<span class="spin"></span>')
    : html`<p class="p">${v.catalog.message ?? ''} The list of countries and IDs comes from the V18 server, so it is always up to date.</p>
<div class="row g8"><button class="btn pri" data-act="load-catalog">${raw(icon('refresh'))}Try again</button><button class="btn" data-act="start-link">${raw(icon('phone'))}Use my phone</button></div>
<p class="sm">Your phone works for every country: it reads your ID, then makes this PC's card.</p>
${v.testMode ? html`<div class="row g8"><button class="btn" data-act="go" data-arg="card-test">${raw(icon('flask'))}TEST card (TEST MODE only)</button></div>` : ''}`
}</div>`;
}

function cardCountry(v: ViewState, ui: LocalUi): Raw {
  const q = ui.countrySearch.trim().toLowerCase();
  const picked = pickedCountry(v, ui);
  const list = v.catalog.countries.filter((c) => !q || c.name.toLowerCase().includes(q) || c.code.toLowerCase() === q);
  const regions = [...new Set(list.map((c) => c.region))].sort((a, b) => regionName(a).localeCompare(regionName(b), 'en'));
  return html`${steps(0)}
<div class="col g4"><h1 class="h1">Where is your ID from?</h1><p class="p">This shows which IDs work for you. Your choice is not saved.</p></div>
${
  v.catalog.status !== 'ok'
    ? catalogProblem(v)
    : html`<label class="inp mw360">${raw(icon('search'))}<span class="vh">Search countries</span><input id="country-search" placeholder="Search ${String(v.catalog.countries.length)} countries" value="${ui.countrySearch}" autocomplete="off"></label>
${regions.map(
  (r) => html`<h2 class="sec">${regionName(r)}</h2><div class="clist">${list
    .filter((c) => c.region === r)
    .map((c) => {
      const on = picked?.code === c.code;
      const ways = c.methods.map((m) => m.label);
      return html`<button class="cbtn ${on ? 'on' : ''}" data-act="pick-country" data-arg="${c.code}" aria-pressed="${String(on)}"><span class="rad ${on ? 'on' : ''}"></span><span class="b">${c.name}</span><span class="sm">${
        ways.slice(0, 3).join(', ') + (ways.length > 3 ? ` and ${ways.length - 3} more` : '')
      }</span></button>`;
    })}</div>`,
)}
${list.length === 0 ? html`<p class="p">No country matches "${ui.countrySearch}".</p>` : ''}`
}
<p class="sm">Country not listed? A passport with a chip works almost everywhere: your phone reads it, then makes this PC's card.</p>
<div class="foot"><button class="btn" data-act="go" data-arg="home">Back</button><span class="r"><button class="btn pri" data-act="go" data-arg="card-methods" ${picked ? '' : 'disabled'}>Continue</button></span></div>`;
}

const PRIVACY_WORDS: Record<string, string> = {
  zero_knowledge: 'Zero-knowledge proof: nothing about you leaves this PC except "18+"',
  on_device: 'Checked on your phone: only "18+" leaves it',
  wallet: 'Your wallet shares only "over 18"',
  login: 'V18 sees your birth date for a moment to decide "18+", then keeps nothing',
  estimate: 'An estimate, not proof. Some sites may not accept it',
};

function methodCard(v: ViewState, m: PcMethod): Raw {
  const docs = m.documents.length ? `Works with: ${m.documents.join(', ')}.` : '';
  if (m.kind === 'aadhaar') {
    return methodRow(
      'go',
      'card-qr',
      'qr',
      html`${m.label}<span class="badge b-ok">Most private</span>`,
      `${docs} Import a picture of the QR. This PC checks UIDAI's seal and builds the proof.${v.proofFilesCached ? '' : ' The first time, V18 downloads about 620 MB of proof files.'}`,
    );
  }
  if (m.kind === 'connector') {
    return methodRow('start-connector', m.connectorId ?? '', 'globe', html`${m.label}<span class="badge b-acc">Sign in</span>`, `${docs} You sign in on ${m.label}'s own page, in your browser. ${PRIVACY_WORDS.login}.`);
  }
  return methodRow('start-link', m.label, 'phone', html`${m.label}<span class="badge">With your phone</span>`, `${docs} ${PRIVACY_WORDS[m.privacy] ?? ''}. Your phone reads it, then approves a card for this PC.`);
}

function cardMethods(v: ViewState, ui: LocalUi): Raw {
  const c = pickedCountry(v, ui);
  if (v.catalog.status !== 'ok' || !c) {
    return html`${steps(1)}${notice(v)}<h1 class="h1">Choose how to make your age card</h1>${catalogProblem(v)}<div class="foot"><button class="btn" data-act="go" data-arg="card-country">Back</button></div>`;
  }
  const onPc = c.methods.filter((m) => m.kind !== 'phone');
  const phone = c.methods.filter((m) => m.kind === 'phone');
  return html`${steps(1)}
${notice(v)}
<div class="row jb ai-end">
<div class="col g4"><h1 class="h1">Choose how to make your age card</h1><p class="p">All of these stay private. Only "18+" is ever passed on.</p></div>
<span class="row g6 noflex"><span class="sm">Country: ${c.name}</span><button class="lnk sm" data-act="go" data-arg="card-country">Change</button></span>
</div>
${onPc.length ? html`<h2 class="sec">On this PC</h2><div class="col g8">${onPc.map((m) => methodCard(v, m))}</div>` : ''}
${
  phone.length
    ? html`<h2 class="sec">With your phone</h2>${
        onPc.length ? '' : html`<p class="p">PCs can't read ID chips or ID QR codes safely, so ${c.name} IDs go through V18 on your phone. It takes about a minute.</p>`
      }<div class="col g8">${phone.map((m) => methodCard(v, m))}</div>`
    : ''
}
<div class="col g8">
${methodRow('start-link', '', 'phone', 'I already have an age card on my phone', 'Your phone approves, then a card for this PC is saved here. Your ID details stay on your phone.')}
${v.testMode ? methodRow('go', 'card-test', 'flask', html`TEST card<span class="badge b-warn">TEST MODE only</span>`, 'For developers. The TEST issuer makes a card for a made-up person. No ID is read.') : ''}
</div>
<div class="foot"><button class="btn" data-act="go" data-arg="card-country">Back</button></div>`;
}

function cardConnect(v: ViewState): Raw {
  const c = v.connect;
  let body: Raw;
  if (!c || c.status === 'hello' || c.status === 'starting') {
    body = html`<div class="col g16"><h1 class="h1">First, Windows Hello</h1>
<p class="p">${c?.status === 'starting' ? 'Approve with Windows Hello again to sign the request.' : 'Approve with Windows Hello. This makes a key for your age card, locked in this PC.'}</p>
<div class="ibar" role="status">${raw(icon('finger'))}<span class="col g2"><span class="b">Look for the Windows Hello window</span><span class="sm">It asks twice: once to make the key, once to sign.</span></span></div></div>`;
  } else if (c.status === 'expired') {
    body = html`<div class="col g16"><h1 class="h1">The sign-in ran out of time</h1><p class="p">Nothing was saved. Try again, and finish the sign-in on ${c.label}'s page.</p>
<div class="row g8"><button class="btn pri" data-act="start-connector" data-arg="${c.connectorId}">Try again</button></div></div>`;
  } else {
    body = html`<div class="col g16"><h1 class="h1">Sign in with ${c.label} in your browser</h1>
<ol class="ol">
<li>V18 opened ${c.label}'s own sign-in page in your web browser.</li>
<li>Sign in there and agree to share your date of birth (or "over 18").</li>
<li>Your browser then asks to open V18. Allow it, and this window finishes by itself.</li>
</ol>
<div class="ibar" role="status"><span class="spin"></span><span class="col g2"><span class="b">Waiting for ${c.label}…</span><span class="sm">V18's server sees your date of birth for a moment to decide "18+". It keeps nothing about you, and ${c.label} doesn't learn which sites you visit.</span></span></div>
<div class="row g8"><button class="btn" data-act="connect-reopen">${raw(icon('external'))}Open the sign-in page again</button></div></div>`;
  }
  return html`${steps(2)}${body}<div class="foot"><button class="btn" data-act="cancel-connect">Cancel</button></div>`;
}

function cardPhone(v: ViewState): Raw {
  const l = v.link;
  let body: Raw;
  if (!l || l.status === 'hello') {
    body = html`<div class="row g40 ai-center mt8">
<div class="qr qr240 dim center-box"><span class="spin lg"></span></div>
<div class="col grow g16">
<h1 class="h1">First, Windows Hello</h1>
<p class="p">${l?.message ?? 'Approve with Windows Hello.'}</p>
<div class="ibar" role="status">${raw(icon('finger'))}<span class="col g2"><span class="b">Look for the Windows Hello window</span><span class="sm">Use your face, fingerprint or PIN there. It may ask twice: once to make the key, once to sign.</span></span></div>
</div></div>`;
  } else if (l.status === 'expired') {
    body = html`<div class="row g40 ai-start mt8">
<div class="qr qr240"><div class="qover">${raw(icon('clock'))}<span class="b6">Code expired</span><button class="btn pri" data-act="start-link">Get a new code</button></div></div>
<div class="col grow g16"><h1 class="h1">The code ran out</h1><p class="p">Codes last 2 minutes and work once. Get a new one, then scan it with your phone.</p></div></div>`;
  } else {
    body = html`<div class="row g40 ai-start mt8">
<div class="col g10 noflex">
<div class="qr qr240"><img src="${l.qr ?? ''}" alt="QR code for V18 on your phone"></div>
<div class="col g6"><div class="row jb"><span class="sm">Code expires in</span><span class="b mono" role="timer" data-countdown="${l.expiresAt ?? 0}">2:00</span></div><div class="prog"><i data-countbar="${l.expiresAt ?? 0}"></i></div></div>
</div>
<div class="col grow g16">
<h1 class="h1">Use your phone to make this PC's card</h1>
<ol class="ol">
${
  l.forLabel
    ? html`<li>Open V18 on your phone and make an age card with <span class="b">${l.forLabel}</span> (skip this if your phone already has one).</li>`
    : html`<li>Open V18 on your phone. It needs an age card already.</li>`
}
<li><span>Tap <span class="b">Make a card for a PC</span>.</span></li>
<li>Scan this code.</li>
<li>Approve on your phone with your fingerprint or face.</li>
</ol>
<div class="ibar" role="status"><span class="spin"></span><span class="col g2"><span class="b">Waiting for your phone…</span><span class="sm">This code lasts 2 minutes and works once. Your ID details stay on your phone.</span></span></div>
</div></div>`;
  }
  return html`${steps(2)}${body}<div class="foot"><button class="btn" data-act="cancel-link">Back</button></div>`;
}

function cardTest(v: ViewState, ui: LocalUi): Raw {
  return html`<div class="col g4"><h1 class="h1">Make a TEST card</h1><p class="p">For developers only. The server's TEST issuer pretends a made-up person showed an ID. Nothing real is read.</p></div>
${
  v.testMode
    ? html`<div class="ibar warn">${raw(icon('flask'))}<span><span class="b">TEST MODE.</span> This only works with a development server (V18_DEV_MODE=1). Real servers refuse TEST cards.</span></div>`
    : html`<div class="ibar err">${raw(icon('warn'))}<span>This server is not in TEST MODE, so it won't make TEST cards.</span></div>`
}
<div class="col g8">
<button class="opt ${ui.testKind === 'adult' ? 'on' : ''}" data-act="test-kind" data-arg="adult"><span class="rad ${ui.testKind === 'adult' ? 'on' : ''}"></span><span class="grow"><span class="t">A made-up adult (born 1 Jan 1990)</span><span class="d">You get a TEST age card that lasts 30 days.</span></span></button>
<button class="opt ${ui.testKind === 'under18' ? 'on' : ''}" data-act="test-kind" data-arg="under18"><span class="rad ${ui.testKind === 'under18' ? 'on' : ''}"></span><span class="grow"><span class="t">A made-up 15-year-old</span><span class="d">To see what happens when someone under 18 tries. No card is made.</span></span></button>
</div>
<div class="row g8"><button class="btn pri" data-act="test-card" ${v.testMode ? '' : 'disabled'}>Make TEST card</button></div>
<p class="sm">You'll approve with Windows Hello twice: once to make the key, once to sign the request.</p>
<div class="foot"><button class="btn" data-act="go" data-arg="card-methods">Back</button></div>`;
}

function cardQr(v: ViewState): Raw {
  const a = v.aadhaar ?? { stage: 'pick' as const };
  let body: Raw;
  if (a.stage === 'pick') {
    body = html`${notice(v)}<div class="drop h250">
<span class="oi">${raw(icon('fileDown'))}</span>
<span class="b">Choose a picture of your Aadhaar Secure QR</span>
<button class="btn" data-act="aadhaar-pick">Choose file</button>
<span class="sm">A PNG or JPG picture of the QR (for an e-Aadhaar PDF, take a screenshot of its QR), or a .txt file with the QR number. The file is read on this PC. It is never uploaded.</span>
</div>`;
  } else {
    const good = a.stage === 'read';
    const tooLong = a.message === 'too-long';
    body = html`<div class="card col g16 pad-md">
${good ? html`<div class="ibar ok" role="status">${raw(icon('check'))}<span>QR read. ${a.testQr ? 'TEST seal found (Anon Aadhaar TEST key).' : "UIDAI's seal found."}</span></div>` : ''}
${!good && a.message && a.message !== 'seal' && a.message !== 'under18' && !tooLong ? html`<div class="ibar err" role="alert">${raw(icon('warn'))}<span>${a.message}</span></div>` : ''}
${tooLong ? html`<div class="ibar err" role="alert">${raw(icon('warn'))}<span>This QR holds more data than the Anon Aadhaar proof can read. Download a fresh e-Aadhaar and try its QR, or use your phone.</span></div>` : ''}
${
  (a.checks ?? []).length
    ? html`<ul class="pl">${(a.checks ?? []).map((c) => html`<li class="${c.ok ? 'done' : 'bad'}"><span class="d">${raw(icon(c.ok ? 'check' : 'x'))}</span>${c.label}</li>`)}</ul>`
    : ''
}
${a.fileName ? html`<p class="sm">File: ${a.fileName}. Its contents were not saved.</p>` : ''}
${
  good
    ? html`<div class="ibar">${raw(icon('chip'))}<span class="col g2"><span class="b">Next: your PC builds the proof</span><span class="sm">${
        v.proofFilesCached ? 'The proof files are already on this PC.' : 'First, V18 downloads the proof files once (about 620 MB) and checks each one.'
      } Building the proof takes about 20 seconds on a fast PC (longer on older ones) and needs a lot of free memory for a moment. Windows Hello asks twice: to make the key, then to sign.</span></span></div>`
    : ''
}
<div class="row g8">${good ? html`<button class="btn pri" data-act="aadhaar-build">Build my proof</button>` : ''}<button class="btn" data-act="aadhaar-reset">${good ? 'Use another QR' : 'Try another file'}</button></div>
</div>`;
  }
  return html`${steps(2)}
<div class="col g4"><h1 class="h1">Scan your Aadhaar Secure QR</h1><p class="p">The QR on your Aadhaar letter, card or e-Aadhaar carries UIDAI's seal. V18 checks it on this PC.</p></div>
${body}
<div class="ibar">${raw(icon('info'))}<span class="p">Your name, birth date, photo and Aadhaar number are read only in this PC's memory, to check the seal and build the proof, then dropped. They are never saved or sent.</span></div>
<div class="foot"><button class="btn" data-act="go" data-arg="card-methods">Back</button></div>`;
}

function cardWorking(v: ViewState): Raw {
  const w = v.work;
  const p = w?.progress;
  return html`${steps(3)}
<div class="row g48 ai-center flex1 px8">
<div class="seal seal-lg" aria-hidden="true"><span class="spin ring"></span>${raw(icon('shieldCheck'))}</div>
<div class="col grow g16">
<h1 class="h1">${w?.title ?? 'Working…'}</h1>
<p class="p">${w?.text ?? ''}</p>
<div class="card col g14"><ul class="pl">${(w?.steps ?? []).map((s) => html`<li class="${s.state}"><span class="d">${s.state === 'done' ? raw(icon('check')) : ''}</span>${s.label}</li>`)}</ul>
${
  p
    ? html`<div class="col g6" role="status"><div class="row jb"><span class="sm">${p.label}${p.detail ? `: ${p.detail}` : ''}</span><span class="sm mono">${String(Math.floor(p.pct))}%${
        w?.since ? html` · <span data-since="${String(w.since)}">0:00</span>` : ''
      }</span></div><div class="prog" role="progressbar" aria-label="Progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${String(Math.floor(p.pct))}"><i data-pct="${String(p.pct)}"></i></div></div>`
    : ''
}</div>
<div class="ibar">${raw(icon('finger'))}<span class="p">If Windows Hello asks, use your face, fingerprint or PIN.</span></div>
${w?.cancellable ? html`<div class="row g8"><button class="btn" data-act="aadhaar-cancel">Cancel</button></div>` : ''}
</div></div>`;
}

function cardSaved(v: ViewState): Raw {
  const c = v.card;
  if (!c) return home(v);
  return html`${steps(5, true)}
<div class="row g40 ai-center flex1">
${ageCard(c)}
<div class="col grow g14">
<span class="si sm ok">${raw(icon('check'))}</span>
<h1 class="h1">Your age card is saved</h1>
<p class="p">From now on, when a site asks, just unlock with Windows Hello. You don't need to make a card again until it runs out.</p>
<ul class="ck">
${ok(`Valid for ${c.daysLeft} days, until ${c.validUntilLabel}`)}
${ok(c.testKey ? 'TEST key: kept in memory only, gone when V18 closes' : 'Locked by Windows Hello, kept in this PC')}
${ok('No ID details were saved on this PC')}
${c.method === 'anon_aadhaar' && v.lastProofSeconds !== null ? ok(`Zero-knowledge proof built on this PC in ${v.lastProofSeconds} seconds`) : ''}
</ul>
<div class="row g8 mt6"><button class="btn pri" data-act="go" data-arg="home">Go to Home</button><button class="btn" data-act="go" data-arg="settings">Settings</button></div>
</div></div>`;
}

function seals(): Raw {
  return html`<div class="col g4"><h1 class="h1">How seals work</h1><p class="p">A short guide. No maths needed.</p></div>
<div class="card row g16 ai-start"><span class="oi">${raw(icon('shieldCheck'))}</span><span class="col g4"><span class="h3">A seal is a maths stamp</span><span class="p">Governments put a digital seal on passports, ID cards and ID QR codes. Only they can make it, and anyone can check it. If one letter changes, the seal breaks.</span></span></div>
<h2 class="h3">What happens when a site asks</h2>
<div class="flow">
<div class="fbox"><span class="oi">${raw(icon('passport'))}</span><span class="h3">1. Your ID</span><span class="p f13">Sealed by the government.</span></div>
<span class="farr" aria-hidden="true">${raw(icon('arrowR'))}</span>
<div class="fbox"><span class="oi">${raw(icon('phone'))}</span><span class="h3">2. Your device</span><span class="p f13">Builds a proof that says only "18+ yes".</span></div>
<span class="farr" aria-hidden="true">${raw(icon('arrowR'))}</span>
<div class="fbox"><span class="oi">${raw(icon('shieldCheck'))}</span><span class="h3">3. V18</span><span class="p f13">Checks the proof, then seals a ticket without seeing it.</span></div>
<span class="farr" aria-hidden="true">${raw(icon('arrowR'))}</span>
<div class="fbox"><span class="oi">${raw(icon('globe'))}</span><span class="h3">4. The website</span><span class="p f13">Checks our seal on its own server, then lets you in.</span></div>
</div>
<div class="grid3">
<div class="card col g6"><span class="oi">${raw(icon('ticket'))}</span><span class="h3">Age card and tickets</span><span class="p">Like a cinema: show your ID once to get a membership card, then get a ticket each visit. Each ticket works once and lasts 5 minutes.</span></div>
<div class="card col g6"><span class="oi">${raw(icon('eyeOff'))}</span><span class="h3">Why sites can't follow you</span><span class="p">We seal each ticket without seeing it (a "blind" seal). Every ticket looks different, so sites can't tell it's the same person coming back.</span></div>
<div class="card col g6"><span class="oi">${raw(icon('lock'))}</span><span class="h3">Why it's hard to cheat</span><span class="p">Change a birth date and the seal breaks. Reuse an old proof and it fails, because every check has a fresh one-time number.</span></div>
</div>
<div class="ibar warn">${raw(icon('warn'))}<span><span class="b">What a seal can't stop:</span> someone using another adult's real ID. Windows Hello, child-account checks and Shared PC mode make that harder, but no system can fully stop it.</span></div>`;
}

function toggle(act: string, on: boolean, label: string): Raw {
  return html`<button class="tgw" data-act="${act}" aria-pressed="${String(on)}" aria-label="${label}"><span>${on ? 'On' : 'Off'}</span><span class="tg ${on ? 'on' : ''}"></span></button>`;
}

function settings(v: ViewState, ui: LocalUi): Raw {
  const c = v.card;
  const s = v.settings;
  const helloLine = v.testKey
    ? 'OFF: TEST key mode'
    : v.hello.ok
      ? 'Set up and working'
      : v.hello.code === 'HELLO_NOT_SET_UP'
        ? 'Not set up on this Windows account'
        : v.hello.code === 'CHECKING'
          ? 'Checking…'
          : `Not working: ${v.hello.detail ?? v.hello.code ?? ''}`;
  return html`<h1 class="h1">Settings</h1>
${notice(v)}
<h2 class="sec">Age card</h2>
<div class="sets">
<div class="set">${raw(icon('idcard'))}<span class="grow"><span>Your age card</span><span class="d">${
    s.sharedPc ? 'None: Shared PC mode keeps no card' : c ? `${c.methodLabel}, valid until ${c.validUntilLabel}` : 'No age card on this PC'
  }</span></span>${c ? html`<button class="btn dng" data-act="ask-delete" ${v.busy ? 'disabled' : ''}>${raw(icon('trash'))}Delete age card</button>` : ''}</div>
${
    v.proofFilesCached
      ? html`<div class="set">${raw(icon('fileDown'))}<span class="grow"><span>Aadhaar proof files</span><span class="d">About 620 MB on this PC, used to build Aadhaar proofs. Deleting them frees the space; V18 downloads them again if you need them.</span></span><button class="btn" data-act="delete-proof-files" ${v.busy ? 'disabled' : ''}>${raw(icon('trash'))}Delete files</button></div>`
      : ''
  }
</div>
<h2 class="sec">This PC</h2>
<div class="sets">
<div class="set">${raw(icon('people'))}<span class="grow"><span>Shared PC mode</span><span class="d">Nothing is remembered. Every visit needs a fresh check. Recommended for family PCs.</span></span>${toggle('toggle-shared', s.sharedPc, 'Shared PC mode')}</div>
${c && !s.sharedPc ? html`<div class="ibar warn">${raw(icon('warn'))}<span>Turning this on deletes the age card saved on this PC. You'll check your age fresh each time, with your phone.</span></div>` : ''}
${
    v.startWithWindows !== null
      ? html`<div class="set">${raw(icon('pc'))}<span class="grow"><span>Start V18 when I sign in to Windows</span><span class="d">V18 waits in the system tray, so it answers sites straight away. Off by default. Sites can still open V18 when it isn't running.</span></span>${toggle(
          'toggle-startup',
          v.startWithWindows,
          'Start V18 when I sign in to Windows',
        )}</div>`
      : ''
  }
<div class="set">${raw(icon('bell'))}<span class="grow"><span>Tell me when a site asks</span><span class="d">Show a Windows notification as well as the V18 window.</span></span>${toggle('toggle-notify', s.notify, 'Tell me when a site asks')}</div>
<div class="set">${raw(icon('finger'))}<span class="grow"><span>Windows Hello for every ticket</span><span class="d">A ticket can't be made without your face, fingerprint or PIN. Windows Hello here: ${helloLine}.</span></span>${
    v.testKey ? raw('<span class="badge b-err">OFF (TEST KEY)</span>') : html`<span class="badge b-ok">${raw(icon('check'))}Always on</span>`
  }</div>
</div>
<h2 class="sec">Privacy and help</h2>
<div class="sets">
<div class="set">${raw(icon('eyeOff'))}<span class="grow"><span>What V18 never stores</span><span class="d">ID scans, photos, your name, birth date, ID number, your face, or which sites you visit. Not on this PC, not on our servers. This PC keeps only: card ID, card type, end date, the name of the Windows Hello key, the server address and these settings (plus the public Aadhaar proof files, if downloaded).</span></span></div>
<button class="set setlink" data-act="go" data-arg="seals">${raw(icon('shieldCheck'))}<span class="grow"><span>How seals work</span><span class="d">A short guide to why an age card can't be faked.</span></span>${raw(icon('chevR', 'ic chev'))}</button>
<div class="set">${raw(icon('info'))}<span class="grow"><span>V18 server</span><span class="d">${v.serverUrl}${v.serverReachable === false ? ' (not reachable right now)' : ''}${v.testMode ? ' (TEST MODE)' : ''}. ${v.debugBuild ? 'Debug build.' : ''}</span></span><button class="btn" data-act="refresh-server">Check again</button></div>
</div>
${ui.confirmDelete ? deleteDialog() : ''}${ui.confirmShared ? sharedDialog() : ''}`;
}

function deleteDialog(): Raw {
  return html`<div class="scr"></div><div class="dlg mid w440" role="dialog" aria-label="Delete your age card?">
<div class="db pad-dlg"><h2 class="h2">Delete your age card?</h2><p class="p">It's turned off on the V18 server and its key is removed from Windows Hello right away. Windows Hello will ask you to confirm. To make a new card, you'll need to start again.</p></div>
<div class="df"><button class="btn dngf" data-act="delete-card">Delete</button><button class="btn" data-act="cancel-dialog">Cancel</button></div></div>`;
}

function sharedDialog(): Raw {
  return html`<div class="scr"></div><div class="dlg mid w440" role="dialog" aria-label="Turn on Shared PC mode?">
<div class="db pad-dlg"><h2 class="h2">Turn on Shared PC mode?</h2><p class="p">This deletes your age card from this PC and turns it off on the V18 server. Windows Hello will ask you to confirm. If the server can't be reached, the card is still deleted here.</p></div>
<div class="df"><button class="btn pri" data-act="shared-on">Turn on</button><button class="btn" data-act="cancel-dialog">Cancel</button></div></div>`;
}

function errPage(si: 'err' | 'warn' | '', ico: string, title: string, intro: string, list: Raw | null, buttons: Raw, foot = 'Nothing was saved or sent.', listTitle = 'This can happen when'): Raw {
  return html`<div class="col g16 mw580 center-y">
<span class="si ${si}">${raw(icon(ico))}</span>
<h1 class="h1">${title}</h1>
<p class="p">${intro}</p>
${list ? html`<div class="card col g10"><span class="h3">${listTitle}</span><ul class="ck">${list}</ul></div>` : ''}
<div class="row g8">${buttons}</div>
<p class="sm">${foot}</p></div>`;
}

function errIntegrity(v: ViewState): Raw {
  const code = v.error?.code ?? v.hello.code;
  if (code === 'HELLO_NOT_SET_UP') {
    return errPage(
      'err',
      'finger',
      "Windows Hello isn't set up",
      'V18 keeps your age card locked by Windows Hello (and the TPM security chip). This Windows account has no Windows Hello PIN, face or fingerprint, so V18 can\'t save a card here. V18 never falls back to a weaker key.',
      html`${ok('Open Settings, then Accounts, then Sign-in options.')}${ok('Set up a PIN (Windows Hello). Face or fingerprint is optional.')}${ok('Come back and try again.')}`,
      html`<button class="btn pri" data-act="open-hello-settings">${raw(icon('external'))}Open sign-in options</button><button class="btn" data-act="go" data-arg="card-methods">${raw(icon('refresh'))}Try again</button><button class="btn" data-act="use-phone-always">Use my phone each time</button>`,
      'Nothing was saved or sent.',
      'How to fix it',
    );
  }
  return errPage(
    'err',
    'chip',
    "We couldn't check this PC's security",
    `V18 keeps your age card in Windows Hello and this PC's security chip (TPM). The check didn't pass, so we can't save a card on this PC. ${v.error?.detail ?? v.hello.detail ?? ''}`,
    html`${no("The security chip (TPM) is turned off in your PC's start-up settings.")}${no("Windows or V18 has been changed, or isn't up to date.")}${no('The security chip locked itself after too many wrong PINs.')}`,
    html`<button class="btn pri" data-act="go" data-arg="card-methods">${raw(icon('refresh'))}Try again</button><button class="btn" data-act="use-phone-always">Use my phone each time</button>`,
  );
}

function errSeal(v: ViewState): Raw {
  return errPage(
    'err',
    'shieldX',
    "This ID's seal didn't check out",
    `We couldn't confirm the government seal on this ID, so no age card was made. ${v.error?.detail ?? ''}`,
    html`${no('The QR is a screenshot, photo or copy that was changed.')}${no('The ID chip is damaged or worn out.')}${no("The ID is from a country V18 doesn't support yet.")}`,
    html`<button class="btn pri" data-act="go" data-arg="card-qr">${raw(icon('refresh'))}Try again</button><button class="btn" data-act="go" data-arg="card-methods">Use a different ID</button>`,
  );
}

function errUnder18(): Raw {
  return errPage(
    '',
    'heart',
    'This is for adults (18+)',
    "Your ID shows you're under 18, so no age card was made. That's the rule. You haven't done anything wrong.",
    null,
    html`<button class="btn pri" data-act="go" data-arg="home">Back to Home</button>`,
    'Nothing was saved. No site learns your age.',
  );
}

function errOffline(v: ViewState): Raw {
  return errPage(
    'warn',
    'offline',
    "You're offline",
    `${v.error?.detail ?? 'V18 needs the internet for this.'} Check your Wi-Fi or cable, then try again.`,
    null,
    v.error?.code === 'OFFLINE_DELETE'
      ? html`<button class="btn pri" data-act="go" data-arg="settings">${raw(icon('refresh'))}Try again</button><button class="btn dng" data-act="delete-local">Delete from this PC only</button>`
      : html`<button class="btn pri" data-act="go" data-arg="card-methods">${raw(icon('refresh'))}Try again</button><button class="btn" data-act="go" data-arg="home">Cancel</button>`,
    'Nothing was shared.',
  );
}

function errGeneral(v: ViewState): Raw {
  return errPage(
    'warn',
    'warn',
    v.error?.title ?? 'Something went wrong',
    v.error?.detail ?? '',
    null,
    html`<button class="btn pri" data-act="go" data-arg="card-methods">Back</button><button class="btn" data-act="go" data-arg="home">Home</button>`,
  );
}

export function mainScreen(v: ViewState, ui: LocalUi): Raw {
  if (v.screen === 'welcome') return html`<div class="win">${titleBar(v)}${testBanners(v)}<div class="wb">${welcome(v, ui)}</div></div>`;
  let inner: Raw;
  let center = false;
  switch (v.screen) {
    case 'home':
      inner = home(v);
      break;
    case 'card-country':
      inner = cardCountry(v, ui);
      break;
    case 'card-methods':
      inner = cardMethods(v, ui);
      break;
    case 'card-phone':
      inner = cardPhone(v);
      break;
    case 'card-connect':
      inner = cardConnect(v);
      break;
    case 'card-test':
      inner = cardTest(v, ui);
      break;
    case 'card-qr':
      inner = cardQr(v);
      break;
    case 'card-working':
      inner = cardWorking(v);
      break;
    case 'card-saved':
      inner = cardSaved(v);
      break;
    case 'seals':
      inner = seals();
      break;
    case 'settings':
      inner = settings(v, ui);
      break;
    case 'err-integrity':
      inner = errIntegrity(v);
      center = true;
      break;
    case 'err-seal':
      inner = errSeal(v);
      center = true;
      break;
    case 'err-under18':
      inner = errUnder18();
      center = true;
      break;
    case 'err-offline':
      inner = errOffline(v);
      center = true;
      break;
    case 'child':
      inner = childPage();
      center = true;
      break;
    default:
      inner = errGeneral(v);
      center = true;
  }
  return html`<div class="win">${titleBar(v)}${testBanners(v)}<div class="wb">${nav(v)}<main class="main ${center ? 'jcenter' : ''}">${inner}</main></div></div>`;
}

function childPage(): Raw {
  return html`<div class="col g16 mw580 center-y aicenter tcenter">
<div class="seal">${raw(icon('heart'))}</div>
<h1 class="h1 mt10">This is a child account</h1>
<p class="p">Hi! This Windows account is set up for someone under 18, so V18 won't make 18+ tickets here. That's on purpose. It helps keep younger people safe online.</p>
<div class="ibar">${raw(icon('info'))}<span class="p">Nothing was shared. The site only sees that the age check didn't finish.</span></div>
<p class="sm">Are you an adult? Sign in to Windows with your own account.</p></div>`;
}
