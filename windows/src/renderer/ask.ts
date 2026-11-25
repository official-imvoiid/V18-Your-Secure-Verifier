// The "a site asks" dialog window, adapted from AskDialog, AskHello, AskSent, Err* and ChildAccount.

import type { AskView, ViewState } from '../main/view.js';
import { html, raw, type Raw } from './html.js';
import { icon, LOGO } from './icons.js';
import { testBanners } from './screens.js';

function frame(v: ViewState, body: Raw, foot: Raw | null): Raw {
  return html`<div class="askwin">
<div class="tb drag dlg-tb">${raw(LOGO)}<span>V18</span>${v.testMode ? raw('<span class="badge b-warn tb-badge">TEST MODE</span>') : ''}${v.testKey ? raw('<span class="badge b-err tb-badge">TEST KEY</span>') : ''}</div>
${testBanners(v)}
<div class="db">${body}</div>
${foot ? html`<div class="df">${foot}</div>` : ''}
</div>`;
}

function siteLine(a: AskView, suffix = 'asks:'): Raw {
  return html`<div class="row g8 tx2">${raw(icon('lock'))}<span class="b">${a.host ?? 'A website'}</span><span>${suffix}</span></div>`;
}

export function askScreen(v: ViewState): Raw {
  const a = v.ask;
  if (!a) return frame(v, html`<p class="p">Nothing to do right now.</p>`, html`<button class="btn" data-act="ask-close">Close</button>`);
  switch (a.stage) {
    case 'loading':
      return frame(v, html`${a.host ? siteLine(a, 'is asking for an age check') : ''}<div class="row g12 mt8"><span class="spin"></span><span class="b">Checking the request with V18…</span></div>`, html`<button class="btn" data-act="ask-close">Cancel</button>`);

    case 'confirm':
      return frame(
        v,
        html`${siteLine(a)}
<h1 class="h1">Are you ${a.minAge}+?</h1>
${a.message ? html`<div class="ibar warn" role="status">${raw(icon('info'))}<span>${a.message}</span></div>` : ''}
<div class="card col g10 pad-sm">
<span class="lab">The site will get</span>
<ul class="ck"><li>${raw(icon('check', 'ic y'))}<span class="b">${a.minAge}+: yes</span></li><li>${raw(icon('check', 'ic y'))}<span>A one-time ticket</span></li></ul>
<span class="lab mt4">The site won't get</span>
<p class="p">Your name, birthday, ID, face, or the other sites you visit.</p>
</div>
<div class="row g12"><span class="oi">${raw(icon('idcard'))}</span><span class="col g0"><span class="b">Using your age card</span><span class="sm">${a.cardLine ?? ''}</span></span></div>
<button class="lnk sm astart" data-act="ask-phone">Use my phone instead</button>`,
        html`<button class="btn pri" data-act="ask-approve">Send ${a.minAge}+ ticket</button><button class="btn" data-act="ask-close">Not now</button>`,
      );

    case 'hello':
    case 'working':
      return frame(
        v,
        html`<span class="row sm g6 b6 tx2">${raw(icon('finger', 'ic s16'))}Windows Hello</span>
<h2 class="h2">${a.stage === 'hello' ? "Making sure it's you" : 'Making your ticket…'}</h2>
<p class="p">V18 wants to use your age card for ${a.host ?? 'this site'}.</p>
<div class="col aicenter g12 py12"><span class="si big">${a.stage === 'hello' ? raw(icon('finger')) : raw('<span class="spin lg"></span>')}</span>
<span class="b">${a.stage === 'hello' ? 'Use the Windows Hello window: face, fingerprint or PIN' : 'Sealing a one-time ticket, without V18 seeing it'}</span></div>
${a.stage === 'hello' ? html`<p class="sm">To stop, choose Cancel in the Windows Hello window. Nothing is sent until you approve.</p>` : ''}`,
        null,
      );

    case 'sent':
      return frame(
        v,
        html`<div class="col aicenter tcenter g16"><span class="si ok">${raw(icon('ticketCheck'))}</span>
<h1 class="h1">Ticket sent</h1>
<p class="p">${a.host ?? 'The site'} got a one-time ${a.minAge}+ ticket. It works once and can't be linked to you.</p>
<div class="ibar w100">${raw(icon('eyeOff'))}<span class="p">Nothing about you was shared. V18 kept no record of this visit.</span></div>
<p class="sm">This window closes by itself in <span data-countdown-s="${a.closeAt ?? 0}">5</span> seconds.</p></div>`,
        html`<button class="btn pri" data-act="ask-close">Back to browser</button>`,
      );

    case 'nocard':
      return frame(
        v,
        html`${siteLine(a, 'is asking for an age check')}
<span class="si sm">${raw(icon('idcard'))}</span>
<h2 class="h2">You don't have an age card on this PC</h2>
<p class="p">${a.message ? a.message + ' ' : ''}Make one now (it takes about a minute with your phone), or use your phone just for this site.</p>`,
        html`<button class="btn pri" data-act="ask-get-card">Get an age card</button><button class="btn" data-act="ask-phone">Use my phone this time</button>`,
      );

    case 'shared':
      return frame(
        v,
        html`${siteLine(a, 'is asking for an age check')}
<span class="si sm">${raw(icon('people'))}</span>
<h2 class="h2">Shared PC mode is on</h2>
<p class="p">Nothing is remembered on this PC, so use your phone for this check. Your phone makes the ticket. Nothing stays on this PC.</p>`,
        html`<button class="btn pri" data-act="ask-phone">${raw(icon('phone'))}Use my phone</button><button class="btn" data-act="ask-close">Not now</button>`,
      );

    case 'phone':
      return frame(
        v,
        html`${siteLine(a, 'is asking for an age check')}
<div class="row g20 ai-start">
<div class="qr qr180"><img src="${a.qr ?? ''}" alt="QR code for V18 on your phone"></div>
<div class="col g10 grow"><h2 class="h2">Scan with your phone</h2>
<ol class="ol"><li>Open V18 on your phone.</li><li><span>Tap <span class="b">Scan a code</span>.</span></li><li>Scan this code.</li><li>Approve on your phone.</li></ol></div></div>
<p class="sm">This code works once, and only for ${a.host ?? 'this site'}. When your phone says it's done, go back to the browser.</p>`,
        html`<button class="btn pri" data-act="ask-close">Done</button>${!v.settings.sharedPc && v.card && !v.card.expired ? html`<button class="btn" data-act="ask-back">Use this PC instead</button>` : ''}`,
      );

    case 'offline':
      return frame(
        v,
        html`<span class="si sm warn">${raw(icon('offline'))}</span>
<h2 class="h2">You're offline</h2>
<p class="p">V18 needs the internet to get a ticket for ${a.host ?? 'this site'}. ${v.card ? 'Your age card is still safe on this PC.' : ''}</p>
<div class="ibar">${raw(icon('wifi'))}<span class="p">Check your Wi-Fi or cable, then try again. Nothing was shared.</span></div>`,
        html`<button class="btn pri" data-act="ask-retry">${raw(icon('refresh'))}Try again</button><button class="btn" data-act="ask-close">Cancel</button>`,
      );

    case 'expired':
      return frame(
        v,
        html`<div class="row g8 tx2">${raw(icon('lock'))}<span>${a.host ?? 'A site'} asked for an age check</span></div>
<span class="si sm warn">${raw(icon('clock'))}</span>
<h2 class="h2">Your age card has expired</h2>
<p class="p">${a.message ? a.message + ' ' : ''}Age cards last a few months, so they stay up to date. Make a new one. It takes about a minute.</p>
${v.card ? html`<div class="card row g12 pad-sm">${raw(icon('idcard'))}<span class="col g0"><span class="b">Old card: ${v.card.methodLabel}</span><span class="sm">Ended on ${v.card.validUntilLabel}</span></span><span class="badge b-warn ml-auto">Expired</span></div>` : ''}`,
        html`<button class="btn pri" data-act="ask-get-card">Renew age card</button><button class="btn" data-act="ask-phone">Use my phone this time</button>`,
      );

    case 'under18':
      return frame(
        v,
        html`${siteLine(a, '')}<span class="si sm">${raw(icon('heart'))}</span><h2 class="h2">This site is for adults (${a.minAge}+)</h2>
<p class="p">No ticket was made. That's the rule for this kind of site. You haven't done anything wrong.</p>
<div class="ibar">${raw(icon('info'))}<span class="p">The site doesn't learn your age. It only sees that the check didn't finish. Nothing was saved.</span></div>`,
        html`<button class="btn pri" data-act="ask-close">Back to browser</button>`,
      );

    case 'child':
      return frame(
        v,
        html`<div class="col aicenter tcenter g14"><div class="seal sm-seal">${raw(icon('heart'))}</div>
<h2 class="h2">This is a child account</h2>
<p class="p">Hi! This Windows account is set up for someone under 18, so V18 won't make 18+ tickets here. That's on purpose. It helps keep younger people safe online.</p>
<div class="ibar">${raw(icon('info'))}<span class="p">Nothing was shared. The site only sees that the age check didn't finish.</span></div>
<p class="sm">Are you an adult? Sign in to Windows with your own account.</p></div>`,
        html`<button class="btn pri" data-act="ask-close">OK</button>`,
      );

    case 'integrity':
      return frame(
        v,
        html`<span class="si sm err">${raw(icon('finger'))}</span>
<h2 class="h2">Windows Hello isn't ready</h2>
<p class="p">${a.message ?? ''} V18 needs Windows Hello to use your age card. It never uses a weaker key instead.</p>`,
        html`<button class="btn pri" data-act="open-hello-settings">Open sign-in options</button><button class="btn" data-act="ask-phone">Use my phone this time</button>`,
      );

    default:
      return frame(
        v,
        html`${a.host ? siteLine(a, 'asked for an age check') : ''}<span class="si sm warn">${raw(icon('warn'))}</span>
<h2 class="h2">No ticket was sent</h2>
<p class="p">${a.message ?? 'Something went wrong.'}</p>`,
        html`<button class="btn pri" data-act="ask-close">Close</button>`,
      );
  }
}
