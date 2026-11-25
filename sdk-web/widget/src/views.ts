/**
 * HTML for each widget screen. Pure functions of the state, so they can be tested without a browser.
 * Copy and layout follow the V18 design mock-ups: WidgetChoose, QrWaiting, QrConnected, QrApproved, QrDone,
 * QrExpired, QrRetry, WidgetWallet.
 */
import { ICONS as I } from './icons.js';
import { generateQrSvg } from './qr.js';
import { esc, formatClock } from './util.js';
import type { WidgetState } from './controller.js';

export interface ViewHtml {
  body: string;
  footer: string;
  /** A narrower dialog (done screen). */
  compact?: boolean;
  /** Hide the close button (done screen, like the design). */
  hideClose?: boolean;
}

const h2 = (text: string) => `<h2 class="h2" id="v18-title" tabindex="-1">${text}</h2>`;
const h1 = (text: string) => `<h2 class="h1" id="v18-title" tabindex="-1">${text}</h2>`;
const lockFooter = (text: string, right = '') => `${I.lock}<span>${text}</span>${right}`;
const backLink = (label = 'Choose another way') =>
  `<button type="button" class="lnk row g6" data-act="back">${I.back}${label}</button>`;

function timerBlock(s: WidgetState, label = 'Code expires in'): string {
  const pct = s.totalSeconds > 0 ? Math.round((s.secondsLeft / s.totalSeconds) * 100) : 0;
  return `<div class="col g6">
    <div class="row sb"><span class="sm" id="v18-timer-label">${label}</span>
      <span class="b mono" role="timer" aria-labelledby="v18-timer-label" data-timer>${formatClock(s.secondsLeft)}</span></div>
    <div class="prog" aria-hidden="true"><i data-prog style="width:${pct}%"></i></div>
  </div>`;
}

function phoneDrawing(badge: 'ok' | 'wait' | 'bad', center: string): string {
  const icon = badge === 'ok' ? I.check : badge === 'bad' ? I.cross : I.clock;
  return `<div class="phone" aria-hidden="true"><span class="pb ${badge === 'ok' ? '' : badge}">${icon}</span>${center}
    <span class="ln"></span><span class="ln" style="width:50%"></span></div>`;
}

function pcDrawing(badge: 'ok' | 'wait' | 'bad'): string {
  const icon = badge === 'ok' ? I.check : badge === 'bad' ? I.cross : I.clock;
  return `<div class="pc" aria-hidden="true"><span class="pb ${badge === 'ok' ? '' : badge}">${icon}</span>${I.logo}
    <span class="ln"></span><span class="ln" style="width:50%"></span></div>`;
}

/** The dev-only box with the test-wallet button. Shown only when the controller allows it. */
function devBox(s: WidgetState, allowed: boolean, target: string): string {
  if (!allowed) return '';
  const tw = s.testWallet;
  return `<div class="dev" role="group" aria-label="Developer tools (test mode only)">
    <div class="row g8">${I.flask}<span class="b">${esc(tw.label)}</span><span class="badge b-warn">Dev only</span></div>
    <p class="sm">Acts as ${target} inside this browser. It runs the real V18 flow with a test age card
      (<span class="mono">test_dev</span>) and a real blind-signed ticket. Never use this for real age checks.</p>
    <div class="row g8 wrap">
      <button type="button" class="btn" data-act="simulate" ${tw.busy ? 'disabled aria-disabled="true"' : ''}>
        ${tw.busy ? '<span class="spin sm" aria-hidden="true"></span>' : ''}Simulate ${target} with the test wallet</button>
    </div>
    ${tw.message ? `<p class="sm ${tw.failed ? 'errtx' : ''}" role="${tw.failed ? 'alert' : 'status'}">${esc(tw.message)}</p>` : ''}
  </div>`;
}

export function renderView(s: WidgetState, opts: { canSimulate: boolean }): ViewHtml {
  const host = esc(s.host);
  const age = s.minAge;

  switch (s.view) {
    case 'choose': {
      // The wallet option exists only when this browser AND the V18 server can do it.
      const wallet = s.walletSupport && s.walletServer;
      return {
        body: `<div class="wm-b">
          <div class="wm-l">
            <div class="col g4">${h2('Check your age privately')}
              <p class="p" id="v18-desc">${host} asks: are you ${age} or older? Choose how you want to show it.</p></div>
            <button type="button" class="opt" data-act="phone">
              <span class="oi">${I.qr}</span>
              <span class="grow"><span class="t">Use my phone (scan a QR)<span class="badge b-acc">Works on any PC</span></span>
              <span class="d">Scan a code with the V18 app. Your phone checks your ID.</span></span>${I.chev}
            </button>
            <button type="button" class="opt" data-act="windows">
              <span class="oi">${I.monitor}</span>
              <span class="grow"><span class="t">Use V18 for Windows</span>
              <span class="d">Use the age card saved on this PC. Unlock it with Windows Hello.</span></span>${I.chev}
            </button>
            ${wallet ? `<button type="button" class="opt" data-act="wallet">
              <span class="oi">${I.wallet}</span>
              <span class="grow"><span class="t">Use a phone wallet ID</span>
              <span class="d">Your browser asks the ID in your phone's wallet to share only "over ${age}: yes".</span></span>${I.chev}
            </button>` : ''}
            <p class="sm">No V18 app yet? Install V18 on your Android phone or Windows PC first.</p>
          </div>
          <div class="wm-r">
            <h3 class="h3">What ${host} gets</h3>
            <ul class="ck">
              <li>${I.yes}<span class="b">${age}+: yes</span></li>
              <li>${I.yes}<span>A one-time ticket that can't be reused</span></li>
            </ul>
            <h3 class="h3 mt8">What it never gets</h3>
            <ul class="ck">
              <li>${I.no}<span>Your name</span></li>
              <li>${I.no}<span>Your date of birth</span></li>
              <li>${I.no}<span>Your ID number or photo</span></li>
              <li>${I.no}<span>Your face</span></li>
              <li>${I.no}<span>Which other sites you visit</span></li>
            </ul>
          </div>
        </div>`,
        footer: lockFooter(
          'Only a proof leaves your device. V18 stores nothing about you.',
          '<button type="button" class="lnk r" data-act="how">How it works</button>'
        ),
      };
    }

    case 'starting':
      return {
        body: `<div class="split">
          <div class="col w260 g14"><div class="qr loading" role="img" aria-label="Getting a code">
            <span class="spin lg" aria-hidden="true"></span></div></div>
          <div class="col grow g18">${h2(s.method === 'windows' ? 'Getting V18 for Windows ready…' : s.method === 'wallet' ? 'Getting your browser ready…' : 'Getting a code…')}
            <p class="p">${s.method === 'wallet'
              ? `Asking ${host} for a one-time challenge, then asking V18 to prepare the question for your wallet.`
              : `Asking ${host} for a one-time challenge, then asking V18 for a short-lived code.`}</p></div>
        </div>`,
        footer: backLink(),
      };

    case 'qr_waiting':
      return {
        body: `<div class="split">
          <div class="col w260 g14">
            <div class="qr" role="img" aria-label="QR code for the V18 app on your phone. It works once and lasts ${Math.round(s.totalSeconds / 60)} minutes.">
              ${generateQrSvg(s.qrData ?? '', 4, 0)}</div>
            ${timerBlock(s)}
          </div>
          <div class="col grow g18">${h2('Scan with your phone')}
            <ol class="ol">
              <li>Open V18 on your phone.</li>
              <li><span>Tap <span class="b">Scan a code</span>.</span></li>
              <li>Point your camera at this QR code.</li>
              <li>Check your ID on your phone, then approve.</li>
            </ol>
            <div class="ibar ac"><span class="spin" aria-hidden="true"></span><span class="col g2">
              <span class="b">Waiting for your phone…</span>
              <span class="sm">This code works once, and only for ${host}.</span></span></div>
            <p class="sm">Your ID is read on your phone. This PC and the site never see it.</p>
            ${devBox(s, opts.canSimulate, 'a phone')}
          </div>
        </div>`,
        footer: `${backLink()}<span class="r">No app? Install V18 on your Android phone first.</span>`,
      };

    case 'connected':
      return {
        body: `<div class="split ac">
          <div class="w260 center">${phoneDrawing('ok', I.logo)}</div>
          <div class="col grow g16">
            <span class="badge b-ok self-start">${I.check}Phone connected</span>
            ${h2('Now check your ID on your phone')}
            <p class="p">Follow the steps on your phone. When it's done, approve the ${age}+ ticket with your fingerprint, face or PIN.</p>
            <div class="ibar ac"><span class="spin" aria-hidden="true"></span><span class="col g2">
              <span class="b">Waiting for you to approve on your phone…</span>
              <span class="sm">Your phone reads your ID. Only a proof leaves it.</span></span></div>
            ${timerBlock(s, 'Time left')}
          </div>
        </div>`,
        footer: `<button type="button" class="lnk" data-act="back">Cancel</button><span class="r">Connected to: your phone</span>`,
      };

    case 'win_waiting':
      return {
        body: `<div class="split ac">
          <div class="w260 center">${pcDrawing(s.windowsAppOpened ? 'ok' : 'wait')}</div>
          <div class="col grow g16">
            ${s.windowsAppOpened ? `<span class="badge b-ok self-start">${I.check}V18 for Windows is open</span>` : ''}
            ${h2(s.windowsAppOpened ? 'Approve in V18 for Windows' : 'Opening V18 for Windows…')}
            <p class="p">Unlock your age card with Windows Hello to give ${host} a one-time ${age}+ ticket. This request works once, and only for ${host}.</p>
            <div class="ibar ac"><span class="spin" aria-hidden="true"></span><span class="col g2">
              <span class="b">${s.windowsAppOpened ? 'Waiting for you to approve…' : 'Waiting for V18 for Windows…'}</span>
              <span class="sm">If your browser asks to open V18, choose Open.</span></span></div>
            ${s.windowsHelpHint ? `<div class="ibar warn" role="status">${I.info}<span class="col g2">
              <span class="b">Nothing happened?</span>
              <span class="p">You may not have V18 for Windows on this PC yet.</span></span></div>` : ''}
            ${timerBlock(s, 'Request expires in')}
            <div class="row g8 wrap">
              <button type="button" class="btn" data-act="reopen">${I.refresh}Open V18 again</button>
              <button type="button" class="btn sub" data-act="help">Don't have the app?</button>
            </div>
            ${devBox(s, opts.canSimulate, 'V18 for Windows')}
          </div>
        </div>`,
        footer: `${backLink()}<span class="r">Your age card stays on this PC, locked by Windows Hello.</span>`,
      };

    case 'win_help':
      return {
        body: `<div class="split">
          <div class="w260 center">${pcDrawing('bad')}</div>
          <div class="col grow g16">${h2("Don't have V18 for Windows?")}
            <p class="p">Install <span class="b">V18 for Windows</span> on this PC, add your age card once, then try again.</p>
            <p class="p">No time for that? <span class="b">Use your phone instead.</span> It works on any PC: you scan a code with the V18 app.</p>
            <div class="ibar">${I.info}<span class="p">Browsers don't tell websites whether an app opened, so we can't be sure. If V18 for Windows did open, just approve there: this page is still waiting.</span></div>
            <div class="row g8 wrap">
              <button type="button" class="btn pri" data-act="phone">${I.qr}Use my phone instead</button>
              <button type="button" class="btn" data-act="reopen">${I.refresh}Try opening again</button>
            </div>
            ${timerBlock(s, 'Request expires in')}
            ${devBox(s, opts.canSimulate, 'V18 for Windows')}
          </div>
        </div>`,
        footer: `<button type="button" class="lnk row g6" data-act="win_back">${I.back}Back</button>`,
      };

    case 'approved': {
      const giving = s.progress === 'giving';
      if (s.method === 'wallet') {
        return {
          body: `<div class="split ac">
            <div class="w260 center"><span class="si ok">${I.wallet}</span></div>
            <div class="col grow g16">
              <span class="badge b-ok self-start">${I.check}Your wallet said ${age}+: yes</span>
              ${h2(`Getting your ${age}+ ticket`)}
              <div class="card"><ul class="pl">
                <li class="done"><span class="d">${I.check}</span>Your wallet shared "over ${age}: yes"</li>
                <li class="done"><span class="d">${I.check}</span>V18 checked the ID's digital seal</li>
                <li class="${giving ? 'done' : 'cur'}"><span class="d">${giving ? I.check : ''}</span>Getting a one-time ticket from V18</li>
                <li class="${giving ? 'cur' : 'todo'}"><span class="d"></span>Giving it to ${host}</li>
              </ul></div>
              <p class="sm">V18 makes the ticket from the wallet's answer, then forgets the answer.</p>
            </div>
          </div>`,
          footer: lockFooter(`Only "over ${age}: yes" left your wallet.`),
        };
      }
      const phone = s.method !== 'windows';
      return {
        body: `<div class="split ac">
          <div class="w260 center">${phone ? phoneDrawing('ok', `<span class="si sm ok">${I.fingerprint}</span>`) : pcDrawing('ok')}</div>
          <div class="col grow g16">
            <span class="badge b-ok self-start">${I.check}${phone ? 'Approved on your phone' : 'Approved in V18 for Windows'}</span>
            ${h2(`Getting your ${age}+ ticket`)}
            <div class="card"><ul class="pl">
              <li class="done"><span class="d">${I.check}</span>${phone ? 'Phone connected' : 'V18 for Windows opened'}</li>
              <li class="done"><span class="d">${I.check}</span>${phone ? 'ID checked on your phone' : 'Age card unlocked with Windows Hello'}</li>
              <li class="${giving ? 'done' : 'cur'}"><span class="d">${giving ? I.check : ''}</span>Getting a one-time ticket from V18</li>
              <li class="${giving ? 'cur' : 'todo'}"><span class="d"></span>Giving it to ${host}</li>
            </ul></div>
            <p class="sm">The ticket is sealed without V18 seeing it, so it can't be linked back to you.</p>
          </div>
        </div>`,
        footer: lockFooter(phone ? 'Only a proof left your phone.' : 'Only a proof left V18 for Windows.'),
      };
    }

    case 'done':
      return {
        compact: true,
        hideClose: true,
        body: `<div class="col ac center tc g16 pad-done">
          <span class="si ok">${I.check}</span>
          ${h1(s.usesVerifyUrl ? `You're verified as ${age}+` : `Your ${age}+ ticket is ready`)}
          <p class="p">${host} got a one-time ticket that says ${age}+. Nothing else.</p>
          <div class="row g8 jc wrap">
            <span class="badge b-ok">${I.check}Shared: ${age}+ yes</span>
            <span class="badge b-acc">${I.eyeOff}Not shared: name, birthday, ID, face</span>
          </div>
          <button type="button" class="btn pri wide" data-act="continue">Continue to ${host}</button>
          <p class="sm">This window closes by itself in 3 seconds.</p>
        </div>`,
        footer: '',
      };

    case 'expired': {
      const phone = s.method === 'phone' || s.method === null;
      const wallet = s.method === 'wallet';
      return {
        body: `<div class="split">
          <div class="col w260 g14">
            ${phone
              ? `<div class="qr dim" aria-hidden="true">${generateQrSvg(s.qrData ?? 'expired', 4, 0)}<div class="qover">${I.clock}<span class="b dk">Code expired</span></div></div>`
              : wallet
                ? `<div class="center"><span class="si warn">${I.wallet}</span></div>`
                : `<div class="center">${pcDrawing('bad')}</div>`}
            <div class="col g6"><div class="row sb"><span class="sm">${phone ? 'Code expires in' : 'Request expires in'}</span><span class="b mono">0:00</span></div>
              <div class="prog" aria-hidden="true"><i style="width:0%"></i></div></div>
          </div>
          <div class="col grow g16">
            <span class="badge b-warn self-start">${I.clock}Expired</span>
            ${h2(phone ? 'This code has expired' : 'This request has expired')}
            <p class="p">${phone
              ? 'For your safety, each code lasts 2 minutes and works only once. Get a new code and scan it with your phone.'
              : wallet
                ? 'For your safety, each wallet request lasts 2 minutes and works only once. Try again and share from your wallet.'
                : 'For your safety, each request lasts 2 minutes and works only once. Try again and approve in V18 for Windows.'}</p>
            <div class="row g8 wrap">
              <button type="button" class="btn pri" data-act="retry">${I.refresh}${phone ? 'Get a new code' : 'Try again'}</button>
              <button type="button" class="btn" data-act="back">Choose another way</button>
            </div>
            <p class="sm">Nothing was shared. The site got no ticket.</p>
          </div>
        </div>`,
        footer: lockFooter(phone ? "Old codes can't be reused, so a copied code is useless." : "Old requests can't be reused."),
      };
    }

    case 'retry': {
      const lost = s.errorCode === 'CONNECTION_LOST';
      const phone = s.method === 'phone' || s.method === null;
      const title = lost
        ? phone ? 'We lost the connection to your phone' : 'We lost the connection to V18'
        : "We couldn't start the age check";
      const text = lost
        ? phone
          ? 'Check that your phone has internet and the V18 app is open. Then try again with a new code.'
          : 'Check that this PC has internet. Then try again.'
        : 'This PC could not reach V18 or this website. Check your internet connection, then try again.';
      return {
        body: `<div class="split ac">
          <div class="w260 center">${phone ? phoneDrawing('bad', I.wifiOff) : s.method === 'wallet' ? `<span class="si err">${I.wifiOff}</span>` : pcDrawing('bad')}</div>
          <div class="col grow g16">
            <span class="badge b-err self-start">Not connected</span>
            ${h2(title)}
            <p class="p">${text}</p>
            ${s.error ? `<p class="sm">Details: ${esc(s.error)}${s.errorCode && !lost ? ` (${esc(s.errorCode)})` : ''}</p>` : ''}
            <div class="row g8 wrap">
              <button type="button" class="btn pri" data-act="retry">${I.refresh}Try again</button>
              <button type="button" class="btn" data-act="back">Choose another way</button>
            </div>
            <div class="ibar">${I.info}<span class="p">Nothing was shared and nothing was saved. The site got no ticket.</span></div>
          </div>
        </div>`,
        footer: '',
      };
    }

    case 'site_refused':
      return {
        body: `<div class="split ac">
          <div class="w260 center"><span class="si err">${I.cross}</span></div>
          <div class="col grow g16">
            <span class="badge b-err self-start">Not accepted</span>
            ${h2(`${host} did not accept the ticket`)}
            <p class="p">Its server checked the ticket and said no. Nothing about you was shared. You can try again with a new ticket.</p>
            ${s.error ? `<p class="sm">The site said: ${esc(s.error)}${s.errorCode ? ` (${esc(s.errorCode)})` : ''}</p>` : ''}
            <div class="row g8 wrap">
              <button type="button" class="btn pri" data-act="retry">${I.refresh}Try again</button>
              <button type="button" class="btn" data-act="back">Choose another way</button>
            </div>
          </div>
        </div>`,
        footer: lockFooter('Each ticket works once, so a refused ticket is thrown away.'),
      };

    case 'wallet_ready':
      return {
        body: `<div class="split ac">
          <div class="w260 center"><span class="si">${I.wallet}</span></div>
          <div class="col grow g16">${h2('Ask your phone wallet')}
            <p class="p">Your browser will ask the ID in your phone's wallet for one thing: <span class="b">over ${age}, yes or no</span>.</p>
            <div class="row g8 wrap">
              <button type="button" class="btn pri" data-act="wallet_open">${I.wallet}Open my wallet</button>
            </div>
            ${timerBlock(s, 'Request expires in')}
          </div>
        </div>`,
        footer: `${backLink()}<span class="r">Not shared: name, birth date, photo, ID number.</span>`,
      };

    case 'wallet_waiting':
      return {
        body: `<div class="split ac">
          <div class="w260 center"><span class="si">${I.wallet}</span></div>
          <div class="col grow g16">${h2('Waiting for your browser')}
            <p class="p">Your browser asks your phone's wallet. Only "over ${age}: yes" comes back. V18 turns it into a one-time ticket for ${host}.</p>
            <div class="ibar ac"><span class="spin" aria-hidden="true"></span><span class="col g2">
              <span class="b">Follow the steps your browser shows…</span>
              <span class="sm">If it shows a code, scan it with your phone and approve in the wallet.</span></span></div>
            <p class="sm">Not shared: name, birth date, photo, ID number.</p>
            ${timerBlock(s, 'Request expires in')}
          </div>
        </div>`,
        footer: backLink(),
      };

    case 'wallet_checking':
      return {
        body: `<div class="split ac">
          <div class="w260 center"><span class="si">${I.wallet}</span></div>
          <div class="col grow g16">${h2('Checking the answer')}
            <div class="ibar ac"><span class="spin" aria-hidden="true"></span><span class="col g2">
              <span class="b">V18 is checking your wallet's answer…</span>
              <span class="sm">It checks the ID's digital seal, and that the answer was made just now for ${host}.</span></span></div>
          </div>
        </div>`,
        footer: lockFooter(`Only "over ${age}: yes" left your wallet.`),
      };

    case 'wallet_failed': {
      const code = s.errorCode ?? '';
      const cancelled = code === 'WALLET_CANCELLED';
      const under = code === 'UNDER_AGE';
      const issuer = /ISSUER|IACA|TRUST/.test(code);
      const title = cancelled
        ? 'Your wallet shared nothing'
        : under
          ? `Your wallet did not say ${age}+`
          : issuer
            ? "V18 can't accept this ID"
            : "V18 couldn't use your wallet's answer";
      const text = cancelled
        ? 'You closed the wallet, or it has no ID that can answer. Nothing was shared.'
        : under
          ? `The ID in your wallet answered "over ${age}: no", so ${host} gets no ticket.`
          : issuer
            ? 'The ID in your wallet comes from an issuer V18 does not trust. Try the V18 app instead.'
            : 'The answer could not be checked, so nothing was passed on. You can try again.';
      return {
        body: `<div class="split ac">
          <div class="w260 center"><span class="si ${under ? 'err' : 'warn'}">${I.wallet}</span></div>
          <div class="col grow g16">
            <span class="badge ${under ? 'b-err' : 'b-warn'} self-start">${cancelled ? 'Nothing shared' : 'Not accepted'}</span>
            ${h2(title)}
            <p class="p">${text}</p>
            ${s.error && !cancelled ? `<p class="sm">Details: ${esc(s.error)}${code ? ` (${esc(code)})` : ''}</p>` : ''}
            <div class="row g8 wrap">
              ${under ? '' : `<button type="button" class="btn pri" data-act="retry">${I.refresh}Try again</button>`}
              <button type="button" class="btn${under ? ' pri' : ''}" data-act="back">Choose another way</button>
            </div>
          </div>
        </div>`,
        footer: lockFooter('The site got no ticket.'),
      };
    }

    case 'how':
      return {
        body: `<div class="split">
          <div class="w260 center"><span class="si">${I.logo}</span></div>
          <div class="col grow g16">${h2('How V18 works')}
            <ol class="ol">
              <li>Your phone or PC checks your ID. The ID never leaves it.</li>
              <li>V18 seals a one-time ${age}+ ticket without seeing it, so the ticket can't be linked back to you.</li>
              <li>${host}'s own server checks the seal and lets you in. It learns only "${age}+: yes".</li>
            </ol>
            ${s.walletSupport && s.walletServer ? `<p class="sm">With a phone wallet ID, your wallet tells V18 only "over ${age}: yes". V18 checks the ID's digital seal, makes the ticket, and forgets the answer.</p>` : ''}
            <div class="row g8"><button type="button" class="btn" data-act="back">${I.back}Back</button></div>
          </div>
        </div>`,
        footer: lockFooter('V18 stores nothing about you.'),
      };
  }
}

/** What a screen reader hears when the screen changes. */
export function announcement(s: WidgetState): string {
  switch (s.view) {
    case 'starting': return s.method === 'wallet' ? 'Getting your browser ready.' : 'Getting a code.';
    case 'qr_waiting': return 'QR code ready. Scan it with the V18 app on your phone.';
    case 'connected': return 'Phone connected. Approve on your phone.';
    case 'win_waiting': return s.windowsAppOpened ? 'V18 for Windows is open. Approve there.' : 'Opening V18 for Windows.';
    case 'win_help': return "Help: don't have V18 for Windows?";
    case 'approved': return s.progress === 'giving' ? `Giving the ticket to ${s.host}.` : s.method === 'wallet' ? 'Your wallet said yes. Getting your ticket.' : 'Approved. Getting your ticket.';
    case 'done': return `Done. ${s.host} got a one-time ${s.minAge}+ ticket.`;
    case 'expired': return 'The code expired. Nothing was shared.';
    case 'retry': return 'Not connected. Nothing was shared.';
    case 'site_refused': return `${s.host} did not accept the ticket.`;
    case 'wallet_ready': return 'Ready to ask your phone wallet. Press Open my wallet.';
    case 'wallet_waiting': return 'Waiting for your browser and your phone wallet.';
    case 'wallet_checking': return "V18 is checking your wallet's answer.";
    case 'wallet_failed': return s.errorCode === 'WALLET_CANCELLED' ? 'Your wallet shared nothing.' : "Your wallet's answer was not accepted.";
    default: return '';
  }
}

export function testModeBanner(s: WidgetState): string {
  if (s.devMode !== true) return '';
  return `<div class="tm" role="note">${I.flask}<span><span class="b">TEST MODE.</span> This V18 server is for testing. Its tickets are not real age checks.</span></div>`;
}
