// Widget styles, from the V18 design mock-ups (Fluent style, blue). Lives inside a Shadow DOM,
// so the host page's CSS cannot touch it and it cannot touch the page. No web fonts are loaded
// (a font request would tell a third party who opened the age check).
export const WIDGET_CSS = `
:host{all:initial}
.as{--font:"Segoe UI Variable Text","Segoe UI Variable","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
--font-d:"Segoe UI Variable Display","Segoe UI Variable","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
--card:#FFFFFF;--card2:#F6F6F6;--stroke:#E3E3E3;--stroke2:#CFCFCF;--tx:#1B1B1B;--tx2:#5C5C5C;--tx3:#666666;
--accent:#2F5BD3;--accent-h:#2950BC;--on-accent:#FFFFFF;--accent-tx:#2450C2;--accent-bg:#E8EEFC;
--ok:#0E7A3E;--ok-bg:#E3F4E8;--warn:#8A5300;--warn-bg:#FFF4CE;--err:#C42B1C;--err-bg:#FDE7E9;--on-err:#FFFFFF;
--hover:rgba(0,0,0,.04);--scrim:rgba(20,20,20,.42);--focus:#1B1B1B;
--shadow-l:0 32px 64px rgba(0,0,0,.22),0 2px 20px rgba(0,0,0,.14);
font-family:var(--font);font-size:14px;line-height:20px;color:var(--tx);-webkit-font-smoothing:antialiased;text-align:left}
.as.dark{--card:#2E2E2E;--card2:#363636;--stroke:#3B3B3B;--stroke2:#555555;--tx:#FFFFFF;--tx2:#C8C8C8;--tx3:#ADADAD;
--accent:#8FB0FF;--accent-h:#A5C0FF;--on-accent:#0D1A3D;--accent-tx:#9DBBFF;--accent-bg:#27324D;
--ok:#74D19A;--ok-bg:#1F3628;--warn:#FFCB5C;--warn-bg:#3D3219;--err:#FF9AA2;--err-bg:#45272A;--on-err:#3B0D12;
--hover:rgba(255,255,255,.05);--scrim:rgba(0,0,0,.6);--focus:#FFFFFF;
--shadow-l:0 32px 64px rgba(0,0,0,.6),0 2px 20px rgba(0,0,0,.45);color-scheme:dark}
.as *,.as *::before,.as *::after{box-sizing:border-box}
.as h1,.as h2,.as h3,.as p,.as ul,.as ol{margin:0;padding:0}
.as ul,.as ol{list-style:none}
.as button{font:inherit;color:inherit}
.as [hidden]{display:none!important}
.vh{position:absolute!important;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}

/* overlay + dialog */
.ov{position:fixed;inset:0;z-index:2147483646;display:flex;align-items:center;justify-content:center;padding:16px;background:var(--scrim);overflow:auto;animation:fade .18s ease-out}
@keyframes fade{from{opacity:0}to{opacity:1}}
.wm{position:relative;width:840px;max-width:100%;max-height:calc(100vh - 32px);overflow:auto;display:flex;flex-direction:column;background:var(--card);border-radius:16px;box-shadow:var(--shadow-l);margin:auto}
.wm.compact{width:560px}
.wm-h{display:flex;align-items:center;gap:10px;height:60px;flex:none;padding:0 12px 0 22px;border-bottom:1px solid var(--stroke)}
.wm-h .logo{width:22px;height:22px}
.wm-b{display:flex}
.wm-l{flex:1;min-width:0;display:flex;flex-direction:column;gap:14px;padding:26px 28px}
.wm-r{width:300px;flex:none;display:flex;flex-direction:column;gap:14px;padding:26px;background:var(--card2);border-left:1px solid var(--stroke)}
.wm-f{display:flex;align-items:center;gap:8px;min-height:52px;flex:none;padding:8px 22px;border-top:1px solid var(--stroke);font-size:12px;line-height:16px;color:var(--tx2)}
.wm-f:empty{display:none}
.wm-f .ic{width:16px;height:16px}
.wm-f .r{margin-left:auto}
.split{display:flex;gap:40px;align-items:flex-start;padding:32px 36px}
.split.ac{align-items:center}
.pad-done{padding:40px 48px 36px}

/* test mode banner */
.tm{display:flex;align-items:flex-start;gap:10px;padding:10px 22px;background:var(--warn-bg);color:var(--warn);border-bottom:1px solid var(--stroke);font-size:13px;line-height:18px}
.tm .b{color:var(--warn)}
.tm .ic{width:18px;height:18px;margin-top:0}
.dev{display:flex;flex-direction:column;gap:8px;padding:12px 14px;border:1.5px dashed var(--warn);border-radius:8px;background:var(--warn-bg);color:var(--tx)}
.dev .ic{color:var(--warn)}
.errtx{color:var(--err)!important}

/* type */
.h1{font-family:var(--font-d);font-size:28px;line-height:36px;font-weight:600}
.h2{font-family:var(--font-d);font-size:20px;line-height:28px;font-weight:600}
.h3{font-size:14px;line-height:20px;font-weight:600}
.p{color:var(--tx2)}
.sm{font-size:12px;line-height:16px;color:var(--tx3)}
.b{font-weight:600;color:var(--tx)}
.b.dk{color:#1B1B1B}
.mono{font-family:"Cascadia Mono",Consolas,ui-monospace,monospace}

/* layout helpers */
.row{display:flex;align-items:center;gap:12px}
.col{display:flex;flex-direction:column;gap:12px}
.grow{flex:1;min-width:0}
.g2{gap:2px}.g4{gap:4px}.g6{gap:6px}.g8{gap:8px}.g14{gap:14px}.g16{gap:16px}.g18{gap:18px}
.sb{justify-content:space-between}.jc{justify-content:center}.wrap{flex-wrap:wrap}.ac{align-items:center}
.center{display:flex;justify-content:center;align-items:center}.tc{text-align:center}
.self-start{align-self:flex-start}.mt8{margin-top:8px}
.w260{width:260px;flex:none}

/* icons */
.ic{width:20px;height:20px;flex:none;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.ic.s24{width:24px;height:24px}
.logo{width:20px;height:20px;flex:none}
.logo .s{fill:var(--accent)}
.logo .c{fill:none;stroke:var(--on-accent);stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}

/* buttons and links */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:40px;padding:0 18px;border-radius:6px;border:1px solid var(--stroke2);background:var(--card);color:var(--tx);font-weight:500;cursor:pointer;white-space:nowrap}
.btn:hover{background:var(--card2)}
.btn[disabled]{opacity:.6;cursor:progress}
.btn.pri{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.btn.pri:hover{background:var(--accent-h);border-color:var(--accent-h)}
.btn.sub{background:transparent;border-color:transparent;color:var(--accent-tx)}
.btn.sub:hover{background:var(--accent-bg)}
.btn.wide{min-width:280px;margin-top:8px}
.btn .ic{width:18px;height:18px}
.lnk{color:var(--accent-tx);cursor:pointer;background:none;border:0;padding:4px 0;font-size:inherit}
.lnk:hover{text-decoration:underline}
.lnk.r{margin-left:auto}
.x{width:40px;height:40px;flex:none;border-radius:6px;display:inline-flex;align-items:center;justify-content:center;margin-left:auto;color:var(--tx2);cursor:pointer;background:none;border:0}
.x:hover{background:var(--hover)}
.as :focus-visible{outline:2px solid var(--focus);outline-offset:2px;box-shadow:0 0 0 4px var(--card)}
.as h2:focus{outline:none}

/* surfaces */
.card{background:var(--card);border:1px solid var(--stroke);border-radius:8px;padding:16px 20px}

/* option rows */
.opt{display:flex;align-items:center;gap:16px;width:100%;min-height:76px;padding:12px 16px;background:var(--card);border:1px solid var(--stroke);border-radius:8px;cursor:pointer;text-align:left}
.opt:hover{background:var(--card2);border-color:var(--stroke2)}
.oi{width:40px;height:40px;flex:none;border-radius:8px;display:flex;align-items:center;justify-content:center;background:var(--accent-bg);color:var(--accent-tx)}
.oi .ic{width:22px;height:22px}
.opt .grow{display:flex;flex-direction:column;gap:2px}
.opt .t{display:flex;align-items:center;flex-wrap:wrap;gap:8px;font-weight:600}
.opt .d{font-size:13px;line-height:18px;color:var(--tx2)}
.chev{width:16px;height:16px;color:var(--tx3)}

/* badges */
.badge{display:inline-flex;align-items:center;gap:4px;min-height:22px;padding:0 9px;border-radius:11px;font-size:12px;line-height:16px;font-weight:600}
.badge .ic{width:14px;height:14px;stroke-width:2}
.b-acc{background:var(--accent-bg);color:var(--accent-tx)}
.b-ok{background:var(--ok-bg);color:var(--ok)}
.b-warn{background:var(--warn-bg);color:var(--warn)}
.b-err{background:var(--err-bg);color:var(--err)}

/* info bars */
.ibar{display:flex;align-items:flex-start;gap:12px;padding:12px 16px;border-radius:6px;background:var(--card);border:1px solid var(--stroke)}
.ibar.ac{align-items:center}
.ibar .ic{color:var(--accent-tx)}
.ibar.warn{background:var(--warn-bg);border-color:transparent}.ibar.warn .ic{color:var(--warn)}

/* status circles */
.si{width:72px;height:72px;flex:none;border-radius:50%;display:flex;align-items:center;justify-content:center;background:var(--accent-bg);color:var(--accent-tx)}
.si .ic{width:34px;height:34px;stroke-width:1.7}
.si .logo{width:34px;height:34px}
.si.ok{background:var(--ok-bg);color:var(--ok)}
.si.warn{background:var(--warn-bg);color:var(--warn)}
.si.err{background:var(--err-bg);color:var(--err)}
.si.sm{width:48px;height:48px}.si.sm .ic{width:24px;height:24px}

/* lists */
.ck{display:flex;flex-direction:column;gap:8px}
.ck li{display:flex;align-items:flex-start;gap:10px}
.ck .ic{width:18px;height:18px;margin-top:1px;stroke-width:2}
.ck .y{color:var(--ok)}
.ck .n{color:var(--tx3)}
.ol{display:flex;flex-direction:column;gap:12px;counter-reset:s}
.ol li{display:flex;align-items:flex-start;gap:12px}
.ol li::before{counter-increment:s;content:counter(s);width:24px;height:24px;flex:none;border-radius:50%;display:flex;align-items:center;justify-content:center;background:var(--accent-bg);color:var(--accent-tx);font-size:12px;font-weight:700}

/* progress */
@keyframes spin{to{transform:rotate(360deg)}}
.spin{width:20px;height:20px;flex:none;border-radius:50%;border:2.5px solid var(--accent-bg);border-top-color:var(--accent);animation:spin .9s linear infinite}
.spin.lg{width:44px;height:44px;border-width:4px}
.spin.sm{width:14px;height:14px;border-width:2px}
.prog{height:4px;border-radius:2px;background:var(--stroke);overflow:hidden}
.prog i{display:block;height:100%;border-radius:2px;background:var(--accent);transition:width .9s linear}
.pl{display:flex;flex-direction:column;gap:14px}
.pl li{display:flex;align-items:center;gap:12px}
.pl .d{width:24px;height:24px;flex:none;border-radius:50%;border:1.5px solid var(--stroke2);display:flex;align-items:center;justify-content:center}
.pl .done .d{background:var(--ok);border-color:var(--ok);color:var(--card)}
.pl .done .d .ic{width:14px;height:14px;stroke-width:2.6}
.pl .cur{font-weight:600}
.pl .cur .d{border:2.5px solid var(--accent-bg);border-top-color:var(--accent);animation:spin .9s linear infinite}
.pl .todo{color:var(--tx3)}

/* QR: always dark on white, even in dark mode, so phone cameras can read it */
.qr{position:relative;display:flex;align-items:center;justify-content:center;width:260px;height:260px;padding:16px;border-radius:12px;background:#FFFFFF;border:1px solid var(--stroke)}
.qr svg{display:block;width:100%;height:100%}
.qr.dim svg{filter:blur(3px);opacity:.22}
.qr.loading{background:var(--card2)}
.qover{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;padding:16px;text-align:center;color:#1B1B1B}
.qover .ic{width:32px;height:32px}

/* phone and PC drawings */
.phone,.pc{position:relative;flex:none;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;padding:16px;background:var(--card);border:3px solid var(--tx2)}
.phone{width:132px;height:236px;border-radius:24px}
.phone::before{content:"";position:absolute;top:10px;left:50%;width:36px;height:5px;margin-left:-18px;border-radius:3px;background:var(--stroke2)}
.pc{width:220px;height:150px;border-radius:10px}
.pc::after{content:"";position:absolute;bottom:-22px;left:50%;width:80px;height:6px;margin-left:-40px;border-radius:3px;background:var(--tx2)}
.pb{position:absolute;right:-16px;top:-16px;width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:var(--ok);color:var(--card);border:4px solid var(--card)}
.pb.wait{background:var(--accent);color:var(--on-accent)}
.pb.bad{background:var(--err);color:var(--on-err)}
.pb .ic{width:20px;height:20px;stroke-width:2.4}
.phone .ln,.pc .ln{height:6px;width:70%;border-radius:3px;background:var(--stroke)}
.phone .logo,.pc .logo{width:34px;height:34px}
.phone > .ic{width:34px;height:34px;color:var(--tx2)}

/* small screens: stack the columns */
@media (max-width:720px){
  .wm-b{flex-direction:column}
  .wm-r{width:auto;border-left:0;border-top:1px solid var(--stroke)}
  .split{flex-direction:column;align-items:stretch;gap:24px;padding:24px 20px}
  .w260{width:auto}
  .qr{margin:0 auto;width:min(260px,100%);height:auto;aspect-ratio:1}
  .wm-l,.wm-r{padding:20px}
  .btn.wide{min-width:0;width:100%}
}
@media (prefers-reduced-motion:reduce){
  .ov{animation:none}
  .spin,.pl .cur .d{animation:none;border-top-color:var(--accent);border-right-color:var(--accent)}
  .prog i{transition:none}
}
@media (forced-colors:active){
  .opt,.btn,.ibar,.card,.qr{border:1px solid CanvasText}
}
`;
