// Icons from the V18 design mock-ups (Fluent-style line icons, 24x24).

const ic = (body: string, cls = 'ic') =>
  `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${body}</svg>`;

export const ICONS = {
  logo: `<svg class="logo" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path class="s" d="M12 2.2l8 3.2v6.1c0 4.9-3.4 8.7-8 10.3-4.6-1.6-8-5.4-8-10.3V5.4z"></path><path class="c" d="M8.4 12.1l2.5 2.5 4.7-5.1"></path></svg>`,
  close: ic('<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"></path>'),
  qr: ic('<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2.5v2.5H14zM17.5 17.5H20V20h-2.5zM14 18.5v1.5M18.5 14H20"></path>'),
  monitor: ic('<rect x="3" y="4" width="18" height="12" rx="2"></rect><path d="M8.5 20h7M12 16v4"></path>'),
  wallet: ic('<path d="M4 7.5A2.5 2.5 0 0 1 6.5 5H17v3"></path><path d="M4 7.5V17a2 2 0 0 0 2 2h14V8H6.5A2.5 2.5 0 0 1 4 7.5z"></path><path d="M16 13.5h1.5"></path>'),
  chev: ic('<path d="M9 5.5l6.5 6.5L9 18.5"></path>', 'ic chev'),
  back: ic('<path d="M15 5.5L8.5 12l6.5 6.5"></path>'),
  yes: ic('<path d="M5 12.5l4.5 4.5L19 7.5"></path>', 'ic y'),
  no: ic('<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"></path>', 'ic n'),
  check: ic('<path d="M5 12.5l4.5 4.5L19 7.5"></path>'),
  cross: ic('<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"></path>'),
  lock: ic('<rect x="5" y="10.5" width="14" height="10" rx="2"></rect><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"></path>'),
  clock: ic('<circle cx="12" cy="12" r="8.5"></circle><path d="M12 7.5V12l3 2"></path>'),
  refresh: ic('<path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5V9H15"></path>'),
  fingerprint: ic('<path d="M8.5 5.6A7 7 0 0 1 19 11.6v1.2M5 9.7A7 7 0 0 0 4.9 12v.8M7.8 19.6c.8-1.8 1.2-3.7 1.2-5.8V12a3 3 0 0 1 6 0v1.8c0 2.4-.4 4.6-1.3 6.6M12 12v2c0 2.6-.6 5-1.7 7.2M18.6 16.4c-.2 1.2-.5 2.3-.9 3.4"></path>'),
  eyeOff: ic('<path d="M3 3l18 18M10.6 6.1c.5-.1.9-.1 1.4-.1 5 0 8.5 4.5 9.5 6-.5.8-1.4 2-2.7 3.2M6.6 7.6C4.5 9 3.1 11 2.5 12c1 1.5 4.5 6 9.5 6 1.6 0 3-.4 4.3-1.1M9.9 9.9a3 3 0 0 0 4.2 4.2"></path>'),
  wifiOff: ic('<path d="M3 3l18 18M8.6 16.2a5 5 0 0 1 6.3-.3M5.3 12.9a9.6 9.6 0 0 1 4.3-2.4M18.7 12.9a9.6 9.6 0 0 0-2-1.4M2 9.5a14.6 14.6 0 0 1 4.2-2.7M22 9.5A14.6 14.6 0 0 0 11 5.6M12 19.5v.01"></path>', 'ic s24'),
  info: ic('<circle cx="12" cy="12" r="8.5"></circle><path d="M12 11v5.2M12 7.9v.2"></path>'),
  globe: ic('<circle cx="12" cy="12" r="8.5"></circle><path d="M3.5 12h17M12 3.5c2.3 2.4 3.5 5.2 3.5 8.5s-1.2 6.1-3.5 8.5c-2.3-2.4-3.5-5.2-3.5-8.5s1.2-6.1 3.5-8.5z"></path>'),
  phone: ic('<rect x="7" y="2.5" width="10" height="19" rx="2.5"></rect><path d="M11 18.5h2"></path>'),
  flask: ic('<path d="M9.5 3.5h5M10.5 3.5v5.2L5.2 18a1.6 1.6 0 0 0 1.4 2.5h10.8a1.6 1.6 0 0 0 1.4-2.5l-5.3-9.3V3.5M7.5 14.5h9"></path>'),
};
