/**
 * Deep links (PROTOCOL.md 3.8):
 *   v18://verify?session=<id>&origin=<urlenc>&challenge=<urlenc>&minAge=18&server=<urlenc base URL>
 */

export interface DeepLinkParts {
  sessionId: string;
  origin: string;
  challenge: string;
  minAge: number;
  serverUrl: string; // base URL without /v1
}

export function buildVerifyDeepLink(p: DeepLinkParts): string {
  const q = (v: string) => encodeURIComponent(v);
  return (
    `v18://verify?session=${q(p.sessionId)}&origin=${q(p.origin)}&challenge=${q(p.challenge)}` +
    `&minAge=${p.minAge}&server=${q(p.serverUrl)}`
  );
}

/**
 * Uses the server's deep link if it is a v18://verify link for this session; adds `server=` if it is
 * missing (older servers left it out). Otherwise builds the link from the parts.
 */
export function ensureVerifyDeepLink(serverLink: unknown, p: DeepLinkParts): string {
  if (typeof serverLink !== 'string' || !serverLink.startsWith('v18://verify?')) return buildVerifyDeepLink(p);
  const query = new URLSearchParams(serverLink.slice('v18://verify?'.length));
  if (query.get('session') !== p.sessionId) return buildVerifyDeepLink(p);
  if (query.has('server')) return serverLink;
  return `${serverLink}&server=${encodeURIComponent(p.serverUrl)}`;
}

/**
 * Tries to open a v18:// link without leaving the page. Browsers give no reliable signal that an
 * app opened, so the caller watches for the page losing focus ("blur") as a hint only.
 */
export function openDeepLink(link: string, doc: Document = document): void {
  const a = doc.createElement('a');
  a.href = link;
  a.rel = 'noopener';
  a.style.display = 'none';
  doc.body.appendChild(a);
  a.click();
  a.remove();
}
