// v18:// deep links (PROTOCOL.md 3.8 and 3.9).
//   v18://verify?session=<id>&origin=<urlenc>&challenge=<urlenc>&minAge=18&server=<urlenc base URL>
//   v18://link?id=<linkId>&server=<urlenc>
//   v18://connect?status=ok&cardId=...[&state=...]   (4d.4: the server sends the browser back here
//                                                     after a government or bank login)
// The PC app receives "verify" links from the browser. It makes "link" links (for the phone to
// scan) but never acts on one itself. A "connect" link only wakes up a login the app itself
// started: the app then asks the server, because any web page could open a fake connect link.

import { normalizeServer } from './allowlist.js';
import { parseWebOrigin } from './origin.js';

export type DeepLink =
  | { kind: 'verify'; sessionId: string; origin: string; challenge: string; minAge: number; server: string; serverGiven: boolean }
  | { kind: 'link'; linkId: string; server: string }
  | { kind: 'connect'; status: string; cardId: string | null; state: string | null };

export class DeepLinkError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'DeepLinkError';
  }
}

const ID_RE = /^[A-Za-z0-9_-]{16,128}$/;
const CHALLENGE_RE = /^[\x21-\x7E]{8,512}$/; // printable ASCII, no spaces
const MAX_LINK_LENGTH = 4096;

function single(params: URLSearchParams, name: string): string | null {
  const all = params.getAll(name);
  if (all.length > 1) throw new DeepLinkError('DUPLICATE_PARAM', `"${name}" appears more than once`);
  return all.length === 1 ? all[0] : null;
}

/** Find the first v18:// URL in a command line (Windows passes it as a plain argument). */
export function findDeepLinkArg(argv: readonly string[]): string | null {
  for (const arg of argv) {
    if (typeof arg === 'string' && arg.toLowerCase().startsWith('v18:')) return arg;
  }
  return null;
}

export interface ParseOptions {
  debug: boolean;
  /** Used when a verify link has no server= (the current server does not add it yet). */
  defaultServer: string;
  /** Tests only. */
  extraServerOrigins?: readonly string[];
}

export function parseDeepLink(raw: string, opts: ParseOptions): DeepLink {
  if (typeof raw !== 'string' || raw.length > MAX_LINK_LENGTH) {
    throw new DeepLinkError('BAD_LINK', 'link is missing or too long');
  }
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new DeepLinkError('BAD_LINK', 'not a URL');
  }
  if (url.protocol !== 'v18:') throw new DeepLinkError('BAD_LINK', 'not a v18:// link');
  if (url.username || url.password || url.port || url.hash) throw new DeepLinkError('BAD_LINK', 'unexpected parts in link');
  // Windows and some browsers add a "/" after the host, so "v18://verify/?..." is accepted too.
  if (url.pathname !== '' && url.pathname !== '/') throw new DeepLinkError('BAD_LINK', 'unexpected path in link');
  const action = url.hostname.toLowerCase();
  const params = url.searchParams;

  const serverRaw = single(params, 'server');
  let server: string | null = null;
  if (serverRaw !== null) {
    server = normalizeServer(serverRaw, opts.debug, opts.extraServerOrigins);
    if (!server) throw new DeepLinkError('SERVER_NOT_ALLOWED', 'this link points to a server V18 does not trust');
  }

  if (action === 'verify') {
    const sessionId = single(params, 'session');
    if (!sessionId || !ID_RE.test(sessionId)) throw new DeepLinkError('BAD_SESSION', 'bad or missing session');
    const origin = parseWebOrigin(single(params, 'origin'));
    if (!origin) throw new DeepLinkError('BAD_ORIGIN', 'bad or missing website origin');
    const challenge = single(params, 'challenge');
    if (!challenge || !CHALLENGE_RE.test(challenge)) throw new DeepLinkError('BAD_CHALLENGE', 'bad or missing challenge');
    const minAgeRaw = single(params, 'minAge') ?? '18';
    if (!/^\d{1,2}$/.test(minAgeRaw)) throw new DeepLinkError('BAD_MIN_AGE', 'bad minAge');
    const minAge = Number(minAgeRaw);
    if (minAge < 1 || minAge > 99) throw new DeepLinkError('BAD_MIN_AGE', 'bad minAge');
    return { kind: 'verify', sessionId, origin, challenge, minAge, server: server ?? opts.defaultServer, serverGiven: server !== null };
  }

  if (action === 'link') {
    const linkId = single(params, 'id');
    if (!linkId || !ID_RE.test(linkId)) throw new DeepLinkError('BAD_LINK_ID', 'bad or missing link id');
    if (!server) throw new DeepLinkError('SERVER_NOT_ALLOWED', 'link has no server');
    return { kind: 'link', linkId, server };
  }

  if (action === 'connect') {
    const status = single(params, 'status') ?? '';
    if (!/^[a-z_]{1,32}$/.test(status)) throw new DeepLinkError('BAD_STATUS', 'bad or missing status');
    const cardId = single(params, 'cardId');
    if (cardId !== null && !/^card[_-][A-Za-z0-9_-]{8,64}$/.test(cardId)) throw new DeepLinkError('BAD_CARD_ID', 'bad card id');
    const state = single(params, 'state');
    if (state !== null && !/^[A-Za-z0-9._~-]{8,512}$/.test(state)) throw new DeepLinkError('BAD_STATE', 'bad state');
    return { kind: 'connect', status, cardId, state };
  }

  throw new DeepLinkError('UNKNOWN_ACTION', `unknown link action "${action}"`);
}
