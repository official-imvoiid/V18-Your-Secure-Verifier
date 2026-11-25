// Web origins (PROTOCOL.md 3.6: "origin is the website's web origin (scheme://host[:port])").

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Accepts only a bare origin: https://host[:port], or http:// for this PC's own loopback address
 * (the demo site runs on http://localhost:3000). No path, query, fragment or user name.
 * Returns the origin in its normal form (lower-case, IDN hosts as punycode so look-alike
 * letters are visible), or null.
 */
export function parseWebOrigin(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 300) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password || url.search || url.hash) return null;
  if (url.pathname !== '/' && url.pathname !== '') return null;
  // The raw text must already be a bare origin (no trailing slash or path tricks).
  if (raw.replace(/\/$/, '').toLowerCase() !== url.origin.toLowerCase()) return null;
  if (url.protocol === 'http:' && !LOOPBACK.has(url.hostname)) return null;
  if (!url.hostname || url.hostname.endsWith('.')) return null;
  return url.origin;
}

/** What we show the user: the host, plus the port if it isn't the default, plus "http" warnings. */
export function displayOrigin(origin: string): string {
  const url = new URL(origin);
  return url.protocol === 'http:' ? `${url.host} (not secure: http)` : url.host;
}
