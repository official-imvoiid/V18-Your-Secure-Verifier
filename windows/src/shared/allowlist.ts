// Server allowlist (PROTOCOL.md 3.10, 4b item 9, 4c.7): apps accept `server=` values only from a
// built-in list, so a link can never point the app at a fake server.
//   Release builds: ONLY the production server URL, which is set at build time
//                   (scripts/build.mjs --release, env V18_PRODUCTION_SERVER; default placeholder
//                   https://api.v18.example until a real domain exists).
//   Debug builds:   http://localhost:8080 (the dev server) plus the production URL.

declare const __V18_PRODUCTION_SERVER__: string | undefined;

export const PLACEHOLDER_PRODUCTION_SERVER = 'https://api.v18.example';
/** The production server origin this build was made for. */
export const PRODUCTION_SERVER: string =
  typeof __V18_PRODUCTION_SERVER__ === 'string' && __V18_PRODUCTION_SERVER__ ? __V18_PRODUCTION_SERVER__ : PLACEHOLDER_PRODUCTION_SERVER;

export const DEBUG_SERVER_ORIGINS = ['http://localhost:8080'] as const;
export const API_PATH = '/v1';

export function allowedServerOrigins(debug: boolean): string[] {
  return debug ? [...DEBUG_SERVER_ORIGINS, PRODUCTION_SERVER] : [PRODUCTION_SERVER];
}

/**
 * Turn a `server=` value into the API base URL we will call, or null if it is not allowed.
 * Accepted shapes: "<origin>", "<origin>/", "<origin>/v1", "<origin>/v1/".
 * The result is always "<origin>/v1".
 * `extraOrigins` exists for automated tests only (a mock server on a random port); the app never passes it.
 */
export function normalizeServer(raw: unknown, debug: boolean, extraOrigins: readonly string[] = []): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 200) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.username || url.password || url.search || url.hash) return null;
  const path = url.pathname.replace(/\/+$/, '');
  if (path !== '' && path !== API_PATH) return null;
  if (!allowedServerOrigins(debug).includes(url.origin) && !extraOrigins.includes(url.origin)) return null;
  return url.origin + API_PATH;
}

export function defaultServer(debug: boolean): string {
  return (debug ? DEBUG_SERVER_ORIGINS[0] : PRODUCTION_SERVER) + API_PATH;
}
