import type { ErrorRequestHandler, RequestHandler } from 'express';
import { isWebOrigin } from '../config.js';
import { ApiError, sendError } from '../errors.js';

/**
 * WIDGET endpoints (PROTOCOL.md 4b item 5): the website widget calls these
 * from ANY website, so any web origin may read them. No cookies are used, so
 * Access-Control-Allow-Credentials is never sent.
 */
const WIDGET_ROUTES: { method: string; path: RegExp }[] = [
  { method: 'GET', path: /^\/v1\/health\/?$/i },
  { method: 'GET', path: /^\/v1\/keys\/?$/i },
  { method: 'GET', path: /^\/v1\/keys\/pem\/?$/i },
  { method: 'POST', path: /^\/v1\/pairing\/session\/?$/i },
  { method: 'GET', path: /^\/v1\/pairing\/[^/]+\/?$/i },
  { method: 'POST', path: /^\/v1\/pairing\/[^/]+\/cancel\/?$/i },
  // PROTOCOL.md 4c.1, 4c.2, 4c.5, 4d.2: public data and the wallet steps the widget runs.
  { method: 'GET', path: /^\/v1\/keys\/nullifier\/?$/i },
  { method: 'GET', path: /^\/v1\/artifacts\/[^/]+\/?$/i },
  { method: 'GET', path: /^\/v1\/catalog\/?$/i },
  { method: 'POST', path: /^\/v1\/wallet\/request\/?$/i },
  { method: 'POST', path: /^\/v1\/wallet\/verify\/?$/i },
];

export function isWidgetRoute(method: string, path: string): boolean {
  const m = method === 'HEAD' ? 'GET' : method;
  return WIDGET_ROUTES.some((r) => r.method === m && r.path.test(path));
}

/**
 * CORS in two groups:
 *  - widget endpoints: open to any web origin (the request's origin is echoed);
 *  - everything else (APP endpoints: challenge, card, ticket, link, pairing
 *    connect and submit): only the listed origins (dev demo + V18_CORS_ORIGINS).
 * Apps that are not browsers send no Origin header and are not affected.
 */
export function cors(allowedOrigins: string[]): RequestHandler {
  const allowed = new Set(allowedOrigins);
  return (req, res, next) => {
    res.setHeader('Vary', 'Origin');
    const origin = req.headers.origin;
    const preflight = req.method === 'OPTIONS';
    const method = preflight
      ? String(req.headers['access-control-request-method'] ?? '').toUpperCase()
      : req.method;

    if (typeof origin === 'string') {
      if (allowed.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.setHeader('Access-Control-Max-Age', '600');
      } else if (isWebOrigin(origin) && isWidgetRoute(method, req.path)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Range');
        res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, ETag');
        res.setHeader('Access-Control-Max-Age', '600');
      }
    }
    if (preflight) {
      res.status(204).end();
      return;
    }
    next();
  };
}

/** No caching of API answers unless a route says otherwise. */
export const noStore: RequestHandler = (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
};

export const notFound: RequestHandler = (_req, res) => {
  res.status(404).json({ error: 'Not found. The API lives under /v1.', code: 'NOT_FOUND' });
};

/**
 * Error handler. Privacy rule: it NEVER logs or echoes the request body.
 * (body-parser's JSON error message contains part of the body, so it is
 * replaced by a fixed text.)
 */
export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  if (res.headersSent) return;
  if (err instanceof ApiError) {
    sendError(res, err);
    return;
  }
  const type = (err as { type?: string } | null)?.type;
  if (type === 'entity.parse.failed') {
    sendError(res, new ApiError(400, 'BAD_JSON', 'The request body is not valid JSON'));
    return;
  }
  if (type === 'entity.too.large') {
    sendError(res, new ApiError(413, 'BODY_TOO_LARGE', 'The request body is too large'));
    return;
  }
  if (type === 'encoding.unsupported' || type === 'charset.unsupported') {
    sendError(res, new ApiError(415, 'BAD_ENCODING', 'Send the body as UTF-8 JSON'));
    return;
  }
  // Log where it happened (the route pattern, not the real path) and the stack.
  const where = `${req.method} ${req.route?.path ?? '(no route)'}`;
  console.error(`[v18] internal error at ${where}:`, err instanceof Error ? err.stack : 'non-Error thrown');
  sendError(res, new ApiError(500, 'INTERNAL', 'Something went wrong on the server'));
};
