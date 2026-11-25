import { Request, Response, Router } from 'express';
import type { V18Services } from '../app.js';
import { contentTypeFor } from '../artifacts/service.js';
import { ApiError, route } from '../errors.js';
import { NULLIFIER_KEY_ID } from '../nullifier/service.js';

export const SERVER_VERSION = '0.3.0';

/**
 * All `/v1` endpoints. See docs/server/API.md for every request, response
 * and error. Handlers stay thin: the services do the checks.
 */
export function createRouter(s: V18Services): Router {
  const r = Router();

  // ---- Health and keys ------------------------------------------------------

  r.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: 'v18-server',
      version: SERVER_VERSION,
      protocolVersion: 1,
      contractVersion: '1.3',
      devMode: s.config.devMode,
      time: new Date(s.clock()).toISOString(),
      methods: s.methodStatus(),
      connectors: s.connect.enabled().map((c) => c.id),
      ageThresholds: [...s.config.ageThresholds].sort((a, b) => a - b),
      aadhaarNullifierSeed: s.config.aadhaarNullifierSeed,
      nullifierKeyId: NULLIFIER_KEY_ID,
      artifacts: s.artifacts.complete ? 'ready' : 'missing',
      catalog: s.catalog.status(),
      storage: s.db.dialect,
    });
  });

  r.get(
    '/keys',
    route(async (_req, res) => {
      await s.keys.refresh();
      res.setHeader('Cache-Control', 'public, max-age=300');
      res.json(s.keys.jwks());
    })
  );

  r.get(
    '/keys/pem',
    route(async (req, res) => {
      await s.keys.refresh();
      const kid = typeof req.query.kid === 'string' && req.query.kid.length > 0 ? req.query.kid : undefined;
      const pem = s.keys.pem(kid);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.send(pem);
    })
  );

  // 4c.2: the long-lived nullifier key.
  r.get('/keys/nullifier', (_req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.json(s.nullifierKey.jwks());
  });

  // ---- Artifacts (4c.1) --------------------------------------------------------

  r.get('/artifacts/manifest', (_req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.json(s.artifacts.list());
  });

  r.get('/artifacts/:name', (req, res, next) => {
    const found = s.artifacts.lookup(String(req.params.name));
    if ('error' in found) {
      next(
        found.error === 'unknown'
          ? new ApiError(404, 'ARTIFACT_NOT_FOUND', 'No such artifact. See GET /v1/artifacts/manifest.')
          : new ApiError(503, 'ARTIFACT_NOT_READY', 'This file is not on the server yet (or is still being checked). Try again later.')
      );
      return;
    }
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.setHeader('ETag', `"${found.entry.sha256}"`);
    res.setHeader('X-Content-SHA256', found.entry.sha256!);
    res.type(contentTypeFor(found.entry.name));
    // sendFile handles Range (206) so apps can resume the 612 MB zkey.
    res.sendFile(found.file, { acceptRanges: true, etag: false, lastModified: false, dotfiles: 'deny' }, (err) => {
      if (err && !res.headersSent) next(err);
    });
  });

  // ---- Country catalog (4d.2) ------------------------------------------------------

  r.get('/catalog', route((req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.json(s.catalog.get({ country: req.query.country, platform: req.query.platform }));
  }));

  // ---- Challenges -----------------------------------------------------------

  r.post('/challenge', route(async (_req, res) => {
    res.json(await s.challenges.createChallenge());
  }));

  // ---- Nullifier service (4c.2) ------------------------------------------------------

  r.post('/nullifier/blind-sign', route(async (req, res) => {
    const out = await s.nullifierSign.blindSign(req.body, req.ip);
    s.metrics.nullifierSigns.inc();
    res.json(out);
  }));

  // ---- Age cards ------------------------------------------------------------

  r.post('/card/issue', route(async (req, res) => {
    res.status(201).json(await s.cards.issue(req.body));
  }));

  // Device link (protocol 3.9). Declared before /card/:cardId routes.
  r.post('/card/link/start', route(async (req, res) => {
    res.status(201).json(await s.links.start(req.body));
  }));

  r.post('/card/link/:linkId/approve', route(async (req, res) => {
    res.json(await s.links.approve(String(req.params.linkId), req.body));
  }));

  r.get('/card/link/:linkId', route(async (req, res) => {
    res.json(await s.links.poll(String(req.params.linkId)));
  }));

  r.get('/card/:cardId/status', route(async (req, res) => {
    res.json(await s.cards.status(String(req.params.cardId)));
  }));

  r.delete('/card/:cardId', route(async (req, res) => {
    res.json(await s.cards.revoke(String(req.params.cardId), req.body));
  }));

  // ---- Tickets --------------------------------------------------------------

  r.post('/ticket/blind-sign', route(async (req, res) => {
    res.json(await s.tickets.blindSign(req.body));
  }));

  // ---- QR hand-off (pairing) -------------------------------------------------

  r.post('/pairing/session', route(async (req, res) => {
    res.status(201).json(await s.pairing.create(req.body, req.headers.origin, req.ip));
  }));

  r.get('/pairing/:sessionId', route(async (req, res) => {
    res.json(await s.pairing.poll(String(req.params.sessionId)));
  }));

  r.post('/pairing/:sessionId/connect', route(async (req, res) => {
    res.json(await s.pairing.connect(String(req.params.sessionId)));
  }));

  r.post('/pairing/:sessionId/submit', route(async (req, res) => {
    res.json(await s.pairing.submit(String(req.params.sessionId), req.body));
  }));

  r.post('/pairing/:sessionId/cancel', route(async (req, res) => {
    res.json(await s.pairing.cancel(String(req.params.sessionId)));
  }));

  // ---- Phone wallets (4c.5, 4d.3) ------------------------------------------------------

  r.post('/wallet/request', route(async (req, res) => {
    res.json(await s.wallet.request(req.body, req.headers.origin, req.ip));
  }));

  r.post('/wallet/verify', route(async (req, res) => {
    res.json(await s.wallet.verify(req.body, req.headers.origin, req.ip));
  }));

  r.post('/wallet/app-request', route(async (req, res) => {
    res.json(await s.wallet.appRequest(req.body, req.ip));
  }));

  // ---- Login connectors (4d.4) -------------------------------------------------------

  r.get('/connect/session/:state', route(async (req, res) => {
    res.json(await s.connect.poll(String(req.params.state)));
  }));

  r.get('/connect/session/:state/qr', route(async (req, res) => {
    res.json(await s.connect.bankIdQr(String(req.params.state)));
  }));

  // Fetched by the providers themselves (connectors README, "For the server").
  r.get('/connect/:id/jwks', route(async (req, res) => {
    const out = await s.connect.jwks(String(req.params.id));
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.json(out);
  }));

  r.get('/connect/:id/metadata', route(async (req, res) => {
    const xml = await s.connect.metadata(String(req.params.id));
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.type('application/samlmetadata+xml').send(xml);
  }));

  r.get('/connect/:id/identity-providers', route((req, res) => {
    res.json(s.connect.identityProviders(String(req.params.id)));
  }));

  r.post('/connect/:id/start', route(async (req, res) => {
    res.status(201).json(await s.connect.start(String(req.params.id), req.body, req.ip));
  }));

  const callback = route(async (req, res) => {
    // Query (GET) or form fields (POST, SAML). Strings only; nothing is logged.
    const source = req.method === 'POST' && req.body && typeof req.body === 'object' ? req.body : req.query;
    const params: Record<string, string> = {};
    for (const [k, v] of Object.entries(source as Record<string, unknown>)) if (typeof v === 'string') params[k] = v;
    const target = await s.connect.callback(String(req.params.id), params);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(302).setHeader('Location', target);
    const safe = target.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    res.end(`<!doctype html><meta charset="utf-8"><title>V18</title><p>Back to the V18 app: <a href="${safe}">open V18</a></p>`);
  });
  r.get('/connect/:id/callback', callback);
  r.post('/connect/:id/callback', callback);

  return r;
}
