/**
 * V18 demo website ("Reserve Cellar"), an example 18+ site.
 *
 * What a real website does, all here on the site's own server:
 *   POST /v18/challenge  a fresh challenge for this visit (ChallengeStore from @v18/verify)
 *   POST /v18/verify     checks the ticket with @v18/verify (all PROTOCOL.md 3.7 rules), then
 *                        marks this visit as 18+ in a server-side session (cookie = random visit ID)
 *
 * Two modes:
 *   dev (default)   developer tools: the browser test wallet (/dev/test-wallet.js), the crypto
 *                   inspector and the replay-attack demo. They show only if V18 is in dev mode.
 *   production      DEMO_MODE=production plus V18_SERVER and SITE_ORIGIN. No developer tools at
 *                   all, and the page loads the versioned release widget with its SRI hash.
 */
import express, { NextFunction, Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ChallengeStore, V18Verifier, VerifyResult } from '@v18/verify';

const escapeAttr = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export type DemoMode = 'dev' | 'production';

export interface DemoConfig {
  port: number;
  /** This site's web origin, exactly as the browser sees it. */
  siteOrigin: string;
  /** V18 server base URL (without /v1). */
  v18ServerUrl: string;
  /** "dev" (default) or "production" (no test wallet, no replay demo, release widget with SRI). */
  mode?: DemoMode;
  /** How long an 18+ session lasts. Default 1 hour. */
  sessionSeconds?: number;
  /** For tests. */
  verifier?: V18Verifier;
  /** Secure cookies. Default: on when siteOrigin is https. */
  secureCookies?: boolean;
  /** Trust X-Forwarded-For from one proxy in front (a load balancer or TLS proxy). */
  trustProxy?: boolean;
  /** Where the release widget lives (v18-<version>.min.js). Default sdk-web/release. */
  releaseDir?: string;
}

interface VisitSession {
  verifiedUntil?: number;
  minAge?: number;
  /** Dev mode only: kept for the replay-attack demo. Tickets are anonymous one-time tokens. */
  lastTicket?: string;
}

const VISIT_COOKIE = 'v18_demo_visit';
const ROOT = path.resolve(__dirname, '..');
const PUBLIC = path.join(ROOT, 'public');
const WIDGET_DIST = path.resolve(ROOT, '..', 'widget', 'dist');
const DEFAULT_RELEASE = path.resolve(ROOT, '..', 'release');
const CLIENT_DIST = path.join(ROOT, 'dist', 'public');
const WIDGET_VERSION: string = JSON.parse(fs.readFileSync(path.resolve(ROOT, '..', 'widget', 'package.json'), 'utf8')).version;

/** Subresource Integrity value for a file: "sha384-<base64>". */
export function sriOf(file: string): string {
  return `sha384-${crypto.createHash('sha384').update(fs.readFileSync(file)).digest('base64')}`;
}

/** Removes <!--DEV-->...<!--/DEV--> blocks (production) or just the markers (dev). */
export function applyMode(html: string, mode: DemoMode): string {
  return mode === 'production'
    ? html.replace(/<!--DEV-->[\s\S]*?<!--\/DEV-->/g, '')
    : html.replace(/<!--\/?DEV-->/g, '');
}

export function createDemoApp(cfg: DemoConfig) {
  const mode: DemoMode = cfg.mode ?? 'dev';
  const dev = mode === 'dev';
  const app = express();
  app.disable('x-powered-by');
  if (cfg.trustProxy) app.set('trust proxy', 1);
  const sessionMs = (cfg.sessionSeconds ?? 3600) * 1000;
  const secureCookies = cfg.secureCookies ?? cfg.siteOrigin.startsWith('https://');
  const verifier = cfg.verifier ?? new V18Verifier({ serverUrl: cfg.v18ServerUrl, origin: cfg.siteOrigin, minAge: 18 });
  const challenges = new ChallengeStore();
  const sessions = new Map<string, VisitSession>();
  const v18Origin = new URL(cfg.v18ServerUrl).origin;

  // The widget file and its SRI hash. Production: the versioned release build, checked at start.
  const releaseDir = cfg.releaseDir ?? DEFAULT_RELEASE;
  const widgetName = dev ? 'v18.js' : `v18-${WIDGET_VERSION}.min.js`;
  const widgetFile = path.join(dev ? WIDGET_DIST : releaseDir, widgetName);
  if (!dev && !fs.existsSync(widgetFile)) {
    throw new Error(`Production mode needs the release widget ${widgetFile}. Build it with: npm run release --prefix sdk-web`);
  }
  let widgetSri = { mtime: -1, value: '' };
  const currentSri = () => {
    const mtime = fs.statSync(widgetFile).mtimeMs;
    if (mtime !== widgetSri.mtime) widgetSri = { mtime, value: sriOf(widgetFile) };
    return widgetSri.value;
  };

  // Security headers. Inline scripts need this request's nonce; the widget's styles are inline.
  app.use((_req, res, next) => {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce;
    res.set({
      'Content-Security-Policy': [
        "default-src 'self'",
        `script-src 'self' 'nonce-${nonce}'`,
        "style-src 'self' 'unsafe-inline'",
        `connect-src 'self' ${v18Origin}`,
        "img-src 'self' data:",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "object-src 'none'",
      ].join('; '),
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Opener-Policy': 'same-origin',
      ...(secureCookies ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}),
    });
    next();
  });

  app.use(express.json({ limit: '16kb' }));
  app.use(cookieParser());

  // Every visit gets a random ID in an HttpOnly cookie. The 18+ state lives on this server.
  app.use((req, res, next) => {
    let id: string | undefined = req.cookies?.[VISIT_COOKIE];
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(id)) {
      id = ChallengeStore.newVisitId();
      res.cookie(VISIT_COOKIE, id, { httpOnly: true, sameSite: 'lax', secure: secureCookies, path: '/' });
    }
    (req as any).visitId = id;
    next();
  });

  const visit = (req: Request): string => (req as any).visitId;
  const session = (req: Request): VisitSession => {
    let s = sessions.get(visit(req));
    if (!s) sessions.set(visit(req), (s = {}));
    return s;
  };
  const isVerified = (req: Request): boolean => {
    const s = sessions.get(visit(req));
    return !!s?.verifiedUntil && s.verifiedUntil > Date.now();
  };
  // Forget finished visits now and then, so memory stays small.
  const pruner = setInterval(() => {
    const now = Date.now();
    for (const [id, s] of sessions) if (!s.verifiedUntil || s.verifiedUntil < now) sessions.delete(id);
  }, 10 * 60_000);
  pruner.unref();

  // Refuse cross-site POSTs (the browser always sends Origin on POST from a page).
  const sameOrigin = (req: Request, res: Response, next: NextFunction) => {
    const o = req.get('origin');
    if (o && o !== cfg.siteOrigin) {
      res.status(403).json({ ok: false, error: `Requests must come from ${cfg.siteOrigin}`, code: 'BAD_ORIGIN' });
      return;
    }
    next();
  };

  // ---------------------------------------------------------------- the two routes every site needs

  app.post('/v18/challenge', sameOrigin, (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json(challenges.create(visit(req)));
  });

  async function checkTicket(req: Request, ticket: unknown): Promise<VerifyResult> {
    return verifier.verifyTicket(ticket, { expectedChallenge: challenges.checker(visit(req)), minAge: 18 });
  }

  app.post('/v18/verify', sameOrigin, async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const ticket = req.body?.ticket;
    const result = await checkTicket(req, ticket);
    if (!result.valid) {
      const status = result.code === 'KEYS_UNAVAILABLE' ? 503 : result.code === 'CONFIG_ERROR' ? 500 : 403;
      res.status(status).json({ ok: false, error: result.error, code: result.code });
      return;
    }
    const s = session(req);
    s.verifiedUntil = Date.now() + sessionMs;
    s.minAge = result.ticket.minAge;
    if (dev) s.lastTicket = ticket;
    res.json({
      ok: true,
      minAge: result.ticket.minAge,
      keyId: result.ticket.keyId,
      sessionUntil: new Date(s.verifiedUntil).toISOString(),
    });
  });

  app.post('/api/lock', sameOrigin, (req, res) => {
    sessions.delete(visit(req));
    challenges.clear(visit(req));
    res.json({ ok: true });
  });

  app.get('/healthz', (_req, res) => res.json({ ok: true, mode }));

  // ---------------------------------------------------------------- dev-only tools

  if (dev) {
    app.get('/api/status', async (req, res) => {
      res.set('Cache-Control', 'no-store');
      let v18: any = { reachable: false };
      try {
        const r = await fetch(`${cfg.v18ServerUrl}/v1/health`, { signal: AbortSignal.timeout(2000) });
        const h: any = await r.json();
        v18 = { reachable: r.ok, devMode: h?.devMode === true, version: h?.version, wallet: h?.methods?.mdoc_wallet ?? null };
      } catch {
        /* unreachable */
      }
      const s = sessions.get(visit(req));
      res.json({
        mode,
        verified: isVerified(req),
        sessionUntil: s?.verifiedUntil ? new Date(s.verifiedUntil).toISOString() : null,
        minAge: s?.minAge ?? null,
        hasLastTicket: !!s?.lastTicket,
        siteOrigin: cfg.siteOrigin,
        v18ServerUrl: cfg.v18ServerUrl,
        v18,
      });
    });

    /**
     * Replay-attack demo. Takes this visit's last accepted ticket and attacks with it three ways.
     * It never unlocks anything.
     */
    app.post('/api/demo/replay', sameOrigin, async (req, res) => {
      const ticket = sessions.get(visit(req))?.lastTicket;
      if (!ticket) {
        res.status(400).json({ ok: false, error: 'No ticket has been accepted on this visit yet', code: 'NO_TICKET' });
        return;
      }
      const show = (r: VerifyResult) => (r.valid ? { valid: true } : { valid: false, code: r.code, error: r.error });

      // 1. Exactly what an attacker can do: send the same ticket to /v18/verify again.
      const sameRoute = await checkTicket(req, ticket);

      // 2. Skip the challenge check (read the challenge out of the ticket without trusting it) so
      //    you can see the replay cache stop the ticket by itself.
      let ticketChallenge = '';
      try {
        const prepared = Buffer.from(ticket.split('.')[1], 'base64url');
        ticketChallenge = JSON.parse(prepared.subarray(32).toString('utf8')).challenge;
      } catch {
        /* stays empty */
      }
      const replayOnly = await verifier.verifyTicket(ticket, { expectedChallenge: ticketChallenge || 'none', minAge: 18 });

      // 3. A forged copy: one byte of the seal changed.
      const [kid, prep, sig] = ticket.split('.');
      const sigBytes = Buffer.from(sig, 'base64url');
      sigBytes[sigBytes.length - 1] ^= 0x01;
      const forged = await verifier.verifyTicket(`${kid}.${prep}.${sigBytes.toString('base64url')}`, {
        expectedChallenge: ticketChallenge || 'none',
        minAge: 18,
      });

      res.json({
        ok: true,
        attacks: [
          { name: 'Send the same ticket to /v18/verify again', result: show(sameRoute) },
          { name: 'Same ticket, challenge check skipped: only the replay cache is left', result: show(replayOnly) },
          { name: 'Forged copy: one byte of the V18 seal changed', result: show(forged) },
        ],
        unlockedAnything: false,
      });
    });

    app.use('/dev', express.static(CLIENT_DIST, { maxAge: 0 }));
  }

  // ---------------------------------------------------------------- pages and scripts

  app.get(`/widget/${widgetName}`, (_req, res) => {
    res.set('Cache-Control', dev ? 'no-cache' : 'public, max-age=31536000, immutable');
    res.type('application/javascript').sendFile(widgetFile);
  });

  const sendPage = (res: Response, file: string) => {
    const html = applyMode(fs.readFileSync(path.join(PUBLIC, file), 'utf8'), mode)
      .replace(/\{\{V18_SERVER_URL\}\}/g, escapeAttr(cfg.v18ServerUrl))
      .replace(/\{\{SITE_ORIGIN\}\}/g, escapeAttr(cfg.siteOrigin))
      .replace(/\{\{WIDGET_SRC\}\}/g, `/widget/${widgetName}`)
      .replace(/\{\{WIDGET_INTEGRITY\}\}/g, currentSri())
      .replace(/\{\{NONCE\}\}/g, res.locals.nonce);
    res.set('Cache-Control', 'no-store').type('html').send(html);
  };

  app.get('/', (req, res) => {
    if (isVerified(req)) {
      res.redirect('/adult-content');
      return;
    }
    sendPage(res, 'index.html');
  });

  app.get('/adult-content', (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (!isVerified(req)) {
      res.redirect('/');
      return;
    }
    sendPage(res, 'adult-content.html');
  });

  // The pages above are templates, so only the stylesheet is served as a plain file.
  app.get('/site.css', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=300').type('css').sendFile(path.join(PUBLIC, 'site.css'));
  });

  // Quiet JSON errors: no stack traces and no request bodies in the logs (PROTOCOL.md 2: privacy).
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = Number.isInteger(err?.status) && err.status >= 400 && err.status < 600 ? err.status : 500;
    if (status >= 500) console.error(`[demo-site] ${err?.name ?? 'Error'}: ${err?.message ?? err}`);
    res.status(status).json({
      ok: false,
      error: status === 413 ? 'Request too large' : status < 500 ? 'Bad request' : 'Server error',
      code: status === 413 ? 'TOO_LARGE' : status < 500 ? 'BAD_REQUEST' : 'SERVER_ERROR',
    });
  });

  return app;
}

const cleanServerUrl = (u: string) => u.trim().replace(/\/+$/, '').replace(/\/v1$/, '');

/**
 * Reads the settings from environment variables:
 *   DEMO_MODE      "dev" (default) or "production"
 *   V18_SERVER     V18 server base URL. Required in production. Dev default http://localhost:8080
 *                  (V18_SERVER_URL is the older name and still works)
 *   SITE_ORIGIN    this site's origin as visitors see it. Required in production.
 *   DEMO_PORT      port (default 3000). PORT works too.
 *   TRUST_PROXY=1  behind a TLS proxy or load balancer
 */
export function configFromEnv(env: NodeJS.ProcessEnv = process.env): DemoConfig {
  const mode: DemoMode = (env.DEMO_MODE ?? '').toLowerCase() === 'production' ? 'production' : 'dev';
  const port = parseInt(env.DEMO_PORT || env.PORT || '3000', 10);
  const server = env.V18_SERVER || env.V18_SERVER_URL;
  if (mode === 'production') {
    if (!server) throw new Error('DEMO_MODE=production needs V18_SERVER (for example https://api.v18.example)');
    if (!env.SITE_ORIGIN) throw new Error('DEMO_MODE=production needs SITE_ORIGIN (for example https://shop.example)');
    const u = new URL(server);
    const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    if (u.protocol !== 'https:' && !local) throw new Error('V18_SERVER must use https:// in production');
  }
  return {
    port,
    mode,
    siteOrigin: env.SITE_ORIGIN || `http://localhost:${port}`,
    v18ServerUrl: cleanServerUrl(server || 'http://localhost:8080'),
    trustProxy: env.TRUST_PROXY === '1',
  };
}

if (require.main === module) {
  let cfg: DemoConfig;
  try {
    // `npm run start:prod` passes --production (the same as DEMO_MODE=production).
    cfg = configFromEnv(process.argv.includes('--production') ? { ...process.env, DEMO_MODE: 'production' } : process.env);
  } catch (e: any) {
    console.error(`[demo-site] ${e.message}`);
    process.exit(1);
  }
  createDemoApp(cfg).listen(cfg.port, () => {
    console.log('====================================================');
    console.log('  V18 demo site (Reserve Cellar, an example 18+ site)');
    console.log(`  Mode:        ${cfg.mode === 'production' ? 'production (no developer tools)' : 'dev (developer tools on)'}`);
    console.log(`  Open:        ${cfg.siteOrigin}`);
    console.log(`  V18 server:  ${cfg.v18ServerUrl}`);
    console.log('  Tickets are checked on THIS server with @v18/verify');
    console.log('====================================================');
  });
}
