import type { RequestHandler } from 'express';
import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

/**
 * Prometheus metrics at GET /metrics (PROTOCOL.md 4c.7). Only anonymous
 * counts: route PATTERNS (never real paths, IDs or origins), status codes,
 * methods. Each server instance has its own registry.
 */
export class Metrics {
  readonly registry = new Registry();
  readonly http: Counter<'method' | 'route' | 'status'>;
  readonly latency: Histogram<'route'>;
  readonly cardsIssued: Counter<'method'>;
  readonly ticketsSigned: Counter;
  readonly nullifierSigns: Counter;
  readonly walletResults: Counter<'result'>;

  constructor(gauges: { name: string; help: string; read: () => Promise<number> }[] = [], defaults = true) {
    if (defaults) collectDefaultMetrics({ register: this.registry, prefix: 'v18_' });
    this.http = new Counter({ name: 'v18_http_requests_total', help: 'HTTP requests', labelNames: ['method', 'route', 'status'], registers: [this.registry] });
    this.latency = new Histogram({
      name: 'v18_http_request_seconds',
      help: 'HTTP request time',
      labelNames: ['route'],
      buckets: [0.005, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
      registers: [this.registry],
    });
    this.cardsIssued = new Counter({ name: 'v18_cards_issued_total', help: 'Age cards issued', labelNames: ['method'], registers: [this.registry] });
    this.ticketsSigned = new Counter({ name: 'v18_tickets_signed_total', help: 'Ticket signatures', registers: [this.registry] });
    this.nullifierSigns = new Counter({ name: 'v18_nullifier_signs_total', help: 'Nullifier blind signatures', registers: [this.registry] });
    this.walletResults = new Counter({ name: 'v18_wallet_results_total', help: 'Wallet verifications', labelNames: ['result'], registers: [this.registry] });
    for (const g of gauges) {
      new Gauge({
        name: g.name,
        help: g.help,
        registers: [this.registry],
        async collect() {
          this.set(await g.read().catch(() => -1));
        },
      });
    }
  }

  /** Counts every request by route pattern once the response is done. */
  middleware(): RequestHandler {
    return (req, res, next) => {
      const end = this.latency.startTimer();
      res.on('finish', () => {
        // Express clears baseUrl once the /v1 router is done, so add it back from the URL.
        const route = req.route?.path ? `${req.originalUrl.startsWith('/v1/') ? '/v1' : ''}${req.route.path}` : 'unmatched';
        this.http.inc({ method: req.method, route, status: String(res.statusCode) });
        end({ route });
      });
      next();
    };
  }

  handler(token: string | null): RequestHandler {
    return async (req, res) => {
      if (token && req.headers.authorization !== `Bearer ${token}`) {
        res.status(401).json({ error: 'Metrics need the bearer token (V18_METRICS_TOKEN)', code: 'UNAUTHORIZED' });
        return;
      }
      res.setHeader('Content-Type', this.registry.contentType);
      res.end(await this.registry.metrics());
    };
  }
}
