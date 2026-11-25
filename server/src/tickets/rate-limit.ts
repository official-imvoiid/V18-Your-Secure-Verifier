import { RateLimitRepo, RateResult } from '../db/state.js';
import { ApiError } from '../errors.js';
import { Clock, systemClock } from '../util.js';

/**
 * Sliding-window limit: at most `limit` hits per key in `windowMs`.
 * Kept in the database (shared by all server copies). Keys are card IDs,
 * device key thumbprints or salted IP hashes, never anything about sites.
 */
export class RateLimiter {
  private readonly timer: NodeJS.Timeout;

  constructor(
    private readonly repo: RateLimitRepo,
    /** Namespace, so different limits never share a key. */
    private readonly name: string,
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly clock: Clock = systemClock
  ) {
    this.timer = setInterval(() => {
      this.repo.prune(this.clock()).catch(() => undefined);
    }, 5 * 60_000);
    this.timer.unref();
  }

  /** Counts one hit if allowed. Otherwise says how many seconds to wait. */
  take(key: string): Promise<RateResult> {
    return this.repo.take(`${this.name}:${key}`, this.limit, this.windowMs, this.clock());
  }

  /** Like take, but throws 429 RATE_LIMITED with Retry-After. */
  async takeOrThrow(key: string, message: string): Promise<void> {
    const r = await this.take(key);
    if (!r.ok) {
      throw new ApiError(
        429,
        'RATE_LIMITED',
        message,
        { retryAfterSeconds: r.retryAfterSeconds },
        { 'Retry-After': String(r.retryAfterSeconds) }
      );
    }
  }

  close(): void {
    clearInterval(this.timer);
  }
}
