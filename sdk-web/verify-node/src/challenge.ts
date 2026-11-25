import * as crypto from 'node:crypto';

export interface IssuedChallenge {
  /** 64 hex characters (32 random bytes). Put this in the widget: data-v18-challenge or a JSON reply. */
  challenge: string;
  /** When it stops working, as an ISO date string. */
  expiresAt: string;
}

export interface ChallengeStoreOptions {
  /** How long a challenge works. Default 300 seconds (5 minutes), the same as V18's own challenges. */
  ttlSeconds?: number;
  /** How many open challenges one visit may hold (for example two open tabs). Default 5. */
  maxPerVisit?: number;
  /** Safety cap on how many visits are tracked. The oldest are dropped first. Default 100000. */
  maxVisits?: number;
  /** For tests. Returns epoch milliseconds. */
  clock?: () => number;
}

/**
 * Makes and remembers a fresh challenge for each visit to your website (PROTOCOL.md 3.7 rule 5).
 *
 * A "visit" is whatever ID you already keep for the browser, such as a session cookie.
 * `newVisitId()` makes one if you have nothing yet.
 *
 *   const challenges = new ChallengeStore();
 *   // When the page (or widget) asks:   challenges.create(visitId)
 *   // When a ticket comes back:          verifier.verifyTicket(ticket, { expectedChallenge: challenges.checker(visitId) })
 *
 * Each challenge works once: `take` removes it. This store keeps everything in memory, so it fits
 * a single server process. For several servers, keep challenges in your shared session store.
 */
export class ChallengeStore {
  private visits = new Map<string, Map<string, number>>();
  private lastPruneMs = 0;
  private readonly ttlMs: number;
  private readonly maxPerVisit: number;
  private readonly maxVisits: number;
  private readonly clock: () => number;

  constructor(options: ChallengeStoreOptions = {}) {
    this.ttlMs = (options.ttlSeconds ?? 300) * 1000;
    this.maxPerVisit = options.maxPerVisit ?? 5;
    this.maxVisits = options.maxVisits ?? 100_000;
    this.clock = options.clock ?? Date.now;
  }

  /** A new random visit ID (32 bytes, base64url) for a cookie. */
  public static newVisitId(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  /** Makes a new challenge for this visit and remembers it. */
  public create(visitId: string): IssuedChallenge {
    if (typeof visitId !== 'string' || visitId.length === 0) {
      throw new TypeError('[V18] ChallengeStore.create needs a visit ID');
    }
    const nowMs = this.clock();
    this.maybePrune(nowMs);

    const challenge = crypto.randomBytes(32).toString('hex');
    const expiresAtMs = nowMs + this.ttlMs;

    let open = this.visits.get(visitId);
    if (!open) {
      open = new Map();
    } else {
      this.visits.delete(visitId); // re-insert below so this visit counts as the newest
      for (const [c, exp] of open) if (exp <= nowMs) open.delete(c);
    }
    open.set(challenge, expiresAtMs);
    while (open.size > this.maxPerVisit) open.delete(open.keys().next().value!);
    this.visits.set(visitId, open);
    while (this.visits.size > this.maxVisits) this.visits.delete(this.visits.keys().next().value!);

    return { challenge, expiresAt: new Date(expiresAtMs).toISOString() };
  }

  /**
   * Single use: returns true and forgets the challenge if this visit was given it and it has not
   * expired. Returns false otherwise.
   */
  public take(visitId: string, challenge: string): boolean {
    const open = this.visits.get(visitId);
    if (!open || typeof challenge !== 'string') return false;
    const exp = open.get(challenge);
    if (exp === undefined) return false;
    open.delete(challenge);
    if (open.size === 0) this.visits.delete(visitId);
    return exp > this.clock();
  }

  /** A function to pass as `expectedChallenge` to `verifyTicket`. It takes (uses up) the challenge. */
  public checker(visitId: string): (challenge: string) => boolean {
    return (challenge: string) => this.take(visitId, challenge);
  }

  /** Forgets every open challenge for this visit. */
  public clear(visitId: string): void {
    this.visits.delete(visitId);
  }

  /** How many open challenges this visit holds (for tests and dashboards). */
  public openCount(visitId: string): number {
    const open = this.visits.get(visitId);
    if (!open) return 0;
    const now = this.clock();
    let n = 0;
    for (const exp of open.values()) if (exp > now) n++;
    return n;
  }

  private maybePrune(nowMs: number): void {
    if (nowMs - this.lastPruneMs < 60_000) return;
    this.lastPruneMs = nowMs;
    for (const [visitId, open] of this.visits) {
      for (const [c, exp] of open) if (exp <= nowMs) open.delete(c);
      if (open.size === 0) this.visits.delete(visitId);
    }
  }
}
