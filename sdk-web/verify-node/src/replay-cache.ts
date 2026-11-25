/**
 * Remembers ticket IDs that were already accepted, so a ticket works only once (PROTOCOL.md 3.7 rule 8).
 *
 * The default `MemoryReplayCache` lives in this process's memory. If your website runs on more than
 * one server, give every server the same shared store (for example Redis with SET NX + EXPIRE) by
 * implementing this interface.
 */
export interface ReplayStore {
  /**
   * Atomically: if `ticketId` was seen before, return false. Otherwise remember it until
   * `rememberUntilEpochSeconds` and return true.
   */
  checkAndRemember(ticketId: string, rememberUntilEpochSeconds: number): boolean | Promise<boolean>;
}

export class MemoryReplayCache implements ReplayStore {
  private seen = new Map<string, number>();
  private lastPruneMs = 0;
  private readonly clock: () => number;

  constructor(options: { clock?: () => number } = {}) {
    this.clock = options.clock ?? Date.now;
  }

  public checkAndRemember(ticketId: string, rememberUntilEpochSeconds: number): boolean {
    const nowMs = this.clock();
    this.maybePrune(nowMs);
    const until = this.seen.get(ticketId);
    if (until !== undefined && until * 1000 >= nowMs) return false;
    this.seen.set(ticketId, rememberUntilEpochSeconds);
    return true;
  }

  public has(ticketId: string): boolean {
    return this.seen.has(ticketId);
  }

  public get size(): number {
    return this.seen.size;
  }

  public clear(): void {
    this.seen.clear();
  }

  private maybePrune(nowMs: number): void {
    if (nowMs - this.lastPruneMs < 30_000) return;
    this.lastPruneMs = nowMs;
    for (const [id, until] of this.seen) {
      if (until * 1000 < nowMs) this.seen.delete(id);
    }
  }
}

/** Old name, kept so existing imports keep working. */
export { MemoryReplayCache as ReplayCache };
