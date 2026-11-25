import * as crypto from 'node:crypto';
import { ChallengeRepo } from '../db/state.js';
import { ApiError } from '../errors.js';
import { Clock, systemClock } from '../util.js';

/** 32 random bytes as 64 lowercase hex characters (protocol 3.3). */
export const CHALLENGE_PATTERN = /^[0-9a-f]{64}$/;

const MAX_OPEN_CHALLENGES = 200_000;

/**
 * Single-use server challenges, valid for 5 minutes (protocol 3.3).
 * Every card, ticket, link, nullifier and attested request consumes one.
 * Stored in the database, so any server copy can check a challenge that
 * another copy handed out.
 */
export class ChallengeService {
  private readonly ttlMs: number;
  private readonly timer: NodeJS.Timeout;

  constructor(
    private readonly repo: ChallengeRepo,
    ttlSeconds = 300,
    private readonly clock: Clock = systemClock
  ) {
    this.ttlMs = ttlSeconds * 1000;
    this.timer = setInterval(() => {
      this.repo.prune(this.clock()).catch(() => undefined);
    }, 60_000);
    this.timer.unref();
  }

  async createChallenge(): Promise<{ challenge: string; expiresAt: string }> {
    if ((await this.repo.count()) >= MAX_OPEN_CHALLENGES) {
      await this.repo.prune(this.clock());
      if ((await this.repo.count()) >= MAX_OPEN_CHALLENGES) {
        throw new ApiError(503, 'BUSY', 'Too many open challenges. Try again soon.');
      }
    }
    const challenge = crypto.randomBytes(32).toString('hex');
    const expiresAt = this.clock() + this.ttlMs;
    await this.repo.put(challenge, expiresAt);
    return { challenge, expiresAt: new Date(expiresAt).toISOString() };
  }

  /** True once for a valid, unexpired challenge, then it is gone. */
  async verifyAndConsume(challenge: unknown): Promise<boolean> {
    if (typeof challenge !== 'string' || !CHALLENGE_PATTERN.test(challenge)) return false;
    return this.repo.consume(challenge, this.clock());
  }

  /** Like verifyAndConsume, but throws 401 CHALLENGE_INVALID. */
  async consumeOrThrow(challenge: unknown): Promise<string> {
    if (!(await this.verifyAndConsume(challenge))) {
      throw new ApiError(
        401,
        'CHALLENGE_INVALID',
        'The challenge is missing, expired or already used. Get a new one from POST /v1/challenge.'
      );
    }
    return challenge as string;
  }

  /** True for an open challenge, without using it up. */
  async isOpen(challenge: unknown): Promise<boolean> {
    if (typeof challenge !== 'string' || !CHALLENGE_PATTERN.test(challenge)) return false;
    return this.repo.isOpen(challenge, this.clock());
  }

  openCount(): Promise<number> {
    return this.repo.count();
  }

  close(): void {
    clearInterval(this.timer);
  }
}
