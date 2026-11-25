import * as crypto from 'node:crypto';
import type { SqlDb } from './sql.js';

/**
 * Short-lived protocol state, stored in the database so several server
 * copies can share it (PROTOCOL.md 4c.7). Nothing here is personal data.
 */

// ---- Challenges (protocol 3.3) ----------------------------------------------

export class ChallengeRepo {
  constructor(private readonly db: SqlDb) {}

  async put(challenge: string, expiresAtMs: number): Promise<void> {
    await this.db.run('INSERT INTO challenges (challenge, expires_at) VALUES (?, ?)', [challenge, expiresAtMs]);
  }

  /** Deletes the challenge and says whether it was there and still valid. Atomic. */
  async consume(challenge: string, nowMs: number): Promise<boolean> {
    const row = await this.db.get<{ expires_at: number }>(
      'DELETE FROM challenges WHERE challenge = ? RETURNING expires_at',
      [challenge]
    );
    return row !== undefined && nowMs <= Number(row.expires_at);
  }

  /** True if the challenge exists and is unexpired (it is NOT used up). */
  async isOpen(challenge: string, nowMs: number): Promise<boolean> {
    const row = await this.db.get<{ expires_at: number }>('SELECT expires_at FROM challenges WHERE challenge = ?', [challenge]);
    return row !== undefined && nowMs <= Number(row.expires_at);
  }

  async count(): Promise<number> {
    const r = await this.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM challenges');
    return Number(r?.n ?? 0);
  }

  async prune(nowMs: number): Promise<number> {
    return (await this.db.run('DELETE FROM challenges WHERE expires_at < ?', [nowMs])).changes;
  }
}

// ---- Rate limits --------------------------------------------------------------

export type RateResult = { ok: true } | { ok: false; retryAfterSeconds: number };

/**
 * Sliding-window limits: at most `limit` hits per key in `windowMs`.
 * The row is locked while it is read and written, so two server copies
 * cannot both let the last request through.
 */
export class RateLimitRepo {
  constructor(private readonly db: SqlDb) {}

  async take(key: string, limit: number, windowMs: number, nowMs: number): Promise<RateResult> {
    return this.db.tx(async (tx) => {
      await tx.run(
        'INSERT INTO rate_limits (rl_key, hits, expires_at) VALUES (?, ?, ?) ON CONFLICT (rl_key) DO NOTHING',
        [key, '[]', nowMs + windowMs]
      );
      const row = await tx.get<{ hits: string }>(`SELECT hits FROM rate_limits WHERE rl_key = ?${tx.forUpdate}`, [key]);
      const recent = (JSON.parse(row?.hits ?? '[]') as number[]).filter((t) => t > nowMs - windowMs);
      if (recent.length >= limit) {
        await tx.run('UPDATE rate_limits SET hits = ?, expires_at = ? WHERE rl_key = ?', [
          JSON.stringify(recent),
          recent[recent.length - 1] + windowMs,
          key,
        ]);
        return { ok: false as const, retryAfterSeconds: Math.max(1, Math.ceil((recent[0] + windowMs - nowMs) / 1000)) };
      }
      recent.push(nowMs);
      await tx.run('UPDATE rate_limits SET hits = ?, expires_at = ? WHERE rl_key = ?', [
        JSON.stringify(recent),
        nowMs + windowMs,
        key,
      ]);
      return { ok: true as const };
    });
  }

  async prune(nowMs: number): Promise<number> {
    return (await this.db.run('DELETE FROM rate_limits WHERE expires_at < ?', [nowMs])).changes;
  }
}

// ---- Documents (pairing sessions, device links, wallet requests) ---------------

export type DocKind = 'pairing' | 'link' | 'wallet' | 'connect';

/**
 * Small JSON documents with a version number. `update` reads, changes and
 * writes back only if nobody else wrote in between (compare-and-set), and
 * tries again if they did. That makes "submit once" and "deliver once" safe
 * across server copies.
 */
export class DocRepo {
  constructor(private readonly db: SqlDb) {}

  async insert<T>(kind: DocKind, id: string, data: T, expiresAtMs: number): Promise<void> {
    await this.db.run('INSERT INTO state_docs (kind, id, data, version, expires_at) VALUES (?, ?, ?, 1, ?)', [
      kind,
      id,
      JSON.stringify(data),
      expiresAtMs,
    ]);
  }

  /** Inserts or replaces. */
  async put<T>(kind: DocKind, id: string, data: T, expiresAtMs: number): Promise<void> {
    await this.db.run(
      `INSERT INTO state_docs (kind, id, data, version, expires_at) VALUES (?, ?, ?, 1, ?)
       ON CONFLICT (kind, id) DO UPDATE SET data = excluded.data, version = state_docs.version + 1, expires_at = excluded.expires_at`,
      [kind, id, JSON.stringify(data), expiresAtMs]
    );
  }

  async get<T>(kind: DocKind, id: string): Promise<T | null> {
    const row = await this.db.get<{ data: string }>('SELECT data FROM state_docs WHERE kind = ? AND id = ?', [kind, id]);
    return row ? (JSON.parse(row.data) as T) : null;
  }

  /**
   * Applies `mutate` atomically. `mutate` gets the current value and returns
   * `{value, result}` to write, or `{result}` alone to leave it unchanged. It
   * may throw to refuse. It can run more than once, so it must not have side
   * effects.
   */
  async update<T, R>(
    kind: DocKind,
    id: string,
    mutate: (current: T | null) => { value?: T; expiresAtMs?: number; result: R }
  ): Promise<R> {
    for (let attempt = 0; attempt < 20; attempt++) {
      const row = await this.db.get<{ data: string; version: number; expires_at: number }>(
        'SELECT data, version, expires_at FROM state_docs WHERE kind = ? AND id = ?',
        [kind, id]
      );
      const current = row ? (JSON.parse(row.data) as T) : null;
      const out = mutate(current);
      if (out.value === undefined) return out.result;
      if (!row) {
        throw new Error('DocRepo.update cannot create a document; use insert');
      }
      const r = await this.db.run(
        'UPDATE state_docs SET data = ?, version = version + 1, expires_at = ? WHERE kind = ? AND id = ? AND version = ?',
        [JSON.stringify(out.value), out.expiresAtMs ?? Number(row.expires_at), kind, id, Number(row.version)]
      );
      if (r.changes === 1) return out.result;
      // Someone else changed it in between. Read again.
    }
    throw new Error(`Too much contention on ${kind}/${id}`);
  }

  async delete(kind: DocKind, id: string): Promise<void> {
    await this.db.run('DELETE FROM state_docs WHERE kind = ? AND id = ?', [kind, id]);
  }

  async count(kind: DocKind): Promise<number> {
    const r = await this.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM state_docs WHERE kind = ?', [kind]);
    return Number(r?.n ?? 0);
  }

  async prune(nowMs: number): Promise<number> {
    return (await this.db.run('DELETE FROM state_docs WHERE expires_at < ?', [nowMs])).changes;
  }
}

// ---- Server meta (shared settings such as the IP-hash salt) -----------------------

export class MetaRepo {
  constructor(private readonly db: SqlDb) {}

  /** Returns the stored value, creating it with `make()` the first time (race-safe). */
  async getOrCreate(key: string, make: () => string): Promise<string> {
    await this.db.run('INSERT INTO server_meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING', [key, make()]);
    const row = await this.db.get<{ value: string }>('SELECT value FROM server_meta WHERE key = ?', [key]);
    if (!row) throw new Error(`server_meta ${key} missing`);
    return row.value;
  }
}

/**
 * Hashes a client IP with a salt shared by all server copies (kept in
 * server_meta). Raw IPs are never stored.
 */
export async function ipHasher(meta: MetaRepo): Promise<(ip: string | undefined) => string> {
  const salt = await meta.getOrCreate('ip_salt', () => crypto.randomBytes(32).toString('hex'));
  return (ip) => crypto.createHash('sha256').update(`${salt}|${ip ?? 'unknown'}`).digest('hex').slice(0, 32);
}
