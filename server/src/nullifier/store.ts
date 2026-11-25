import type { SqlDb } from '../db/sql.js';
import { sha256Hex } from '../util.js';

/**
 * Nullifier hashes: anonymous codes that limit how many age cards one ID can
 * make, without revealing the ID. Only the hash is stored.
 */
export class NullifierStore {
  constructor(readonly db: SqlDb) {}

  /**
   * Turns a method's raw nullifier into the stored hash. The method name is
   * mixed in so different methods can never collide.
   */
  static hashFor(method: string, rawNullifier: string): string {
    return sha256Hex(`v18-nullifier-v1\n${method}\n${rawNullifier}`);
  }

  async has(nullifierHash: string): Promise<boolean> {
    return (await this.db.get('SELECT 1 AS x FROM nullifiers WHERE nullifier_hash = ?', [nullifierHash])) !== undefined;
  }

  /** Records a nullifier hash. True if it is new, false if already known. */
  async record(nullifierHash: string, method: string, db: SqlDb = this.db): Promise<boolean> {
    const r = await db.run(
      `INSERT INTO nullifiers (nullifier_hash, issuer_id, created_at) VALUES (?, ?, ?)
       ON CONFLICT (nullifier_hash) DO NOTHING`,
      [nullifierHash, method, new Date().toISOString()]
    );
    return r.changes === 1;
  }

  /** Locks the nullifier row until the transaction ends (PostgreSQL), so the card cap is exact. */
  async lock(nullifierHash: string, tx: SqlDb): Promise<void> {
    await tx.get(`SELECT nullifier_hash FROM nullifiers WHERE nullifier_hash = ?${tx.forUpdate}`, [nullifierHash]);
  }

  /** Anonymous counter for audits. */
  async count(): Promise<number> {
    const row = await this.db.get<{ cnt: number }>('SELECT COUNT(*) AS cnt FROM nullifiers');
    return row ? Number(row.cnt) : 0;
  }
}
