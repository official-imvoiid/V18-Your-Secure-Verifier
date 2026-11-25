import type { DeviceAlg, DevicePublicJwk } from '../device/device-keys.js';
import { isoOf, isoOrNull, SqlDb } from '../db/sql.js';

export type CardMethod =
  | 'test_dev'
  | 'anon_aadhaar'
  | 'passport_zk'
  | 'passport_attested'
  | 'emrtd_attested'
  | 'philsys_qr_attested'
  | 'mynumber_attested'
  | 'face_estimate'
  | 'mdoc_app'
  | `connector:${string}`;

const FIXED_METHODS = new Set([
  'test_dev',
  'anon_aadhaar',
  'passport_zk',
  'passport_attested',
  'emrtd_attested',
  'philsys_qr_attested',
  'mynumber_attested',
  'face_estimate',
  'mdoc_app',
]);

/** Every method a card may be stored with: the fixed ones, and connector:<id> (lower-case id). */
export function isCardMethod(m: unknown): m is CardMethod {
  return typeof m === 'string' && (FIXED_METHODS.has(m) || /^connector:[a-z0-9_]{1,40}$/.test(m));
}

/**
 * One age card. This is everything the server keeps about a card: no name,
 * birth date, ID number, image or site history.
 */
export interface CardRecord {
  cardId: string;
  method: CardMethod;
  assuranceLevel: string;
  minAgeCertified: number;
  deviceKeyAlg: DeviceAlg;
  deviceKeyJwk: DevicePublicJwk;
  deviceKeyThumbprint: string;
  nullifierHash: string;
  status: 'active' | 'revoked';
  issuedAt: string;
  validUntil: string;
  revokedAt: string | null;
}

interface Row {
  card_id: string;
  method: CardMethod;
  assurance_level: string;
  min_age_certified: number;
  device_key_alg: DeviceAlg;
  device_key_jwk: string | DevicePublicJwk;
  device_key_thumbprint: string;
  nullifier_hash: string;
  status: 'active' | 'revoked';
  issued_at: string | Date;
  valid_until: string | Date;
  revoked_at: string | Date | null;
}

function fromRow(r: Row): CardRecord {
  return {
    cardId: r.card_id,
    method: r.method,
    assuranceLevel: r.assurance_level,
    minAgeCertified: Number(r.min_age_certified),
    deviceKeyAlg: r.device_key_alg,
    // SQLite gives TEXT, PostgreSQL gives the parsed JSONB.
    deviceKeyJwk: typeof r.device_key_jwk === 'string' ? (JSON.parse(r.device_key_jwk) as DevicePublicJwk) : r.device_key_jwk,
    deviceKeyThumbprint: r.device_key_thumbprint,
    nullifierHash: r.nullifier_hash,
    status: r.status,
    issuedAt: isoOf(r.issued_at),
    validUntil: isoOf(r.valid_until),
    revokedAt: isoOrNull(r.revoked_at),
  };
}

export class CardStore {
  constructor(readonly db: SqlDb) {}

  async insert(c: CardRecord, db: SqlDb = this.db): Promise<void> {
    // The database no longer lists the methods (migration 004), so the server checks them here.
    if (!isCardMethod(c.method)) throw new Error(`Refusing to store a card with unknown method "${c.method}"`);
    await db.run(
      `INSERT INTO cards (card_id, method, assurance_level, min_age_certified, device_key_alg,
         device_key_jwk, device_key_thumbprint, nullifier_hash, status, issued_at, valid_until, revoked_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        c.cardId,
        c.method,
        c.assuranceLevel,
        c.minAgeCertified,
        c.deviceKeyAlg,
        JSON.stringify(c.deviceKeyJwk),
        c.deviceKeyThumbprint,
        c.nullifierHash,
        c.status,
        c.issuedAt,
        c.validUntil,
        c.revokedAt,
      ]
    );
  }

  async get(cardId: string): Promise<CardRecord | null> {
    const row = await this.db.get<Row>('SELECT * FROM cards WHERE card_id = ?', [cardId]);
    return row ? fromRow(row) : null;
  }

  /** Active, unexpired cards for one nullifier (the cap counts these). */
  async countActive(nullifierHash: string, nowIso: string, db: SqlDb = this.db): Promise<number> {
    const row = await db.get<{ cnt: number }>(
      `SELECT COUNT(*) AS cnt FROM cards WHERE nullifier_hash = ? AND status = 'active' AND valid_until > ?`,
      [nullifierHash, nowIso]
    );
    return Number(row?.cnt ?? 0);
  }

  /** True if an active, unexpired card already uses this device key. */
  async thumbprintInUse(thumbprint: string, nowIso: string, db: SqlDb = this.db): Promise<boolean> {
    const row = await db.get(
      `SELECT 1 AS x FROM cards WHERE device_key_thumbprint = ? AND status = 'active' AND valid_until > ?`,
      [thumbprint, nowIso]
    );
    return row !== undefined;
  }

  /**
   * Holds a lock on this thumbprint until the transaction ends, so two
   * requests with the same new device key cannot both make a card.
   * (SQLite already locks the whole database in a write transaction.)
   */
  async lockThumbprint(thumbprint: string, tx: SqlDb): Promise<void> {
    if (tx.dialect === 'postgres') {
      await tx.get('SELECT pg_advisory_xact_lock(hashtextextended(?, 18))', [`v18-thumb:${thumbprint}`]);
    }
  }

  async revoke(cardId: string, nowIso: string): Promise<void> {
    await this.db.run(`UPDATE cards SET status = 'revoked', revoked_at = ? WHERE card_id = ? AND status = 'active'`, [
      nowIso,
      cardId,
    ]);
  }

  /** Anonymous counts for /metrics. */
  async countByStatus(nowIso: string): Promise<{ active: number; total: number }> {
    const a = await this.db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM cards WHERE status = 'active' AND valid_until > ?`, [nowIso]);
    const t = await this.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM cards');
    return { active: Number(a?.n ?? 0), total: Number(t?.n ?? 0) };
  }
}
