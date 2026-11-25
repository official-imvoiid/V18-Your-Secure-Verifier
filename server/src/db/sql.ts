import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { Pool, PoolClient } from 'pg';
import { serverRoot } from '../config.js';

/**
 * One small SQL interface with two engines:
 *   - SQLite (node:sqlite): a file in dev, or ':memory:' (the "memory" store).
 *   - PostgreSQL (pg): production, so several server copies share all state.
 *
 * Every repository is written once against this interface. SQL uses `?`
 * placeholders; the PostgreSQL engine rewrites them to $1, $2, ...
 * Times in the new tables are epoch milliseconds (BIGINT), so both engines
 * compare them the same way.
 */
export type Dialect = 'sqlite' | 'postgres';
export type SqlValue = string | number | bigint | null | Uint8Array;

export interface SqlDb {
  readonly dialect: Dialect;
  /** " FOR UPDATE" on PostgreSQL, "" on SQLite (which locks the whole file). */
  readonly forUpdate: string;
  all<T = Record<string, unknown>>(sql: string, params?: SqlValue[]): Promise<T[]>;
  get<T = Record<string, unknown>>(sql: string, params?: SqlValue[]): Promise<T | undefined>;
  run(sql: string, params?: SqlValue[]): Promise<{ changes: number }>;
  /** Runs `fn` in one transaction. Nested calls join the outer transaction. */
  tx<T>(fn: (db: SqlDb) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export const MIGRATIONS_DIR = path.join(serverRoot, 'migrations');

// ---------------------------------------------------------------------------
// SQLite
// ---------------------------------------------------------------------------

/**
 * node:sqlite is synchronous, but our transactions await between statements.
 * A simple queue makes sure no other request's statement runs inside an open
 * transaction on the shared connection.
 */
class SqliteDb implements SqlDb {
  readonly dialect = 'sqlite' as const;
  readonly forUpdate = '';
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    readonly raw: DatabaseSync,
    private readonly inTx = false
  ) {}

  private exclusive<T>(fn: () => Promise<T> | T): Promise<T> {
    if (this.inTx) return Promise.resolve().then(fn);
    const next = this.queue.then(fn, fn);
    this.queue = next.catch(() => undefined);
    return next;
  }

  private static norm(params: SqlValue[]): (string | number | bigint | null | Uint8Array)[] {
    return params;
  }

  all<T>(sql: string, params: SqlValue[] = []): Promise<T[]> {
    return this.exclusive(() => this.raw.prepare(sql).all(...SqliteDb.norm(params)) as T[]);
  }

  get<T>(sql: string, params: SqlValue[] = []): Promise<T | undefined> {
    return this.exclusive(() => this.raw.prepare(sql).get(...SqliteDb.norm(params)) as T | undefined);
  }

  run(sql: string, params: SqlValue[] = []): Promise<{ changes: number }> {
    return this.exclusive(() => ({ changes: Number(this.raw.prepare(sql).run(...SqliteDb.norm(params)).changes) }));
  }

  tx<T>(fn: (db: SqlDb) => Promise<T>): Promise<T> {
    if (this.inTx) return fn(this);
    return this.exclusive(async () => {
      this.raw.exec('BEGIN IMMEDIATE');
      try {
        const out = await fn(new SqliteDb(this.raw, true));
        this.raw.exec('COMMIT');
        return out;
      } catch (err) {
        this.raw.exec('ROLLBACK');
        throw err;
      }
    });
  }

  async close(): Promise<void> {
    await this.queue;
    if (this.raw.isOpen) this.raw.close();
  }
}

/** Options for the migration runners. The two extra fields are for tests only. */
export interface MigrateOptions {
  /** TESTS: another migrations folder. */
  migrationsDir?: string;
  /** TESTS: apply migrations up to and including this file name, then stop. */
  upTo?: string;
}

/** SHA-256 of a migration file, with Windows line endings made "\n" so a git checkout cannot change it. */
export function migrationChecksum(sql: string): string {
  return crypto.createHash('sha256').update(sql.replace(/\r\n/g, '\n'), 'utf8').digest('hex');
}

interface MigrationFile {
  name: string;
  sql: string;
  checksum: string;
}

function migrationFiles(dir: string, engine: Dialect, upTo?: string): MigrationFile[] {
  return fs
    .readdirSync(dir)
    .filter((f) => (engine === 'sqlite' ? f.endsWith('_sqlite.sql') : /^\d{3}_.*\.sql$/.test(f) && !f.endsWith('_sqlite.sql')))
    .sort()
    .filter((f) => upTo === undefined || f <= upTo)
    .map((name) => {
      const sql = fs.readFileSync(path.join(dir, name), 'utf8');
      return { name, sql, checksum: migrationChecksum(sql) };
    });
}

/**
 * The guard: a migration that has been applied must never change, or the
 * databases that ran the old text would silently differ from new ones (this
 * happened once with 003, see migration 004). Every applied migration's
 * SHA-256 is stored; the server refuses to start if a file no longer matches.
 * Rows from before the guard have no checksum yet; they get the file's
 * current one the first time.
 */
function checkApplied(
  files: MigrationFile[],
  applied: Map<string, string | null>,
  engine: string,
  backfill: (name: string, checksum: string) => void | Promise<void>
): Promise<void> | void {
  const pending: (void | Promise<void>)[] = [];
  for (const f of files) {
    if (!applied.has(f.name)) continue;
    const recorded = applied.get(f.name);
    if (!recorded) {
      pending.push(backfill(f.name, f.checksum));
    } else if (recorded !== f.checksum) {
      throw new Error(
        `${engine} migration ${f.name} was changed after it was applied to this database ` +
          `(applied ${recorded.slice(0, 12)}..., file now ${f.checksum.slice(0, 12)}...). ` +
          'Never edit an applied migration: put the change in a new numbered migration.'
      );
    }
  }
  if (pending.some((p) => p instanceof Promise)) return Promise.all(pending).then(() => undefined);
}

export function openSqlite(dbPath: string, opts: MigrateOptions = {}): SqlDb {
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const raw = new DatabaseSync(dbPath);
  raw.exec('PRAGMA foreign_keys = ON;');
  if (dbPath !== ':memory:') raw.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
  raw.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL);`);
  const cols = (raw.prepare('PRAGMA table_info(schema_migrations)').all() as { name: string }[]).map((c) => c.name);
  if (!cols.includes('checksum')) raw.exec('ALTER TABLE schema_migrations ADD COLUMN checksum TEXT');

  const files = migrationFiles(opts.migrationsDir ?? MIGRATIONS_DIR, 'sqlite', opts.upTo);
  const applied = new Map(
    (raw.prepare('SELECT name, checksum FROM schema_migrations').all() as { name: string; checksum: string | null }[]).map((r) => [
      r.name,
      r.checksum,
    ])
  );
  try {
    checkApplied(files, applied, 'SQLite', (name, checksum) => {
      raw.prepare('UPDATE schema_migrations SET checksum = ? WHERE name = ?').run(checksum, name);
    });
  } catch (err) {
    raw.close();
    throw err;
  }
  for (const f of files) {
    if (applied.has(f.name)) continue;
    raw.exec('BEGIN');
    try {
      raw.exec(f.sql);
      raw
        .prepare('INSERT INTO schema_migrations (name, applied_at, checksum) VALUES (?, ?, ?)')
        .run(f.name, new Date().toISOString(), f.checksum);
      raw.exec('COMMIT');
    } catch (err) {
      raw.exec('ROLLBACK');
      raw.close();
      throw new Error(`SQLite migration ${f.name} failed: ${(err as Error).message}`);
    }
  }
  return new SqliteDb(raw);
}

// ---------------------------------------------------------------------------
// PostgreSQL
// ---------------------------------------------------------------------------

function toPg(sql: string): string {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

function pgParams(params: SqlValue[]): unknown[] {
  return params.map((p) => (typeof p === 'bigint' ? p.toString() : p instanceof Uint8Array ? Buffer.from(p) : p));
}

type Queryable = Pick<Pool, 'query'> | PoolClient;

class PgDb implements SqlDb {
  readonly dialect = 'postgres' as const;
  readonly forUpdate = ' FOR UPDATE';

  constructor(
    private readonly q: Queryable,
    private readonly pool: Pool,
    private readonly inTx = false
  ) {}

  async all<T>(sql: string, params: SqlValue[] = []): Promise<T[]> {
    const r = await this.q.query(toPg(sql), pgParams(params));
    return r.rows as T[];
  }

  async get<T>(sql: string, params: SqlValue[] = []): Promise<T | undefined> {
    return (await this.all<T>(sql, params))[0];
  }

  async run(sql: string, params: SqlValue[] = []): Promise<{ changes: number }> {
    const r = await this.q.query(toPg(sql), pgParams(params));
    return { changes: r.rowCount ?? 0 };
  }

  async tx<T>(fn: (db: SqlDb) => Promise<T>): Promise<T> {
    if (this.inTx) return fn(this);
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const out = await fn(new PgDb(client, this.pool, true));
      await client.query('COMMIT');
      return out;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

/** Opens a pool and applies `migrations/NNN_*.sql` (not the `_sqlite` ones), once, under a lock. */
export async function openPostgres(url: string, opts: { max?: number } & MigrateOptions = {}): Promise<SqlDb> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const pg = require('pg') as typeof import('pg');
  // BIGINT (int8) comes back as a string by default; our values fit in a JS number.
  pg.types.setTypeParser(20, (v: string) => Number(v));
  const pool = new pg.Pool({ connectionString: url, max: opts.max ?? 10 });
  pool.on('error', (err) => console.error('[v18] PostgreSQL pool error:', err.message));
  let failed: unknown = null;
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock(18018001)');
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
    await client.query('ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT');
    const files = migrationFiles(opts.migrationsDir ?? MIGRATIONS_DIR, 'postgres', opts.upTo);
    const applied = new Map(
      (await client.query('SELECT name, checksum FROM schema_migrations')).rows.map((r) => [r.name as string, r.checksum as string | null])
    );
    await checkApplied(files, applied, 'PostgreSQL', async (name, checksum) => {
      await client.query('UPDATE schema_migrations SET checksum = $1 WHERE name = $2', [checksum, name]);
    });
    for (const f of files) {
      if (applied.has(f.name)) continue;
      await client.query('BEGIN');
      try {
        await client.query(f.sql);
        await client.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [f.name, f.checksum]);
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw new Error(`PostgreSQL migration ${f.name} failed: ${(err as Error).message}`);
      }
    }
  } catch (err) {
    failed = err;
  } finally {
    await client.query('SELECT pg_advisory_unlock(18018001)').catch(() => undefined);
    client.release();
  }
  if (failed) {
    await pool.end().catch(() => undefined);
    throw failed;
  }
  return new PgDb(pool, pool);
}

/** Opens the database the config asks for. */
export async function openSql(opts: { databaseUrl: string | null; dbPath: string }): Promise<SqlDb> {
  if (opts.databaseUrl) return openPostgres(opts.databaseUrl);
  return openSqlite(opts.dbPath);
}

/** SQLite returns TEXT for ISO dates; PostgreSQL returns Date for TIMESTAMPTZ. */
export function isoOf(v: unknown): string {
  if (v instanceof Date) return v.toISOString();
  return String(v);
}

export function isoOrNull(v: unknown): string | null {
  return v === null || v === undefined ? null : isoOf(v);
}
