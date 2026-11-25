import * as path from 'node:path';

/**
 * Server settings. Everything comes from environment variables so the same
 * build runs in dev and production. Tests pass overrides instead.
 *
 * `serverRoot` is the `server/` folder (this file lives in `src/` or `dist/`).
 */
export const serverRoot = path.resolve(__dirname, '..');

export interface Config {
  /** V18_DEV_MODE=1: allows the `test_dev` issuer and Anon Aadhaar test keys. */
  devMode: boolean;
  port: number;
  /** Public base URL put into deep links as `server=` (no `/v1`). */
  publicUrl: string;
  /** Folder for dev data (keys, SQLite). Gitignored. */
  dataDir: string;
  /** SQLite file path, or ':memory:'. */
  dbPath: string;
  /** Folder for the file key store. */
  keyDir: string;
  /** Age thresholds that get their own ticket key, for example [18]. */
  ageThresholds: number[];
  /** A new ticket key every N days. */
  keyRotationDays: number;
  /** RSA modulus size for ticket keys (2048 in dev, 3072 allowed). */
  keyBits: 2048 | 3072 | 4096;
  /** Most active cards one ID (nullifier) may have at once. */
  maxCardsPerId: number;
  /** Most tickets one card may get per hour. */
  ticketsPerHour: number;
  /** Anon Aadhaar nullifier seed (decimal string). Null means not set. */
  aadhaarNullifierSeed: string | null;
  /** Path to the Anon Aadhaar verification key (vkey.json). Null means not set. */
  aadhaarVkeyPath: string | null;
  /**
   * Extra browser origins allowed by CORS on the APP endpoints (the dev demo
   * origin is added in dev mode). Widget endpoints are open to any website.
   */
  corsOrigins: string[];
  /** Most pairing sessions one IP may create per minute. */
  pairingSessionsPerMinute: number;
  /** Express "trust proxy" setting, so the per-IP limit sees real client IPs behind a proxy. */
  trustProxy: boolean | number | string;
  /** Challenge lifetime in seconds. */
  challengeTtlSeconds: number;
  /** Device link lifetime in seconds. */
  linkTtlSeconds: number;

  // ---- Protocol 4c and 4d settings ----------------------------------------------
  /** V18_DATABASE_URL (postgres://...): use PostgreSQL for ALL state. Null: SQLite at dbPath. */
  databaseUrl: string | null;
  /** "file" (dev, plain JSON files) or "db" (encrypted in the database, required in production). */
  keyStore: 'file' | 'db';
  /** V18_KEK: 32-byte key-encryption key (base64 or hex) for the "db" key store. */
  kek: Buffer | null;
  /** Modulus size of the long-lived v18-nullifier-1 key. */
  nullifierKeyBits: 2048 | 3072 | 4096;
  /** Android application ID that must appear in key attestation. */
  androidPackage: string;
  /** Lowercase hex SHA-256 digests of the app signing certificates (V18_ANDROID_CERT_DIGESTS). */
  androidCertDigests: string[];
  /** Nullifier blind-sign limits (4c.2). */
  nullifierPerDevicePerDay: number;
  nullifierPerIpPerHour: number;
  /** Face models accepted for face_estimate (V18_FACE_MODELS). Empty = method off. */
  faceModels: string[];
  /**
   * mynumber_attested is NOT in v1 (PROTOCOL.md 4d.4b). The code is kept; V18_ENABLE_MYNUMBER=1
   * turns it back on (for testing, or once J-LIS and the Digital Agency allow it).
   */
  enableMyNumber: boolean;
  /** Lowest challenge age accepted from the face estimator (4c.6, default 25). */
  faceChallengeAge: number;
  /** Folder of trusted IACA certificates for mdoc wallets (assets/iaca). */
  iacaDir: string;
  /** Dev only: extra IACA PEM files to trust (V18_DEV_IACA_PEMS). */
  devIacaPems: string[];
  /** Secret for connector nullifiers (4d.4, V18_NULLIFIER_SECRET). */
  nullifierSecret: string | null;
  /** Path to the country catalog (4d.2). */
  catalogPath: string;
  /** Optional bearer token for /metrics. */
  metricsToken: string | null;
  /** Wallet verifications per IP per minute. */
  walletPerIpPerMinute: number;
}

/** Dev-only connector nullifier secret. Production must set V18_NULLIFIER_SECRET. */
export const DEV_NULLIFIER_SECRET = 'v18-DEV-ONLY-connector-nullifier-secret';

export const repoRoot = path.resolve(serverRoot, '..');

function keyEnv(value: string | undefined): Buffer | null {
  if (!value) return null;
  const v = value.trim();
  const b = /^[0-9a-fA-F]{64}$/.test(v) ? Buffer.from(v, 'hex') : Buffer.from(v.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (b.length !== 32) throw new Error('V18_KEK must be 32 bytes, as 64 hex characters or base64');
  return b;
}

function bitsEnv(value: string | undefined, fallback: number, name: string): 2048 | 3072 | 4096 {
  const n = intEnv(value, fallback, name);
  if (![2048, 3072, 4096].includes(n)) throw new Error(`${name} must be 2048, 3072 or 4096`);
  return n as 2048 | 3072 | 4096;
}

/** Dev-only default seed. Production must set its own V18_AADHAAR_NULLIFIER_SEED. */
export const DEV_AADHAAR_NULLIFIER_SEED = '180018001800180018';

export const DEV_DEMO_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000'];

function intEnv(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n)) {
    throw new Error(`${name} must be a whole number (got "${value}")`);
  }
  return n;
}

/** "memory" (or ":memory:") gives an in-memory SQLite database. */
function dbPathEnv(value: string | undefined): string | null {
  if (!value) return null;
  return value === 'memory' || value === ':memory:' ? ':memory:' : value;
}

function listEnv(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function isTruthy(value: string | undefined): boolean {
  return value === '1' || value === 'true' || value === 'yes';
}

/**
 * Reads the config from environment variables, then applies overrides.
 */
export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
  overrides: Partial<Config> = {}
): Config {
  const devMode = overrides.devMode ?? isTruthy(env.V18_DEV_MODE);
  const port = overrides.port ?? intEnv(env.PORT, 8080, 'PORT');
  const dataDir = overrides.dataDir ?? path.resolve(env.V18_DATA_DIR || path.join(serverRoot, 'data'));

  const keyBitsRaw = intEnv(env.V18_KEY_BITS, 2048, 'V18_KEY_BITS');
  if (![2048, 3072, 4096].includes(keyBitsRaw)) {
    throw new Error('V18_KEY_BITS must be 2048, 3072 or 4096');
  }

  const thresholds = env.V18_AGE_THRESHOLDS
    ? listEnv(env.V18_AGE_THRESHOLDS).map((s) => intEnv(s, 18, 'V18_AGE_THRESHOLDS'))
    : [18];

  const config: Config = {
    devMode,
    port,
    publicUrl: (env.V18_PUBLIC_URL || `http://localhost:${port}`).replace(/\/+$/, ''),
    dataDir,
    dbPath: dbPathEnv(env.V18_DB_PATH || env.DB_PATH) ?? path.join(dataDir, 'v18.sqlite'),
    keyDir: env.V18_KEY_DIR || path.join(dataDir, 'keys'),
    ageThresholds: thresholds,
    keyRotationDays: intEnv(env.V18_KEY_ROTATION_DAYS, 7, 'V18_KEY_ROTATION_DAYS'),
    keyBits: keyBitsRaw as Config['keyBits'],
    maxCardsPerId: intEnv(env.V18_MAX_CARDS_PER_ID, 3, 'V18_MAX_CARDS_PER_ID'),
    ticketsPerHour: intEnv(env.V18_TICKETS_PER_HOUR, 30, 'V18_TICKETS_PER_HOUR'),
    aadhaarNullifierSeed: env.V18_AADHAAR_NULLIFIER_SEED || (devMode ? DEV_AADHAAR_NULLIFIER_SEED : null),
    aadhaarVkeyPath: env.V18_AADHAAR_VKEY_PATH ? path.resolve(env.V18_AADHAAR_VKEY_PATH) : null,
    corsOrigins: listEnv(env.V18_CORS_ORIGINS),
    pairingSessionsPerMinute: intEnv(env.V18_PAIRING_SESSIONS_PER_MINUTE, 30, 'V18_PAIRING_SESSIONS_PER_MINUTE'),
    trustProxy: parseTrustProxy(env.V18_TRUST_PROXY),
    challengeTtlSeconds: 300,
    linkTtlSeconds: 120,
    databaseUrl: env.V18_DATABASE_URL || env.DATABASE_URL || null,
    keyStore: (env.V18_KEY_STORE as Config['keyStore']) || (devMode && !(env.V18_DATABASE_URL || env.DATABASE_URL) ? 'file' : 'db'),
    kek: keyEnv(env.V18_KEK),
    nullifierKeyBits: bitsEnv(env.V18_NULLIFIER_KEY_BITS, devMode ? 2048 : 3072, 'V18_NULLIFIER_KEY_BITS'),
    androidPackage: env.V18_ANDROID_PACKAGE || 'com.v18.app',
    androidCertDigests: listEnv(env.V18_ANDROID_CERT_DIGESTS).map(normalizeCertDigest),
    nullifierPerDevicePerDay: intEnv(env.V18_NULLIFIER_PER_DEVICE_PER_DAY, 5, 'V18_NULLIFIER_PER_DEVICE_PER_DAY'),
    nullifierPerIpPerHour: intEnv(env.V18_NULLIFIER_PER_IP_PER_HOUR, 20, 'V18_NULLIFIER_PER_IP_PER_HOUR'),
    faceModels: listEnv(env.V18_FACE_MODELS),
    enableMyNumber: isTruthy(env.V18_ENABLE_MYNUMBER),
    faceChallengeAge: intEnv(env.V18_FACE_CHALLENGE_AGE, 25, 'V18_FACE_CHALLENGE_AGE'),
    iacaDir: env.V18_IACA_DIR ? path.resolve(env.V18_IACA_DIR) : path.join(serverRoot, 'assets', 'iaca'),
    devIacaPems: listEnv(env.V18_DEV_IACA_PEMS).map((p) => path.resolve(p)),
    nullifierSecret: env.V18_NULLIFIER_SECRET || (devMode ? DEV_NULLIFIER_SECRET : null),
    catalogPath: env.V18_CATALOG_PATH ? path.resolve(env.V18_CATALOG_PATH) : path.join(repoRoot, 'catalog', 'countries.json'),
    metricsToken: env.V18_METRICS_TOKEN || null,
    walletPerIpPerMinute: intEnv(env.V18_WALLET_PER_IP_PER_MINUTE, 30, 'V18_WALLET_PER_IP_PER_MINUTE'),
    ...overrides,
  };
  if (isTruthy(env.V18_PLAY_INTEGRITY)) {
    throw new Error(
      'V18_PLAY_INTEGRITY is not built in v1 (it needs a Play Console project). Unset it; key attestation (4c.3) is always checked.'
    );
  }

  validateConfig(config);
  return config;
}

function validateConfig(c: Config): void {
  if (c.ageThresholds.length === 0) throw new Error('At least one age threshold is needed');
  for (const t of c.ageThresholds) {
    if (!Number.isInteger(t) || t < 1 || t > 99) {
      throw new Error(`Age threshold ${t} must be between 1 and 99`);
    }
  }
  if (new Set(c.ageThresholds).size !== c.ageThresholds.length) {
    throw new Error('Age thresholds must not repeat');
  }
  if (!Number.isInteger(c.keyRotationDays) || c.keyRotationDays < 1 || c.keyRotationDays > 90) {
    throw new Error('V18_KEY_ROTATION_DAYS must be between 1 and 90');
  }
  if (c.maxCardsPerId < 1) throw new Error('V18_MAX_CARDS_PER_ID must be at least 1');
  if (c.ticketsPerHour < 1) throw new Error('V18_TICKETS_PER_HOUR must be at least 1');
  if (c.pairingSessionsPerMinute < 1) throw new Error('V18_PAIRING_SESSIONS_PER_MINUTE must be at least 1');
  if (c.aadhaarNullifierSeed !== null && !/^\d{1,77}$/.test(c.aadhaarNullifierSeed)) {
    throw new Error('V18_AADHAAR_NULLIFIER_SEED must be a decimal number');
  }
  if (c.keyStore !== 'file' && c.keyStore !== 'db') throw new Error('V18_KEY_STORE must be "file" or "db"');
  if (c.faceChallengeAge < 25) throw new Error('V18_FACE_CHALLENGE_AGE must be at least 25 (PROTOCOL.md 4c.6)');
  if (c.nullifierPerDevicePerDay < 1 || c.nullifierPerIpPerHour < 1) throw new Error('Nullifier limits must be at least 1');
  if (c.nullifierSecret !== null && !c.devMode && c.nullifierSecret.length < 32) {
    throw new Error('V18_NULLIFIER_SECRET must be at least 32 characters');
  }
  for (const o of c.corsOrigins) {
    if (!isWebOrigin(o)) throw new Error(`V18_CORS_ORIGINS entry "${o}" is not an origin like https://site.example`);
  }
}

/** V18_ANDROID_CERT_DIGESTS entries: hex (colons allowed) or base64 SHA-256. */
export function normalizeCertDigest(value: string): string {
  const v = value.trim();
  const hex = v.replace(/:/g, '').toLowerCase();
  if (/^[0-9a-f]{64}$/.test(hex)) return hex;
  const b = Buffer.from(v.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (b.length === 32) return b.toString('hex');
  throw new Error(`V18_ANDROID_CERT_DIGESTS entry "${value}" is not a SHA-256 digest (64 hex characters or base64)`);
}

/** V18_TRUST_PROXY: unset/"0"/"false" = off, "true" = trust all, digits = hop count, else an Express value like "loopback". */
function parseTrustProxy(value: string | undefined): boolean | number | string {
  if (value === undefined || value === '' || value === '0' || value === 'false') return false;
  if (value === 'true' || value === 'yes') return true;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

/** True for `scheme://host[:port]` with http or https and nothing else. */
export function isWebOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 255) return false;
  try {
    const u = new URL(value);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    return u.origin === value;
  } catch {
    return false;
  }
}
