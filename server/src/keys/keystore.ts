import * as fs from 'node:fs';
import * as path from 'node:path';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import type { SqlDb } from '../db/sql.js';
import { KeyWrapper } from './wrap.js';

/**
 * `ticket`: RSABSSA-SHA384-PSS-Randomized age keys (protocol 3.2), rotated.
 * `nullifier`: the long-lived RSABSSA-SHA384-PSSZERO-Deterministic key (4c.2).
 */
export type KeyPurpose = 'ticket' | 'nullifier';

/** Public facts about one signing key. The private part stays inside the key store. */
export interface TicketKeyInfo {
  /** Key ID, for example `v18-age18-20261109` or `v18-nullifier-1`. */
  kid: string;
  purpose: KeyPurpose;
  /** The age threshold this key stands for (`v18_min_age`); 0 for the nullifier key. */
  minAge: number;
  /** Signing starts at this time (epoch seconds). */
  nbf: number;
  /** Signing stops at this time (epoch seconds). */
  exp: number;
  modulusBits: number;
  publicJwk: { kty: 'RSA'; n: string; e: string };
}

export type KeySpec = Omit<TicketKeyInfo, 'publicJwk'>;

/**
 * Where signing keys live (protocol 3.2, 4c.7).
 *
 * The server only ever asks the store to make a key, list public keys,
 * blind-sign, or delete a key, so an HSM (PKCS#11 raw RSA) can implement
 * this interface directly.
 *
 *   - MemoryKeyStore: keys vanish on restart (tests).
 *   - FileKeyStore: plain JSON files in server/data/keys/ (DEV ONLY).
 *   - SqlKeyStore: in the database, each private key sealed by a KeyWrapper
 *     (V18_KEK or a KMS). Production default; shared by all server copies.
 */
export interface KeyStore {
  readonly kind: string;
  list(): Promise<TicketKeyInfo[]>;
  /**
   * Makes a key. If another server copy made the same key ID first, returns
   * that one instead (so all copies agree).
   */
  generate(spec: KeySpec): Promise<TicketKeyInfo>;
  /** RFC 9474 BlindSign (the raw RSA step, the same for both variants). */
  blindSign(kid: string, blindedMsg: Uint8Array): Promise<Uint8Array>;
  remove(kid: string): Promise<void>;
}

const RSA_PSS_SHA384 = { name: 'RSA-PSS', hash: 'SHA-384' } as const;

function suiteFor(purpose: KeyPurpose) {
  return purpose === 'nullifier' ? RSABSSA.SHA384.PSSZero.Deterministic() : RSABSSA.SHA384.PSS.Randomized();
}

async function makePair(spec: KeySpec): Promise<{ info: TicketKeyInfo; privateKey: CryptoKey }> {
  const pair = await RSABSSA.SHA384.generateKey({
    modulusLength: spec.modulusBits,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  });
  const pub = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
  if (!pub.n || !pub.e) throw new Error('Key export failed');
  return { info: { ...spec, publicJwk: { kty: 'RSA', n: pub.n, e: pub.e } }, privateKey: pair.privateKey };
}

interface HeldKey {
  info: TicketKeyInfo;
  privateKey: CryptoKey;
}

/** Shared code for stores that sign inside this Node process. */
abstract class InProcessKeyStore implements KeyStore {
  abstract readonly kind: string;
  protected keys = new Map<string, HeldKey>();

  async list(): Promise<TicketKeyInfo[]> {
    return [...this.keys.values()].map((k) => ({ ...k.info }));
  }

  async generate(spec: KeySpec): Promise<TicketKeyInfo> {
    const existing = this.keys.get(spec.kid);
    if (existing) return { ...existing.info };
    const { info, privateKey } = await makePair(spec);
    await this.persist(info, privateKey);
    this.keys.set(spec.kid, { info, privateKey });
    return { ...info };
  }

  async blindSign(kid: string, blindedMsg: Uint8Array): Promise<Uint8Array> {
    const held = this.keys.get(kid);
    if (!held) throw new Error(`Unknown key ${kid}`);
    return new Uint8Array(await suiteFor(held.info.purpose).blindSign(held.privateKey, blindedMsg));
  }

  async remove(kid: string): Promise<void> {
    this.keys.delete(kid);
    await this.unpersist(kid);
  }

  protected async persist(_info: TicketKeyInfo, _privateKey: CryptoKey): Promise<void> {}
  protected async unpersist(_kid: string): Promise<void> {}
}

/** Keys live only in memory. Used by tests. */
export class MemoryKeyStore extends InProcessKeyStore {
  readonly kind = 'memory';
}

interface KeyFile {
  version: 1;
  kid: string;
  purpose?: KeyPurpose;
  minAge: number;
  nbf: number;
  exp: number;
  modulusBits: number;
  publicJwk: { kty: 'RSA'; n: string; e: string };
  privateJwk: JsonWebKey;
}

const KID_FILE = /^(v18-age\d{1,2}-\d{8}|v18-nullifier-\d{1,3})\.json$/;

/**
 * DEV key store: one JSON file per key in a folder (default `server/data/keys/`).
 * The files hold PRIVATE keys in plain text, so the folder is gitignored and
 * written with owner-only permissions where the OS supports it. Production
 * uses SqlKeyStore with V18_KEK instead.
 */
export class FileKeyStore extends InProcessKeyStore {
  readonly kind = 'file';

  private constructor(private readonly dir: string) {
    super();
  }

  static async open(dir: string): Promise<FileKeyStore> {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const store = new FileKeyStore(dir);
    for (const name of fs.readdirSync(dir)) {
      if (!KID_FILE.test(name)) continue;
      const file = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')) as KeyFile;
      if (file.version !== 1 || `${file.kid}.json` !== name) {
        throw new Error(`Key file ${name} is not a V18 key file`);
      }
      const privateKey = await crypto.subtle.importKey('jwk', file.privateJwk, RSA_PSS_SHA384, true, ['sign']);
      const { privateJwk: _drop, version: _v, ...rest } = file;
      store.keys.set(file.kid, { info: { ...rest, purpose: rest.purpose ?? 'ticket' }, privateKey });
    }
    return store;
  }

  protected async persist(info: TicketKeyInfo, privateKey: CryptoKey): Promise<void> {
    const privateJwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;
    const file: KeyFile = { version: 1, ...info, privateJwk };
    const target = path.join(this.dir, `${info.kid}.json`);
    const tmp = `${target}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(file, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, target);
  }

  protected async unpersist(kid: string): Promise<void> {
    fs.rmSync(path.join(this.dir, `${kid}.json`), { force: true });
  }
}

/**
 * PRODUCTION key store: keys in the `signing_keys` table, every private key
 * sealed by a KeyWrapper (AES-256-GCM with V18_KEK, or a KMS). The plain
 * private key exists only in this process's memory. All server copies share
 * the table, so they publish the same JWKS.
 */
export class SqlKeyStore implements KeyStore {
  readonly kind: string;
  private cache = new Map<string, CryptoKey>();

  constructor(
    private readonly db: SqlDb,
    private readonly wrapper: KeyWrapper
  ) {
    this.kind = `db+${wrapper.kind}`;
  }

  async list(): Promise<TicketKeyInfo[]> {
    const rows = await this.db.all<{ info: string }>('SELECT info FROM signing_keys ORDER BY kid');
    return rows.map((r) => JSON.parse(r.info) as TicketKeyInfo);
  }

  async generate(spec: KeySpec): Promise<TicketKeyInfo> {
    const found = await this.db.get<{ info: string }>('SELECT info FROM signing_keys WHERE kid = ?', [spec.kid]);
    if (found) return JSON.parse(found.info) as TicketKeyInfo;
    const { info, privateKey } = await makePair(spec);
    const privateJwk = Buffer.from(JSON.stringify(await crypto.subtle.exportKey('jwk', privateKey)), 'utf8');
    const sealed = await this.wrapper.wrap(privateJwk, spec.kid);
    privateJwk.fill(0);
    const r = await this.db.run(
      `INSERT INTO signing_keys (kid, purpose, info, wrapped_private, created_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (kid) DO NOTHING`,
      [spec.kid, spec.purpose, JSON.stringify(info), sealed, Date.now()]
    );
    if (r.changes === 0) {
      // Another server copy won the race; use its key.
      const row = await this.db.get<{ info: string }>('SELECT info FROM signing_keys WHERE kid = ?', [spec.kid]);
      if (!row) throw new Error(`Key ${spec.kid} vanished`);
      return JSON.parse(row.info) as TicketKeyInfo;
    }
    this.cache.set(spec.kid, privateKey);
    return info;
  }

  private async privateKey(kid: string): Promise<{ key: CryptoKey; purpose: KeyPurpose }> {
    const row = await this.db.get<{ info: string; wrapped_private: string }>(
      'SELECT info, wrapped_private FROM signing_keys WHERE kid = ?',
      [kid]
    );
    if (!row) throw new Error(`Unknown key ${kid}`);
    const info = JSON.parse(row.info) as TicketKeyInfo;
    let key = this.cache.get(kid);
    if (!key) {
      const plain = await this.wrapper.unwrap(row.wrapped_private, kid);
      // Extractable only inside this process: @cloudflare/blindrsa-ts reads the key to do the raw RSA step.
      key = await crypto.subtle.importKey('jwk', JSON.parse(plain.toString('utf8')) as JsonWebKey, RSA_PSS_SHA384, true, ['sign']);
      plain.fill(0);
      this.cache.set(kid, key);
    }
    return { key, purpose: info.purpose };
  }

  async blindSign(kid: string, blindedMsg: Uint8Array): Promise<Uint8Array> {
    const { key, purpose } = await this.privateKey(kid);
    return new Uint8Array(await suiteFor(purpose).blindSign(key, blindedMsg));
  }

  async remove(kid: string): Promise<void> {
    this.cache.delete(kid);
    await this.db.run('DELETE FROM signing_keys WHERE kid = ?', [kid]);
  }

  /** Checks that every stored key opens with this wrapper (fails fast on a wrong V18_KEK). */
  async checkAll(): Promise<void> {
    for (const k of await this.list()) await this.privateKey(k.kid);
  }
}
