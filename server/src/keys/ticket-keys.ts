import * as nodeCrypto from 'node:crypto';
import { ApiError } from '../errors.js';
import { Clock, systemClock } from '../util.js';
import { KeyStore, TicketKeyInfo } from './keystore.js';

export const TICKET_ALGORITHM = 'RSABSSA-SHA384-PSS-Randomized';
const DAY = 86_400;

export interface TicketJwk {
  kty: 'RSA';
  kid: string;
  use: 'sig';
  alg: typeof TICKET_ALGORITHM;
  n: string;
  e: string;
  v18_min_age: number;
  nbf: number;
  exp: number;
}

interface ThresholdKeys {
  previous?: TicketKeyInfo;
  current: TicketKeyInfo;
  next: TicketKeyInfo;
}

/** `v18-age18-20261109`: age threshold plus the UTC start date of the key. */
export function keyIdFor(minAge: number, nbfSeconds: number): string {
  const d = new Date(nbfSeconds * 1000);
  const ymd =
    d.getUTCFullYear().toString().padStart(4, '0') +
    (d.getUTCMonth() + 1).toString().padStart(2, '0') +
    d.getUTCDate().toString().padStart(2, '0');
  return `v18-age${minAge}-${ymd}`;
}

/**
 * Ticket signing keys: one key per age threshold and period (protocol 3.2).
 *
 * Each threshold has a chain of keys. A key signs from `nbf` until `exp`
 * (`V18_KEY_ROTATION_DAYS` long), then the next key takes over. The JWKS
 * lists the previous, current and next keys, so websites can cache it.
 * Keys come from a `KeyStore`, so they survive restarts when the store does.
 */
export class TicketKeyService {
  private state = new Map<number, ThresholdKeys>();
  private refreshing: Promise<void> | null = null;
  private readonly timer: NodeJS.Timeout;

  constructor(
    private readonly store: KeyStore,
    private readonly opts: { thresholds: number[]; rotationDays: number; modulusBits: number },
    private readonly clock: Clock = systemClock
  ) {
    // Rotate on time even when nobody calls the server.
    this.timer = setInterval(() => {
      this.refresh().catch((err) => console.error('[v18] key rotation failed:', (err as Error).message));
    }, 60_000);
    this.timer.unref();
  }

  get storeKind(): string {
    return this.store.kind;
  }

  private nowSeconds(): number {
    return Math.floor(this.clock() / 1000);
  }

  private isFresh(): boolean {
    if (this.state.size !== this.opts.thresholds.length) return false;
    const now = this.nowSeconds();
    for (const s of this.state.values()) {
      if (!(s.current.nbf <= now && now < s.current.exp)) return false;
    }
    return true;
  }

  /** Makes sure every threshold has a current and a next key. Cheap when nothing changed. */
  async refresh(): Promise<void> {
    if (this.isFresh()) return;
    if (!this.refreshing) {
      this.refreshing = this.doRefresh().finally(() => {
        this.refreshing = null;
      });
    }
    await this.refreshing;
  }

  private async doRefresh(): Promise<void> {
    const now = this.nowSeconds();
    const period = this.opts.rotationDays * DAY;
    const all = (await this.store.list()).filter((k) => (k.purpose ?? 'ticket') === 'ticket');
    const keep = new Set<string>();
    const nextState = new Map<number, ThresholdKeys>();

    for (const minAge of this.opts.thresholds) {
      const keys = all.filter((k) => k.minAge === minAge).sort((a, b) => a.nbf - b.nbf);
      const make = async (nbf: number, exp: number): Promise<TicketKeyInfo> => {
        const kid = keyIdFor(minAge, nbf);
        const clash = all.find((k) => k.kid === kid);
        if (clash) {
          // Only possible if the clock moved backwards a lot. Drop the stale key.
          await this.store.remove(kid);
          const i = keys.findIndex((k) => k.kid === kid);
          if (i >= 0) keys.splice(i, 1);
        }
        const info = await this.store.generate({ kid, purpose: 'ticket', minAge, nbf, exp, modulusBits: this.opts.modulusBits });
        keys.push(info);
        return info;
      };

      let current = keys.find((k) => k.nbf <= now && now < k.exp);
      if (!current) {
        const nbf = now - (now % DAY); // start of today (UTC)
        current = await make(nbf, nbf + period);
      }
      const cur = current;
      const next = keys.find((k) => k.nbf === cur.exp) ?? (await make(cur.exp, cur.exp + period));
      const previous = keys.find((k) => k.exp === cur.nbf);

      nextState.set(minAge, { previous, current: cur, next });
      for (const k of [previous, cur, next]) if (k) keep.add(k.kid);
    }

    // Delete ticket keys that are no longer published (older than "previous").
    // Other keys (the nullifier key) are never touched here.
    for (const k of await this.store.list()) {
      if ((k.purpose ?? 'ticket') === 'ticket' && !keep.has(k.kid)) await this.store.remove(k.kid);
    }
    this.state = nextState;
  }

  /** Every published key (previous, current, next) for every threshold. */
  published(): TicketKeyInfo[] {
    const out: TicketKeyInfo[] = [];
    for (const minAge of [...this.opts.thresholds].sort((a, b) => a - b)) {
      const s = this.state.get(minAge);
      if (!s) continue;
      if (s.previous) out.push(s.previous);
      out.push(s.current, s.next);
    }
    return out;
  }

  jwks(): { keys: TicketJwk[] } {
    return { keys: this.published().map(toJwk) };
  }

  find(kid: string): TicketKeyInfo | undefined {
    return this.published().find((k) => k.kid === kid);
  }

  isCurrent(key: TicketKeyInfo): boolean {
    const now = this.nowSeconds();
    return key.nbf <= now && now < key.exp;
  }

  /** The lowest configured age threshold at or above `minAge`. */
  thresholdFor(minAge: number): number {
    const t = [...this.opts.thresholds].sort((a, b) => a - b).find((x) => x >= minAge);
    if (t === undefined) throw new ApiError(400, 'MIN_AGE_UNSUPPORTED', `This server has no ticket key for age ${minAge}+`);
    return t;
  }

  /** The current key for a threshold (default: 18, or the lowest configured one). */
  currentKey(minAge?: number): TicketKeyInfo {
    const age = minAge ?? (this.opts.thresholds.includes(18) ? 18 : Math.min(...this.opts.thresholds));
    const s = this.state.get(age);
    if (!s) throw new ApiError(404, 'KEY_NOT_FOUND', `No ticket key for age ${age}`);
    return s.current;
  }

  pem(kid?: string): string {
    const key = kid ? this.find(kid) : this.currentKey();
    if (!key) throw new ApiError(404, 'KEY_NOT_FOUND', `Key ${kid} is not in the JWKS`);
    return nodeCrypto
      .createPublicKey({ key: key.publicJwk, format: 'jwk' })
      .export({ type: 'spki', format: 'pem' })
      .toString();
  }

  /**
   * Blind-signs with a published key. Checks the blinded message is exactly
   * the modulus length and smaller than the modulus (RFC 9474 input rules).
   */
  async blindSign(key: TicketKeyInfo, blinded: Uint8Array): Promise<Uint8Array> {
    const kLen = Math.ceil(key.modulusBits / 8);
    if (blinded.length !== kLen) {
      throw new ApiError(400, 'BAD_BLINDED_MESSAGE', `blindedMessage must be ${kLen} bytes for key ${key.kid}`);
    }
    const m = BigInt('0x' + Buffer.from(blinded).toString('hex'));
    const n = BigInt('0x' + Buffer.from(key.publicJwk.n, 'base64url').toString('hex'));
    if (m === 0n || m >= n) {
      throw new ApiError(400, 'BAD_BLINDED_MESSAGE', 'blindedMessage is out of range for this key');
    }
    return this.store.blindSign(key.kid, blinded);
  }

  close(): void {
    clearInterval(this.timer);
  }
}

export function toJwk(k: TicketKeyInfo): TicketJwk {
  return {
    kty: 'RSA',
    kid: k.kid,
    use: 'sig',
    alg: TICKET_ALGORITHM,
    n: k.publicJwk.n,
    e: k.publicJwk.e,
    v18_min_age: k.minAge,
    nbf: k.nbf,
    exp: k.exp,
  };
}
