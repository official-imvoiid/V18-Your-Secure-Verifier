/**
 * BROWSER TEST WALLET (DEV ONLY). Not a real V18 app.
 *
 * It plays the part of the phone app, inside the browser, so you can try the whole protocol without
 * a phone. It follows PROTOCOL.md exactly:
 *   - a WebCrypto ES256 device key (non-extractable private key),
 *   - a `test_dev` age card (works only on a V18 server in dev mode; the birth date is test data),
 *   - a ticket made with RFC 9474 blind signatures (@cloudflare/blindrsa-ts), with a device
 *     signature on every request.
 * A browser key is NOT hardware-backed and there is no fingerprint check, which is why this is test only.
 *
 * Runs in browsers and in Node 22 (both have fetch and crypto.subtle), so the demo-site tests use it too.
 */
import { RSABSSA } from '@cloudflare/blindrsa-ts';

export const ALG = 'RSABSSA-SHA384-PSS-Randomized';
export const ADULT_TEST_BIRTH_DATE = '1990-01-01';
export const CHILD_TEST_BIRTH_DATE = '2012-06-01';

export interface StoredCard {
  serverUrl: string;
  cardId: string;
  method: string;
  minAgeCertified: number;
  validUntil: string;
  birthDate: string;
  testSubjectId: string;
  privateKey: CryptoKey;
  publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  thumbprint: string;
}

export interface WalletStorage {
  load(): Promise<StoredCard | null>;
  save(card: StoredCard): Promise<void>;
  clear(): Promise<void>;
}

export class MemoryStorage implements WalletStorage {
  private card: StoredCard | null = null;
  async load() { return this.card; }
  async save(c: StoredCard) { this.card = c; }
  async clear() { this.card = null; }
}

export type LogKind = 'step' | 'ok' | 'err' | 'data';
export type Logger = (kind: LogKind, text: string) => void;

export class V18ApiError extends Error {
  constructor(message: string, public readonly code: string | undefined, public readonly status: number) {
    super(code ? `${code}: ${message}` : message);
    this.name = 'V18ApiError';
  }
}

// ------------------------------------------------------------------ small helpers

const te = new TextEncoder();

export function b64u(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64u(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}

const short = (s: string, n = 18) => (s.length > n * 2 ? `${s.slice(0, n)}…${s.slice(-6)}` : s);

/** RFC 7638 JWK thumbprint for an EC P-256 key: SHA-256 over {"crv","kty","x","y"} in that order. */
export async function ecThumbprint(jwk: { crv: string; kty: string; x: string; y: string }): Promise<string> {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return b64u(await crypto.subtle.digest('SHA-256', te.encode(canonical)));
}

/** The signing strings from PROTOCOL.md 3.4 (fields joined with \n, no trailing newline). */
export const signingString = {
  cardIssue: (challenge: string, thumbprint: string) => ['v18-card-issue', challenge, thumbprint].join('\n'),
  ticketRequest: (cardId: string, challenge: string, keyId: string, blindedMessage: string) =>
    ['v18-ticket-request', cardId, challenge, keyId, blindedMessage].join('\n'),
  cardDelete: (cardId: string, challenge: string) => ['v18-card-delete', cardId, challenge].join('\n'),
};

/** ES256 device signature: WebCrypto gives raw 64-byte r||s, which the protocol allows. */
async function deviceSign(privateKey: CryptoKey, text: string): Promise<{ alg: 'ES256'; sig: string }> {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, te.encode(text));
  return { alg: 'ES256', sig: b64u(sig) };
}

function randomHexId(bytes = 12): string {
  const u8 = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ------------------------------------------------------------------ the wallet

export interface TestWalletOptions {
  serverUrl: string;
  storage?: WalletStorage;
  fetch?: typeof fetch;
  log?: Logger;
  /** Test birth date for new cards. Default an adult date. */
  birthDate?: string;
}

export class TestWalletCore {
  public readonly serverUrl: string;
  private readonly storage: WalletStorage;
  private readonly fetchFn: typeof fetch;
  private log: Logger;
  public birthDate: string;
  private readonly suite = RSABSSA.SHA384.PSS.Randomized();

  constructor(opts: TestWalletOptions) {
    this.serverUrl = opts.serverUrl.replace(/\/+$/, '').replace(/\/v1$/, '');
    this.storage = opts.storage ?? new MemoryStorage();
    this.fetchFn = opts.fetch ?? ((...a: Parameters<typeof fetch>) => globalThis.fetch(...a));
    this.log = opts.log ?? (() => {});
    this.birthDate = opts.birthDate ?? ADULT_TEST_BIRTH_DATE;
  }

  public setLogger(log: Logger): void {
    this.log = log;
  }

  private async api(method: string, path: string, body?: unknown): Promise<any> {
    let res: Response;
    try {
      res = await this.fetchFn(`${this.serverUrl}/v1${path}`, {
        method,
        headers: body !== undefined ? { 'Content-Type': 'application/json', accept: 'application/json' } : { accept: 'application/json' },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e: any) {
      throw new V18ApiError(`Could not reach the V18 server at ${this.serverUrl} (${e?.message ?? e})`, 'NETWORK', 0);
    }
    const data: any = await res.json().catch(() => null);
    if (!res.ok) throw new V18ApiError(data?.error ?? `HTTP ${res.status}`, data?.code, res.status);
    return data;
  }

  public async health(): Promise<{ devMode: boolean; raw: any }> {
    const raw = await this.api('GET', '/health');
    return { devMode: raw?.devMode === true, raw };
  }

  private async freshChallenge(purpose: string): Promise<string> {
    const { challenge } = await this.api('POST', '/challenge');
    if (typeof challenge !== 'string') throw new V18ApiError('V18 sent no challenge', 'BAD_REPLY', 200);
    this.log('data', `V18 challenge for ${purpose}: ${short(challenge)}`);
    return challenge;
  }

  public async currentCard(): Promise<StoredCard | null> {
    const c = await this.storage.load();
    return c && c.serverUrl === this.serverUrl ? c : null;
  }

  /** Returns an active test card, making a new one if needed. */
  public async ensureCard(): Promise<StoredCard> {
    const stored = await this.currentCard();
    if (stored && stored.birthDate === this.birthDate) {
      try {
        const st = await this.api('GET', `/card/${encodeURIComponent(stored.cardId)}/status`);
        if (st?.status === 'active') {
          this.log('ok', `Using the saved test age card ${short(stored.cardId)} (valid until ${String(st.validUntil ?? stored.validUntil).slice(0, 10)})`);
          return stored;
        }
        this.log('step', `Saved card is ${st?.status ?? 'unknown'}; making a new one`);
      } catch (e: any) {
        if (!(e instanceof V18ApiError) || e.status !== 404) throw e;
        this.log('step', 'Saved card is unknown to this V18 server; making a new one');
      }
      await this.storage.clear();
    } else if (stored) {
      this.log('step', 'Test birth date changed; deleting the old test card first');
      await this.deleteCard().catch(() => this.storage.clear());
    }
    return this.issueCard();
  }

  private async issueCard(retryOnOveruse = true, subjectId?: string): Promise<StoredCard> {
    this.log('step', '1. Making a device key in this browser (WebCrypto ES256, private key not extractable)');
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
    const publicJwk = { kty: 'EC' as const, crv: 'P-256' as const, x: jwk.x!, y: jwk.y! };
    const thumbprint = await ecThumbprint(publicJwk);
    this.log('data', `Device key thumbprint (RFC 7638): ${thumbprint}`);

    const challenge = await this.freshChallenge('the card');
    const deviceSignature = await deviceSign(pair.privateKey, signingString.cardIssue(challenge, thumbprint));
    this.log('data', `Signed "v18-card-issue\\n<challenge>\\n<thumbprint>" -> ${short(deviceSignature.sig)}`);

    const testSubjectId = subjectId ?? `browser-test-${randomHexId()}`;
    this.log('step', `2. Asking V18 for a test_dev age card (TEST DATA: birth date ${this.birthDate})`);
    let card: any;
    try {
      card = await this.api('POST', '/card/issue', {
        method: 'test_dev',
        challenge,
        devicePublicKey: { ...publicJwk, alg: 'ES256' },
        deviceSignature,
        proof: { testSubjectId, birthDate: this.birthDate },
      });
    } catch (e: any) {
      if (retryOnOveruse && e instanceof V18ApiError && e.code === 'NULLIFIER_OVERUSED') {
        this.log('step', 'This test subject already has the most cards allowed; trying a new test subject');
        return this.issueCard(false);
      }
      throw e;
    }
    const stored: StoredCard = {
      serverUrl: this.serverUrl,
      cardId: card.cardId,
      method: card.method ?? 'test_dev',
      minAgeCertified: Number.isInteger(card.minAgeCertified) ? card.minAgeCertified : 18,
      validUntil: card.validUntil,
      birthDate: this.birthDate,
      testSubjectId,
      privateKey: pair.privateKey,
      publicJwk,
      thumbprint,
    };
    await this.storage.save(stored);
    this.log('ok', `Age card ${short(stored.cardId)} issued: ${stored.minAgeCertified}+, valid until ${String(stored.validUntil).slice(0, 10)}`);
    return stored;
  }

  /** Picks the current ticket key: nbf <= now <= exp, v18_min_age >= minAge and <= the card's age. */
  public async pickKey(minAge: number, card: StoredCard): Promise<{ kid: string; jwk: any; minAge: number }> {
    const jwks = await this.api('GET', '/keys');
    const now = Math.floor(Date.now() / 1000);
    const usable = (jwks?.keys ?? []).filter(
      (k: any) =>
        k?.kty === 'RSA' && k.alg === ALG && Number.isInteger(k.v18_min_age) &&
        k.v18_min_age >= minAge && k.v18_min_age <= card.minAgeCertified &&
        Number.isInteger(k.nbf) && Number.isInteger(k.exp) && k.nbf <= now && now <= k.exp
    );
    if (usable.length === 0) throw new V18ApiError(`No current ${minAge}+ ticket key in the V18 JWKS`, 'NO_KEY', 200);
    usable.sort((a: any, b: any) => a.v18_min_age - b.v18_min_age || b.nbf - a.nbf);
    const k = usable[0];
    return { kid: k.kid, jwk: k, minAge: k.v18_min_age };
  }

  /** Makes a one-time ticket for a website (PROTOCOL.md 3.6). */
  public async makeTicket(site: { origin: string; challenge: string; minAge: number }): Promise<string> {
    const card = await this.ensureCard();
    const key = await this.pickKey(site.minAge, card);
    this.log('data', `Ticket key from JWKS: ${key.kid} (v18_min_age ${key.minAge})`);

    const publicKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: key.jwk.n, e: key.jwk.e, ext: true },
      { name: 'RSA-PSS', hash: 'SHA-384' },
      true,
      ['verify']
    );

    const iat = Math.floor(Date.now() / 1000);
    const message = {
      v: 1,
      ticketId: b64u(crypto.getRandomValues(new Uint8Array(16))),
      origin: site.origin,
      challenge: site.challenge,
      minAge: key.minAge,
      iat,
      expiresAt: iat + 300,
    };
    this.log('step', `3. Writing the ticket message on this device (V18 never sees it): ${JSON.stringify(message)}`);

    const prepared = this.suite.prepare(te.encode(JSON.stringify(message)));
    const { blindedMsg, inv } = await this.suite.blind(publicKey, prepared);
    const blindedMessage = b64u(blindedMsg);
    this.log('data', `Blinded (RFC 9474): ${short(blindedMessage, 24)}  (looks random to V18)`);

    const challenge = await this.freshChallenge('the ticket');
    const deviceSignature = await deviceSign(
      card.privateKey,
      signingString.ticketRequest(card.cardId, challenge, key.kid, blindedMessage)
    );
    this.log('step', '4. Asking V18 to blind-sign, with the card ID and a device signature');
    const res = await this.api('POST', '/ticket/blind-sign', {
      cardId: card.cardId,
      challenge,
      keyId: key.kid,
      blindedMessage,
      deviceSignature,
    });
    if (res.keyId && res.keyId !== key.kid) throw new V18ApiError('V18 signed with a different key than asked', 'KEY_MISMATCH', 200);
    this.log('data', `Blind signature from V18: ${short(res.blindSignature, 24)}`);

    const sig = await this.suite.finalize(publicKey, prepared, fromB64u(res.blindSignature), inv);
    const ticket = `${key.kid}.${b64u(prepared)}.${b64u(sig)}`;
    this.log('ok', `5. Unblinded and checked: a normal RSA-PSS signature. Ticket: ${short(ticket, 28)}`);
    return ticket;
  }

  /** Acts as the phone for a QR hand-off session: connect, make a real ticket, submit it. */
  public async simulatePhone(s: { sessionId: string; origin: string; challenge: string; minAge: number; onProgress?: (m: string) => void }): Promise<void> {
    const id = encodeURIComponent(s.sessionId);
    s.onProgress?.('Connecting to the hand-off session…');
    this.log('step', `Test wallet acting as the phone for hand-off session ${short(s.sessionId)}`);
    await this.api('POST', `/pairing/${id}/connect`, {});
    this.log('ok', 'Connected to the hand-off session');
    s.onProgress?.('Getting a test age card and a real ticket…');
    const ticket = await this.makeTicket({ origin: s.origin, challenge: s.challenge, minAge: s.minAge });
    s.onProgress?.('Sending the ticket to the hand-off session…');
    await this.api('POST', `/pairing/${id}/submit`, { ticket });
    this.log('ok', 'Ticket submitted to the hand-off session. The widget picks it up on its next poll.');
  }

  /** Deletes the test card on the server (frees its nullifier slot) and forgets it here. */
  public async deleteCard(): Promise<boolean> {
    const card = await this.currentCard();
    if (!card) {
      await this.storage.clear();
      return false;
    }
    try {
      const challenge = await this.freshChallenge('deleting the card');
      const deviceSignature = await deviceSign(card.privateKey, signingString.cardDelete(card.cardId, challenge));
      await this.api('DELETE', `/card/${encodeURIComponent(card.cardId)}`, { challenge, deviceSignature });
      this.log('ok', `Test card ${short(card.cardId)} deleted on the V18 server`);
    } finally {
      await this.storage.clear();
    }
    return true;
  }
}
