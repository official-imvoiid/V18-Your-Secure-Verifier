/**
 * Swedish BankID, through BankID's own relying party API v6.0 (developers.bankid.com).
 *
 * BankID is not OIDC. The documented flow is:
 *   1. POST /auth { endUserIp, returnUrl } over mutual TLS -> orderRef, autoStartToken, qrStartToken, qrStartSecret
 *   2. Same device: open https://app.bankid.com/?autostarttoken=<token>. When the person is done,
 *      the BankID app opens `returnUrl` (our callback, carrying `state`).
 *      Other device (a PC): show the animated QR code (see `bankIdQrData`).
 *   3. POST /collect { orderRef } every 2 seconds until `complete` or `failed`.
 *      `completionData.user.personalNumber` (12 digits, YYYYMMDDNNNN) gives the birth date.
 *
 * The personal number is the subject (only for the nullifier HMAC). Name, signature and the
 * OCSP response in completionData are ignored and dropped.
 */
import { request as httpsRequest } from 'node:https';
import { readFileSync } from 'node:fs';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { birthDateFromSwedishPersonalNumber } from '../age.js';
import { envValue, inlineOrFile } from '../config.js';
import { decide } from '../oidc.js';
import {
  ConnectorError,
  type AuthStart,
  type AuthStartParams,
  type CallbackParams,
  type Connector,
  type ConnectorOptions,
  type ConnectorResult,
  type Env,
} from '../types.js';

const ID = 'bankid_se' as const;
export const BANKID_PRODUCTION_API = 'https://appapi2.bankid.com/rp/v6.0';
export const BANKID_TEST_API = 'https://appapi2.test.bankid.com/rp/v6.0';

interface BankIdSession {
  orderRef: string;
  qrStartToken: string;
  qrStartSecret: string;
  /** When /auth answered (ms since 1970), for the QR time counter. */
  startedAt: number;
}

interface TlsMaterial {
  pfx?: Buffer;
  passphrase?: string;
  cert?: string;
  key?: string;
  ca: string;
}

function readMaybeFile(value: string): Buffer {
  return value.trim().startsWith('-----BEGIN') ? Buffer.from(value) : readFileSync(value.trim());
}

function tls(env: Env): TlsMaterial {
  const ca = envValue(env, ID, 'CA');
  const pfx = envValue(env, ID, 'PFX');
  const cert = envValue(env, ID, 'CERT');
  const key = envValue(env, ID, 'KEY');
  if (!ca || (!pfx && !(cert && key))) throw new ConnectorError(ID, 'NOT_CONFIGURED', 'BankID is not set up on this server.');
  return {
    ca: inlineOrFile(ca),
    pfx: pfx ? readMaybeFile(pfx) : undefined,
    passphrase: envValue(env, ID, 'PASSPHRASE'),
    cert: cert ? inlineOrFile(cert) : undefined,
    key: key ? inlineOrFile(key) : undefined,
  };
}

function postJson(url: string, body: unknown, material: TlsMaterial): Promise<{ status: number; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = httpsRequest(
      url,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': data.length },
        ca: material.ca,
        pfx: material.pfx,
        passphrase: material.passphrase,
        cert: material.cert,
        key: material.key,
        timeout: 15_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          let json: Record<string, unknown> = {};
          try {
            json = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, unknown>;
          } catch {
            /* not JSON */
          }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end(data);
  });
}

/**
 * The text for the animated QR code (other-device flow), from BankID's documented formula:
 * "bankid." + qrStartToken + "." + seconds since the order started + "." + HMAC-SHA256(qrStartSecret, seconds) in hex.
 * Show a new code every second. The server can use this for a QR page for Windows users.
 */
export function bankIdQrData(session: string, nowMs: number = Date.now()): string {
  const s = JSON.parse(session) as BankIdSession;
  const time = Math.max(0, Math.floor((nowMs - s.startedAt) / 1000));
  const code = createHmac('sha256', s.qrStartSecret).update(String(time)).digest('hex');
  return `bankid.${s.qrStartToken}.${time}.${code}`;
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function sameText(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function createBankIdSe(env: Env, options: ConnectorOptions = {}): Connector {
  const now = options.now ?? (() => new Date());
  const poll = options.bankidPoll ?? { intervalMs: 2000, attempts: 10 };
  const api = (envValue(env, ID, 'API_URL') ?? BANKID_PRODUCTION_API).replace(/\/+$/, '');
  const fail = (code: ConstructorParameters<typeof ConnectorError>[1], message: string, providerCode?: string) =>
    new ConnectorError(ID, code, message, providerCode);

  async function call(path: string, body: unknown) {
    let res;
    try {
      res = await postJson(`${api}${path}`, body, tls(env));
    } catch (err) {
      if (err instanceof ConnectorError) throw err;
      throw fail('INVALID_RESPONSE', 'Could not reach BankID.', 'network');
    }
    if (res.status !== 200) {
      const code = typeof res.json.errorCode === 'string' ? res.json.errorCode : `http_${res.status}`;
      throw fail('INVALID_RESPONSE', 'BankID refused the request.', code);
    }
    return res.json;
  }

  return {
    id: ID,
    label: 'BankID (Sweden)',
    countries: ['SE'],
    assurance: 'high',
    callbackMethod: 'GET',

    isConfigured(e: Env) {
      return envValue(e, ID, 'CA') !== undefined && (envValue(e, ID, 'PFX') !== undefined || (envValue(e, ID, 'CERT') !== undefined && envValue(e, ID, 'KEY') !== undefined));
    },

    async buildAuthUrl(p: AuthStartParams): Promise<AuthStart> {
      if (!p.endUserIp || isIP(p.endUserIp) === 0) throw fail('BAD_REQUEST', 'BankID needs the person’s IP address (endUserIp).');
      if (typeof p.state !== 'string' || p.state.length < 16) throw fail('BAD_REQUEST', 'state must be at least 16 characters.');
      let returnUrl: URL;
      try {
        returnUrl = new URL(p.redirectUri);
      } catch {
        throw fail('BAD_REQUEST', 'redirectUri must be a full URL.');
      }
      returnUrl.searchParams.set('state', p.state);
      const json = await call('/auth', {
        endUserIp: p.endUserIp,
        returnUrl: returnUrl.href,
        userVisibleData: Buffer.from('V18 age check: only "18 or older" is shared.').toString('base64'),
      });
      const { orderRef, autoStartToken, qrStartToken, qrStartSecret } = json;
      if (![orderRef, autoStartToken, qrStartToken, qrStartSecret].every((v) => typeof v === 'string' && v !== '')) {
        throw fail('INVALID_RESPONSE', 'BankID sent an unexpected answer.');
      }
      const session: BankIdSession = {
        orderRef: orderRef as string,
        qrStartToken: qrStartToken as string,
        qrStartSecret: qrStartSecret as string,
        startedAt: Date.now(),
      };
      const authUrl = `https://app.bankid.com/?autostarttoken=${encodeURIComponent(autoStartToken as string)}`;
      return { authUrl, session: JSON.stringify(session) };
    },

    async handleCallback(c: CallbackParams): Promise<ConnectorResult> {
      const state = c.params?.state;
      if (typeof state !== 'string' || !sameText(state, c.state)) throw fail('STATE_MISMATCH', 'The login answer does not belong to this session.');
      let session: BankIdSession;
      try {
        session = JSON.parse(c.session ?? '') as BankIdSession;
      } catch {
        throw fail('INVALID_RESPONSE', 'The saved BankID session is missing.');
      }
      if (typeof session.orderRef !== 'string') throw fail('INVALID_RESPONSE', 'The saved BankID session is missing.');

      for (let i = 0; i < poll.attempts; i++) {
        const json = await call('/collect', { orderRef: session.orderRef });
        if (json.status === 'complete') {
          const completion = json.completionData as { user?: { personalNumber?: unknown } } | undefined;
          const pnr = completion?.user?.personalNumber;
          return decide(ID, { subject: typeof pnr === 'string' ? pnr : undefined, birthDate: birthDateFromSwedishPersonalNumber(pnr) }, now());
        }
        if (json.status === 'failed') {
          throw fail('PROVIDER_ERROR', 'The BankID login was cancelled or failed.', typeof json.hintCode === 'string' ? json.hintCode : 'failed');
        }
        if (json.status !== 'pending') throw fail('INVALID_RESPONSE', 'BankID sent an unexpected answer.');
        if (i < poll.attempts - 1) await sleep(poll.intervalMs);
      }
      throw fail('PENDING', 'The BankID login is not finished yet.', 'pending');
    },
  };
}
