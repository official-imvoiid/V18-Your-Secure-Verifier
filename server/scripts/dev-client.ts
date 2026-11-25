/**
 * V18 dev client: runs the whole happy path against a RUNNING dev server and
 * prints a valid ticket string. TEST USE ONLY.
 *
 *   npm run dev-client                                   # ticket for http://localhost:3000
 *   npm run dev-client -- --origin https://site.test --challenge abc123
 *   npm run dev-client -- --pair "<v18://verify?... deep link or session ID>"
 *   npm run dev-client -- --link "<v18://link?... deep link or link ID>"
 *
 * Options:
 *   --server <url>     V18 server (default http://localhost:8080; "/v1" optional)
 *   --origin <origin>  website origin for the ticket (default http://localhost:3000)
 *   --challenge <c>    the website's challenge (default: random)
 *   --min-age <n>      age the site asks for (default 18)
 *   --pair <x>         act as the phone for a QR hand-off: connect, make the ticket
 *                      for that session, and submit it
 *   --link <x>         act as the phone for a device link: approve it with this
 *                      run's new test card
 *   --rsa              use an RS256 device key (like Windows Hello) instead of ES256
 *   --quiet            print only the ticket
 *   --json             print one JSON object with the ticket and details
 *
 * Progress goes to stderr; the ticket (or JSON) goes to stdout.
 *
 * This file is written from PROTOCOL.md only (it imports nothing from
 * server/src), so it doubles as a reference client for the apps:
 *   1. device key: ES256 via Node crypto (or RS256 with --rsa)
 *   2. POST /v1/challenge, then POST /v1/card/issue with method "test_dev"
 *   3. GET /v1/keys, build the ticket message, RFC 9474 prepare + blind
 *      (@cloudflare/blindrsa-ts)
 *   4. POST /v1/challenge, then POST /v1/ticket/blind-sign with a device signature
 *   5. finalize, check the signature locally, print <keyId>.<prepared>.<signature>
 */
import * as crypto from 'node:crypto';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { calculateJwkThumbprint } from 'jose';

interface Args {
  server: string;
  origin: string;
  challenge: string;
  minAge: number;
  pair?: string;
  link?: string;
  rsa: boolean;
  quiet: boolean;
  json: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    server: 'http://localhost:8080',
    origin: 'http://localhost:3000',
    challenge: crypto.randomBytes(16).toString('hex'),
    minAge: 18,
    rsa: false,
    quiet: false,
    json: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined) fail(`${a} needs a value`);
      return v;
    };
    switch (a) {
      case '--server': args.server = value(); break;
      case '--origin': args.origin = value(); break;
      case '--challenge': args.challenge = value(); break;
      case '--min-age': args.minAge = Number(value()); break;
      case '--pair': args.pair = value(); break;
      case '--link': args.link = value(); break;
      case '--rsa': args.rsa = true; break;
      case '--quiet': args.quiet = true; break;
      case '--json': args.json = true; break;
      case '--help':
      case '-h':
        process.stdout.write('See the comment at the top of server/scripts/dev-client.ts\n');
        process.exit(0);
      default:
        fail(`Unknown option ${a} (try --help)`);
    }
  }
  args.server = args.server.replace(/\/+$/, '').replace(/\/v1$/, '');
  return args;
}

let QUIET = false;
function log(msg: string): void {
  if (!QUIET) process.stderr.write(`[dev-client] ${msg}\n`);
}
function fail(msg: string): never {
  process.stderr.write(`[dev-client] FAILED: ${msg}\n`);
  process.exit(1);
}

const b64url = (b: Uint8Array) => Buffer.from(b).toString('base64url');

async function call(server: string, method: string, path: string, body?: unknown): Promise<any> {
  let res: Response;
  try {
    res = await fetch(`${server}/v1${path}`, {
      method,
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (err) {
    fail(`cannot reach ${server} (${(err as Error).message}). Is the dev server running? (npm run dev)`);
  }
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) fail(`${method} /v1${path} -> ${res.status} ${typeof data === 'object' ? JSON.stringify(data) : data}`);
  return data;
}

/** A device key, standing in for the phone's Keystore or Windows Hello. */
async function makeDeviceKey(rsa: boolean) {
  const { privateKey, publicKey } = rsa
    ? crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    : crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const full = publicKey.export({ format: 'jwk' }) as Record<string, string>;
  const alg = rsa ? 'RS256' : 'ES256';
  const pub: Record<string, string> = rsa
    ? { kty: 'RSA', n: full.n, e: full.e }
    : { kty: 'EC', crv: 'P-256', x: full.x, y: full.y };
  const thumbprint = await calculateJwkThumbprint(pub as any, 'sha256');
  const sign = (signingString: string) => {
    const data = Buffer.from(signingString, 'utf8');
    const sig = rsa
      ? crypto.sign('sha256', data, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING })
      : crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'der' });
    return { alg, sig: b64url(sig) };
  };
  return { alg, jwk: { ...pub, alg }, thumbprint, sign };
}

/** Accepts a session/link ID or a v18:// deep link. */
function fromDeepLink(value: string, param: string): { id: string; params: URLSearchParams | null } {
  if (!value.startsWith('v18://')) return { id: value, params: null };
  const q = value.slice(value.indexOf('?') + 1);
  const params = new URLSearchParams(q);
  const id = params.get(param);
  if (!id) fail(`deep link has no "${param}" parameter`);
  return { id, params };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  QUIET = args.quiet || args.json;
  const { server } = args;

  const health = await call(server, 'GET', '/health');
  if (!health?.devMode) fail('the server is not in dev mode (start it with npm run dev). test_dev cards need V18_DEV_MODE=1.');
  log(`server ${server} is in TEST MODE`);

  // QR hand-off: take origin, challenge and minAge from the session.
  let sessionId: string | undefined;
  if (args.pair) {
    const { id, params } = fromDeepLink(args.pair, 'session');
    sessionId = id;
    if (params) {
      args.origin = params.get('origin') ?? args.origin;
      args.challenge = params.get('challenge') ?? args.challenge;
      args.minAge = Number(params.get('minAge') ?? args.minAge);
    } else {
      const s = await call(server, 'GET', `/pairing/${id}`);
      args.origin = s.origin;
      args.challenge = s.challenge;
      args.minAge = s.minAge;
    }
    await call(server, 'POST', `/pairing/${id}/connect`);
    log(`connected to pairing session ${id} for ${args.origin}`);
  }

  // 1-2. Device key and a test_dev age card.
  const device = await makeDeviceKey(args.rsa);
  const c1 = (await call(server, 'POST', '/challenge')).challenge as string;
  const card = await call(server, 'POST', '/card/issue', {
    method: 'test_dev',
    challenge: c1,
    devicePublicKey: device.jwk,
    deviceSignature: device.sign(`v18-card-issue\n${c1}\n${device.thumbprint}`),
    proof: { testSubjectId: `dev-client-${crypto.randomBytes(8).toString('hex')}`, birthDate: '1990-01-01' },
  });
  log(`TEST age card ${card.cardId} (${device.alg} device key), valid until ${card.validUntil}`);

  // Device link: approve with this card, then stop.
  if (args.link) {
    const { id } = fromDeepLink(args.link, 'id');
    const c = (await call(server, 'POST', '/challenge')).challenge as string;
    const r = await call(server, 'POST', `/card/link/${id}/approve`, {
      cardId: card.cardId,
      challenge: c,
      deviceSignature: device.sign(`v18-link-approve\n${card.cardId}\n${c}\n${id}`),
    });
    log(`approved device link ${id}; the other device's card is valid until ${r.validUntil}`);
    if (args.json) process.stdout.write(JSON.stringify({ linkId: id, status: r.status, validUntil: r.validUntil }) + '\n');
    else process.stdout.write(`approved ${id}\n`);
    return;
  }

  // 3. Pick the current key whose threshold covers the site's age (lowest such key).
  const nowSec = Math.floor(Date.now() / 1000);
  const { keys } = await call(server, 'GET', '/keys');
  const key = (keys as any[])
    .filter((k) => k.nbf <= nowSec && nowSec < k.exp && k.v18_min_age >= args.minAge && k.v18_min_age <= card.minAgeCertified)
    .sort((a, b) => a.v18_min_age - b.v18_min_age)[0];
  if (!key) fail(`no current key for age ${args.minAge}+ that a ${card.minAgeCertified}+ card may use`);

  const payload = {
    v: 1,
    ticketId: b64url(crypto.randomBytes(16)),
    origin: args.origin,
    challenge: args.challenge,
    minAge: args.minAge,
    iat: nowSec,
    expiresAt: nowSec + 300,
  };
  const suite = RSABSSA.SHA384.PSS.Randomized();
  // Import only {kty, n, e}: WebCrypto refuses a JWK whose "alg" is not PS384.
  const publicKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: key.n, e: key.e }, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
  const prepared = suite.prepare(new TextEncoder().encode(JSON.stringify(payload)));
  const { blindedMsg, inv } = await suite.blind(publicKey, prepared);
  const blindedMessage = b64url(blindedMsg);

  // 4. Ask for the blind signature, signed by the device key.
  const c2 = (await call(server, 'POST', '/challenge')).challenge as string;
  const signed = await call(server, 'POST', '/ticket/blind-sign', {
    cardId: card.cardId,
    challenge: c2,
    keyId: key.kid,
    blindedMessage,
    deviceSignature: device.sign(`v18-ticket-request\n${card.cardId}\n${c2}\n${key.kid}\n${blindedMessage}`),
  });

  // 5. Finalize (this also checks the signature) and double-check with Node crypto.
  const signature = await suite.finalize(publicKey, prepared, Buffer.from(signed.blindSignature, 'base64url'), inv);
  const ok = crypto.verify(
    'sha384',
    Buffer.from(prepared),
    {
      key: crypto.createPublicKey({ key: { kty: 'RSA', n: key.n, e: key.e }, format: 'jwk' }),
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 48,
    },
    Buffer.from(signature)
  );
  if (!ok) fail('the finished signature does not verify');
  const ticket = `${signed.keyId}.${b64url(prepared)}.${b64url(signature)}`;
  log(`ticket for ${args.origin} (challenge ${args.challenge}), key ${signed.keyId}, expires in 300 s`);

  if (sessionId) {
    await call(server, 'POST', `/pairing/${sessionId}/submit`, { ticket });
    log(`submitted the ticket to pairing session ${sessionId}`);
  }

  if (args.json) {
    process.stdout.write(JSON.stringify({ ticket, keyId: signed.keyId, cardId: card.cardId, payload, pairingSession: sessionId ?? null }) + '\n');
  } else {
    process.stdout.write(ticket + '\n');
  }
}

main().catch((err: unknown) => fail(err instanceof Error ? err.message : String(err)));
