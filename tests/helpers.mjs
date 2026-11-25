// Shared helpers for the V18 product tests: start the real built server, act as a phone or PC
// (device key, age card, blind-signed ticket), and act as a website (create pairing sessions).
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { calculateJwkThumbprint } from 'jose';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.unref();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/**
 * Starts server/dist/index.js on a free port with its own empty data folder.
 * dev=false is real production mode: no test identities, encrypted keys, its own secrets.
 */
export async function startServer({ dev }) {
  const entry = path.join(ROOT, 'server', 'dist', 'index.js');
  if (!fs.existsSync(entry)) throw new Error('The server is not built yet. Run "npm run build" in the project folder first.');
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'v18-product-'));
  const base = `http://localhost:${port}`;
  const env = { ...process.env, PORT: String(port), V18_DATA_DIR: dataDir, V18_PUBLIC_URL: base };
  for (const k of ['V18_DEV_MODE', 'DATABASE_URL', 'V18_DATABASE_URL', 'V18_DB_PATH', 'DB_PATH', 'V18_KEY_DIR', 'V18_KEY_STORE']) delete env[k];
  if (dev) {
    env.V18_DEV_MODE = '1';
  } else {
    env.V18_KEK = crypto.randomBytes(32).toString('hex');
    env.V18_NULLIFIER_SECRET = crypto.randomBytes(32).toString('hex');
    env.V18_AADHAAR_NULLIFIER_SEED = BigInt('0x' + crypto.randomBytes(8).toString('hex')).toString();
  }
  const child = spawn(process.execPath, [entry], { cwd: path.join(ROOT, 'server'), env, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  child.stdout.on('data', (d) => (log += d));
  child.stderr.on('data', (d) => (log += d));
  const exited = new Promise((r) => child.once('exit', r));
  for (let i = 0; ; i++) {
    if (child.exitCode !== null) throw new Error(`The V18 server stopped while starting:\n${log}`);
    try {
      const r = await fetch(`${base}/v1/health`);
      if (r.ok) break;
    } catch {
      // not listening yet
    }
    if (i > 150) throw new Error(`The V18 server did not start within 30 seconds:\n${log}`);
    await sleep(200);
  }
  return {
    base,
    dataDir,
    log: () => log,
    async stop() {
      child.kill();
      await exited;
      for (let i = 0; i < 10; i++) {
        try {
          fs.rmSync(dataDir, { recursive: true, force: true });
          break;
        } catch {
          await sleep(300);
        }
      }
    },
  };
}

/** One HTTP call to the V18 API. Never throws on an error status. */
export async function api(base, method, route, body, headers = {}) {
  const res = await fetch(`${base}/v1${route}`, {
    method,
    headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { status: res.status, data, headers: res.headers };
}

/** Like api(), but fails the test with the server's answer when the status is not 2xx. */
export async function ok(base, method, route, body, headers) {
  const r = await api(base, method, route, body, headers);
  if (r.status < 200 || r.status >= 300) throw new Error(`${method} /v1${route} -> ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
}

export async function challenge(base) {
  return (await ok(base, 'POST', '/challenge')).challenge;
}

/** A device key, standing in for the phone's Keystore (ES256) or Windows Hello (RS256). */
export async function makeDevice({ rsa = false } = {}) {
  const { privateKey, publicKey } = rsa
    ? crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    : crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const full = publicKey.export({ format: 'jwk' });
  const alg = rsa ? 'RS256' : 'ES256';
  const pub = rsa ? { kty: 'RSA', n: full.n, e: full.e } : { kty: 'EC', crv: 'P-256', x: full.x, y: full.y };
  const thumbprint = await calculateJwkThumbprint(pub, 'sha256');
  const sign = (text) => {
    const data = Buffer.from(text, 'utf8');
    const sig = rsa
      ? crypto.sign('sha256', data, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING })
      : crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'der' });
    return { alg, sig: b64url(sig) };
  };
  return { alg, jwk: { ...pub, alg }, thumbprint, sign };
}

/** Asks for a test_dev age card (dev servers only). Returns the raw answer, so tests can check refusals. */
export async function requestTestCard(base, device, birthDate = '1990-01-01') {
  const c = await challenge(base);
  return api(base, 'POST', '/card/issue', {
    method: 'test_dev',
    challenge: c,
    devicePublicKey: device.jwk,
    deviceSignature: device.sign(`v18-card-issue\n${c}\n${device.thumbprint}`),
    proof: { testSubjectId: `product-test-${crypto.randomBytes(8).toString('hex')}`, birthDate },
  });
}

export async function testCard(base, device) {
  const r = await requestTestCard(base, device);
  if (r.status !== 201) throw new Error(`card/issue -> ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
}

/**
 * Makes a one-time ticket the way the apps do: build the message, blind it (RFC 9474),
 * get the blind signature with the card's device key, finalize. Returns { status, ticket, data }.
 */
export async function requestTicket(base, card, device, { origin, challenge: siteChallenge, minAge = 18 }) {
  const now = Math.floor(Date.now() / 1000);
  const { keys } = await ok(base, 'GET', '/keys');
  const key = keys
    .filter((k) => k.nbf <= now && now < k.exp && k.v18_min_age >= minAge)
    .sort((a, b) => a.v18_min_age - b.v18_min_age)[0];
  if (!key) throw new Error(`No current ticket key for ${minAge}+`);
  const payload = { v: 1, ticketId: b64url(crypto.randomBytes(16)), origin, challenge: siteChallenge, minAge, iat: now, expiresAt: now + 300 };
  const suite = RSABSSA.SHA384.PSS.Randomized();
  const publicKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: key.n, e: key.e }, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
  const prepared = suite.prepare(new TextEncoder().encode(JSON.stringify(payload)));
  const { blindedMsg, inv } = await suite.blind(publicKey, prepared);
  const blindedMessage = b64url(blindedMsg);
  const c = await challenge(base);
  const r = await api(base, 'POST', '/ticket/blind-sign', {
    cardId: card.cardId,
    challenge: c,
    keyId: key.kid,
    blindedMessage,
    deviceSignature: device.sign(`v18-ticket-request\n${card.cardId}\n${c}\n${key.kid}\n${blindedMessage}`),
  });
  if (r.status !== 200) return { status: r.status, data: r.data, ticket: null };
  const signature = await suite.finalize(publicKey, prepared, Buffer.from(r.data.blindSignature, 'base64url'), inv);
  return { status: 200, data: r.data, ticket: `${r.data.keyId}.${b64url(prepared)}.${b64url(signature)}`, payload };
}

/** A website's per-visit challenge (32 random bytes as hex, like the verify libraries make). */
export const siteChallenge = () => crypto.randomBytes(32).toString('hex');

/** Checks a ticket with the Python website library (sdk-web/verify-python). Returns { valid, code }. */
export function verifyWithPython(ticket, { base, origin, challenge: ch, minAge = 18 }) {
  const code = [
    'import json, sys',
    `sys.path.insert(0, ${JSON.stringify(path.join(ROOT, 'sdk-web', 'verify-python'))})`,
    'from v18_verify import V18Verifier',
    'a = json.loads(sys.stdin.read())',
    "v = V18Verifier(server_url=a['base'])",
    "r = v.verify_ticket(a['ticket'], expected_origin=a['origin'], expected_challenge=a['challenge'], min_age=a['minAge'])",
    "print(json.dumps({'valid': bool(r.valid), 'code': getattr(r, 'code', None)}))",
  ].join('\n');
  const py = process.platform === 'win32' ? 'python' : 'python3';
  const r = spawnSync(py, ['-c', code], { input: JSON.stringify({ ticket, base, origin, challenge: ch, minAge }), encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`Python verify library failed:\n${r.stderr}`);
  return JSON.parse(r.stdout.trim().split('\n').pop());
}
