// Makes sdk-web/test-vectors/v1-tickets.json: real RFC 9474 tickets (via @cloudflare/blindrsa-ts)
// that BOTH verify libraries (Node and Python) must judge the same way.
// Run from sdk-web/verify-node:  node scripts/make-vectors.mjs
// Test data only: the private keys are thrown away and never written to disk.
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { RSABSSA } from '@cloudflare/blindrsa-ts';

const suite = RSABSSA.SHA384.PSS.Randomized();
const NOW = 1762700000;
const ORIGIN = 'https://example-site.test';
const CHAL = 'c'.repeat(64);
const b64u = (b) => Buffer.from(b).toString('base64url');

async function key(kid, { minAge = 18, nbf = NOW - 86400, exp = NOW + 6 * 86400, omit = [] } = {}) {
  const pair = await suite.generateKey({ modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) });
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const jwk = { kid, kty: 'RSA', n: pub.n, e: pub.e, use: 'sig', alg: 'RSABSSA-SHA384-PSS-Randomized', v18_min_age: minAge, nbf, exp };
  for (const k of omit) delete jwk[k];
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  const nodePriv = crypto.createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
  return { kid, pair, jwk, nodePriv };
}

function body(over = {}) {
  return { v: 1, ticketId: b64u(crypto.randomBytes(16)), origin: ORIGIN, challenge: CHAL, minAge: 18, iat: NOW, expiresAt: NOW + 300, ...over };
}

async function blind(k, b) {
  const msg = typeof b === 'string' ? new TextEncoder().encode(b) : new TextEncoder().encode(JSON.stringify(b));
  const prepared = suite.prepare(msg);
  const { blindedMsg, inv } = await suite.blind(k.pair.publicKey, prepared);
  const blindSig = await suite.blindSign(k.pair.privateKey, blindedMsg);
  const sig = await suite.finalize(k.pair.publicKey, prepared, blindSig, inv);
  return `${k.kid}.${b64u(prepared)}.${b64u(sig)}`;
}

function direct(k, b, saltLength = 48) {
  const prepared = Buffer.concat([crypto.randomBytes(32), Buffer.from(JSON.stringify(b))]);
  const sig = crypto.sign('sha384', prepared, { key: k.nodePriv, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength });
  return `${k.kid}.${b64u(prepared)}.${b64u(sig)}`;
}

const k18 = await key('v18-age18-20261109');
const k21 = await key('v18-age21-20261109', { minAge: 21 });
const kGrace = await key('v18-age18-20261026', { nbf: NOW - 14 * 86400, exp: NOW - 599 });
const kOld = await key('v18-age18-20261019', { nbf: NOW - 21 * 86400, exp: NOW - 601 });
const kNext = await key('v18-age18-20261116', { nbf: NOW + 3600, exp: NOW + 8 * 86400 });
const kNoAge = await key('v18-noage-20261109', { omit: ['v18_min_age'] });
const kStranger = await key('v18-age18-stranger');

const valid = await blind(k18, body());
const [vk, vp, vs] = valid.split('.');
const badSig = Buffer.from(vs, 'base64url');
badSig[5] ^= 1;

const cases = [
  { name: 'valid 18+ ticket (blind flow)', ticket: valid, expect: 'VALID', minAgeOut: 18 },
  { name: 'same ticket again', ticket: valid, expect: 'REPLAY_DETECTED' },
  { name: '21+ key, 21+ site', ticket: await blind(k21, body()), minAge: 21, expect: 'VALID', minAgeOut: 21 },
  { name: '18+ key, 21+ site, payload lies minAge 21', ticket: await blind(k18, body({ minAge: 21 })), minAge: 21, expect: 'AGE_INSUFFICIENT' },
  { name: 'unknown keyId', ticket: await blind(kStranger, body()), expect: 'UNKNOWN_KEY' },
  { name: 'key expired 599 s ago (grace)', ticket: direct(kGrace, body()), expect: 'VALID', minAgeOut: 18 },
  { name: 'key expired 601 s ago', ticket: direct(kOld, body()), expect: 'KEY_EXPIRED' },
  { name: 'next key, nbf in future', ticket: direct(kNext, body()), expect: 'KEY_NOT_YET_VALID' },
  { name: 'JWKS key without v18_min_age is ignored', ticket: direct(kNoAge, body()), expect: 'UNKNOWN_KEY' },
  { name: 'changed signature', ticket: `${vk}.${vp}.${b64u(badSig)}`, expect: 'INVALID_SIGNATURE' },
  { name: 'PSS salt length 32', ticket: direct(k18, body(), 32), expect: 'INVALID_SIGNATURE' },
  { name: 'v = 2', ticket: await blind(k18, body({ v: 2 })), expect: 'UNSUPPORTED_VERSION' },
  { name: 'other origin', ticket: await blind(k18, body({ origin: 'https://evil.test' })), expect: 'ORIGIN_MISMATCH' },
  { name: 'host-only origin', ticket: await blind(k18, body({ origin: 'example-site.test' })), expect: 'ORIGIN_MISMATCH' },
  { name: 'other challenge', ticket: await blind(k18, body({ challenge: 'd'.repeat(64) })), expect: 'CHALLENGE_MISMATCH' },
  { name: 'iat 61 s in the future', ticket: direct(k18, body({ iat: NOW + 61, expiresAt: NOW + 361 })), expect: 'TICKET_NOT_YET_VALID' },
  { name: 'iat 60 s in the future (edge)', ticket: direct(k18, body({ iat: NOW + 60, expiresAt: NOW + 360 })), expect: 'VALID', minAgeOut: 18 },
  { name: 'expired 61 s ago', ticket: direct(k18, body({ iat: NOW - 361, expiresAt: NOW - 61 })), expect: 'TICKET_EXPIRED' },
  { name: 'expired 60 s ago (edge)', ticket: direct(k18, body({ iat: NOW - 360, expiresAt: NOW - 60 })), expect: 'VALID', minAgeOut: 18 },
  { name: 'lifetime 301 s', ticket: direct(k18, body({ expiresAt: NOW + 301 })), expect: 'TICKET_LIFETIME_INVALID' },
  { name: 'ticketId only 8 bytes', ticket: direct(k18, body({ ticketId: b64u(crypto.randomBytes(8)) })), expect: 'MALFORMED_PAYLOAD' },
  { name: 'signed message is not JSON', ticket: await blind(k18, 'hello'), expect: 'MALFORMED_PAYLOAD' },
  { name: 'two parts only', ticket: `${vk}.${vp}`, expect: 'INVALID_FORMAT' },
  { name: 'padding in base64url', ticket: `${vk}.${vp}=.${vs}`, expect: 'INVALID_FORMAT' },
];

const out = {
  description:
    'V18 protocol v1 ticket test vectors (TEST DATA ONLY). Verify all cases IN ORDER with ONE verifier ' +
    '(one replay cache), clock = now, expectedOrigin = origin, expectedChallenge = challenge, minAge = case.minAge or 18.',
  generatedBy: 'sdk-web/verify-node/scripts/make-vectors.mjs using @cloudflare/blindrsa-ts',
  now: NOW,
  origin: ORIGIN,
  challenge: CHAL,
  jwks: { keys: [k18.jwk, k21.jwk, kGrace.jwk, kOld.jwk, kNext.jwk, kNoAge.jwk] },
  cases,
};

const file = path.resolve(import.meta.dirname, '../../test-vectors/v1-tickets.json');
fs.mkdirSync(path.dirname(file), { recursive: true });
fs.writeFileSync(file, JSON.stringify(out, null, 2) + '\n');
console.log(`Wrote ${cases.length} cases to ${file}`);
