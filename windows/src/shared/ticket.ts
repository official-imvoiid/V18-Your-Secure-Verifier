// One-time 18+ tickets (PROTOCOL.md 3.6), with RFC 9474 RSABSSA-SHA384-PSS-Randomized from
// the vetted @cloudflare/blindrsa-ts library. No home-made cryptography here: this file only
// builds the message, calls the library's prepare / blind / finalize, and formats the result.

import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { randomBytes, webcrypto } from 'node:crypto';
import type { IssuerJwk } from './api.js';
import { b64urlDecode, b64urlEncode, utf8 } from './b64url.js';

export const TICKET_ALG = 'RSABSSA-SHA384-PSS-Randomized';
export const MAX_TICKET_LIFETIME = 300;

const suite = () => RSABSSA.SHA384.PSS.Randomized();

export interface TicketPayload {
  v: 1;
  ticketId: string;
  origin: string;
  challenge: string;
  minAge: number;
  iat: number;
  expiresAt: number;
}

/** Build the ticket message. Field order and spelling follow PROTOCOL.md 3.6 exactly. */
export function buildTicketPayload(input: { origin: string; challenge: string; minAge: number; nowMs?: number; ticketId?: string; lifetime?: number }): TicketPayload {
  const iat = Math.floor((input.nowMs ?? Date.now()) / 1000);
  const lifetime = Math.min(input.lifetime ?? MAX_TICKET_LIFETIME, MAX_TICKET_LIFETIME);
  return {
    v: 1,
    ticketId: input.ticketId ?? b64urlEncode(randomBytes(16)),
    origin: input.origin,
    challenge: input.challenge,
    minAge: input.minAge,
    iat,
    expiresAt: iat + lifetime,
  };
}

export function ticketMessageBytes(p: TicketPayload): Uint8Array {
  // Written out by hand so the key order can never change.
  const json =
    `{"v":1,"ticketId":${JSON.stringify(p.ticketId)},"origin":${JSON.stringify(p.origin)},` +
    `"challenge":${JSON.stringify(p.challenge)},"minAge":${p.minAge},"iat":${p.iat},"expiresAt":${p.expiresAt}}`;
  return utf8(json);
}

/**
 * Pick the signing key to ask for: right algorithm, a threshold that covers the site's age,
 * valid now (nbf <= now < exp). If several match (rotation overlap), take the newest.
 */
export function pickTicketKey(keys: IssuerJwk[], minAge: number, nowSec = Math.floor(Date.now() / 1000)): IssuerJwk | null {
  const ok = keys.filter(
    (k) =>
      k.alg === TICKET_ALG &&
      typeof k.v18_min_age === 'number' &&
      k.v18_min_age >= minAge &&
      (k.nbf === undefined || k.nbf <= nowSec) &&
      (k.exp === undefined || nowSec < k.exp),
  );
  ok.sort((a, b) => (a.v18_min_age! - b.v18_min_age!) || ((b.nbf ?? 0) - (a.nbf ?? 0)));
  return ok[0] ?? null;
}

export async function importIssuerKey(jwk: Pick<IssuerJwk, 'n' | 'e'>): Promise<CryptoKey> {
  return webcrypto.subtle.importKey(
    'jwk',
    { kty: 'RSA', n: jwk.n, e: jwk.e, ext: true },
    { name: 'RSA-PSS', hash: 'SHA-384' },
    true,
    ['verify'],
  ) as Promise<CryptoKey>;
}

export interface BlindedTicket {
  keyId: string;
  publicKey: CryptoKey;
  prepared: Uint8Array;
  blindedMessage: string; // base64url, sent to the server
  inv: Uint8Array; // kept in memory only, never sent or stored
}

export async function blindTicket(issuer: IssuerJwk, payload: TicketPayload): Promise<BlindedTicket> {
  const s = suite();
  const publicKey = await importIssuerKey(issuer);
  const prepared = s.prepare(ticketMessageBytes(payload));
  const { blindedMsg, inv } = await s.blind(publicKey, prepared);
  return { keyId: issuer.kid, publicKey, prepared, blindedMessage: b64urlEncode(blindedMsg), inv };
}

/** Unblind the server's answer and check it (finalize fails if the signature is not valid). */
export async function finalizeTicket(b: BlindedTicket, blindSignatureB64: string): Promise<string> {
  const sig = await suite().finalize(b.publicKey, b.prepared, b64urlDecode(blindSignatureB64), b.inv);
  return `${b.keyId}.${b64urlEncode(b.prepared)}.${b64urlEncode(sig)}`;
}

/** Split a ticket string and check its signature (what a website does; used in tests). */
export async function verifyTicketString(ticket: string, issuer: IssuerJwk): Promise<{ ok: boolean; payload: TicketPayload | null }> {
  const parts = ticket.split('.');
  if (parts.length !== 3 || parts[0] !== issuer.kid) return { ok: false, payload: null };
  const prepared = b64urlDecode(parts[1]);
  const sig = b64urlDecode(parts[2]);
  const ok = await suite().verify(await importIssuerKey(issuer), sig, prepared);
  const payload = JSON.parse(new TextDecoder().decode(prepared.slice(32))) as TicketPayload;
  return { ok, payload };
}
