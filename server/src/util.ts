import * as crypto from 'node:crypto';
import { badRequest } from './errors.js';

/** A clock returns "now" in milliseconds. Tests pass a fake one. */
export type Clock = () => number;
export const systemClock: Clock = () => Date.now();

const B64URL = /^[A-Za-z0-9_-]+$/;

export function isBase64url(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && B64URL.test(value);
}

/** Decodes strict base64url (no padding). Throws a 400 error otherwise. */
export function decodeBase64url(value: unknown, field: string, maxBytes = 8192): Buffer {
  if (!isBase64url(value)) {
    throw badRequest(`${field} must be base64url without padding`);
  }
  if (value.length > Math.ceil((maxBytes * 4) / 3) + 4) {
    throw badRequest(`${field} is too long`);
  }
  // A base64url string of length 4k+1 can never be valid.
  if (value.length % 4 === 1) {
    throw badRequest(`${field} is not valid base64url`);
  }
  return Buffer.from(value, 'base64url');
}

export function toBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** Random ID like `card_<base64url of 16 bytes>`. 16 bytes = 128 random bits. */
export function randomId(prefix: string, bytes = 16): string {
  return `${prefix}_${crypto.randomBytes(bytes).toString('base64url')}`;
}

export function sha256Hex(data: string | Uint8Array): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function requireString(
  body: Record<string, unknown>,
  field: string,
  opts: { max?: number; pattern?: RegExp } = {}
): string {
  const v = body[field];
  if (typeof v !== 'string' || v.length === 0) throw badRequest(`Missing field: ${field}`);
  if (v.length > (opts.max ?? 4096)) throw badRequest(`${field} is too long`);
  if (opts.pattern && !opts.pattern.test(v)) throw badRequest(`${field} has the wrong format`);
  return v;
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function bodyOf(raw: unknown): Record<string, unknown> {
  return isPlainObject(raw) ? raw : {};
}

export function iso(ms: number): string {
  return new Date(ms).toISOString();
}
