/** Strict base64url (no padding) helpers. Node's Buffer decoder silently skips bad characters, so we check first. */

const B64URL = /^[A-Za-z0-9_-]+$/;

export function isBase64Url(s: string): boolean {
  return typeof s === 'string' && s.length > 0 && B64URL.test(s) && s.length % 4 !== 1;
}

export function b64urlDecode(s: string): Buffer | null {
  if (!isBase64Url(s)) return null;
  return Buffer.from(s, 'base64url');
}

export function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}
