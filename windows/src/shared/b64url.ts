// base64url without padding (PROTOCOL.md 3: "Binary values are base64url without padding").

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

export function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/** Strict decode: rejects padding, '+', '/', spaces and impossible lengths. */
export function b64urlDecode(text: string): Uint8Array {
  if (typeof text !== 'string' || !B64URL_RE.test(text) || text.length % 4 === 1) {
    throw new Error('not base64url');
  }
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

export function isB64url(text: unknown, minBytes = 1): text is string {
  if (typeof text !== 'string') return false;
  try {
    return b64urlDecode(text).length >= minBytes;
  } catch {
    return false;
  }
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
