// Device-signature signing strings, exactly as PROTOCOL.md 3.4 lists them:
// fields joined with "\n", no trailing newline, signed as UTF-8 bytes.

import { utf8 } from './b64url.js';

export type DeviceAlg = 'ES256' | 'RS256';

export interface DeviceSignature {
  alg: DeviceAlg;
  sig: string; // base64url
}

function join(tag: string, fields: Record<string, string>): string {
  for (const [name, value] of Object.entries(fields)) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`signing string field "${name}" is empty`);
    }
    // A newline inside a field would let one field pretend to be two.
    if (/[\r\n]/.test(value)) {
      throw new Error(`signing string field "${name}" contains a line break`);
    }
  }
  return [tag, ...Object.values(fields)].join('\n');
}

/** Issue card (proof of possession). Also used by the device link start (3.9 step 1). */
export function cardIssueString(challenge: string, deviceKeyThumbprint: string): string {
  return join('v18-card-issue', { challenge, deviceKeyThumbprint });
}

export function ticketRequestString(cardId: string, challenge: string, keyId: string, blindedMessage: string): string {
  return join('v18-ticket-request', { cardId, challenge, keyId, blindedMessage });
}

export function linkApproveString(cardId: string, challenge: string, linkId: string): string {
  return join('v18-link-approve', { cardId, challenge, linkId });
}

export function cardDeleteString(cardId: string, challenge: string): string {
  return join('v18-card-delete', { cardId, challenge });
}

export function signingBytes(signingString: string): Uint8Array {
  return utf8(signingString);
}
