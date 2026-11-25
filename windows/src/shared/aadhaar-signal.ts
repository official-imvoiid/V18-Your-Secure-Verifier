// The Anon Aadhaar signal V18 uses (PROTOCOL.md 4b item 1):
//   signal = "0x" + hex(SHA-256(UTF-8(challenge + "|" + deviceKeyThumbprint)))
// The proof's signalHash is Anon Aadhaar's hash(signal), which binds the proof to this one
// request (the server's challenge) and this one device key.

import { createHash } from 'node:crypto';

export function aadhaarSignal(challenge: string, deviceKeyThumbprint: string): string {
  return '0x' + createHash('sha256').update(`${challenge}|${deviceKeyThumbprint}`, 'utf8').digest('hex');
}
