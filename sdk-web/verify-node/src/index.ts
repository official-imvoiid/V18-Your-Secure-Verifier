export * from './verifier.js';
export * from './keys.js';
export * from './replay-cache.js';
export * from './challenge.js';
export * from './errors.js';

import { V18Verifier, VerifyOptions, VerifyResult } from './verifier.js';

const defaultVerifiers = new Map<string, V18Verifier>();

/**
 * One-call helper. Keeps one verifier (and so one replay cache) per V18 server URL.
 *
 *   const result = await verifyTicket(req.body.ticket, {
 *     expectedOrigin: 'https://example.com',
 *     expectedChallenge: challenges.checker(visitId),
 *     minAge: 18,
 *   });
 *   if (result.valid) { ...the visitor is 18+... }
 */
export async function verifyTicket(
  ticket: unknown,
  options: VerifyOptions & { serverUrl?: string }
): Promise<VerifyResult> {
  const serverUrl = options.serverUrl ?? 'http://localhost:8080';
  let v = defaultVerifiers.get(serverUrl);
  if (!v) {
    v = new V18Verifier({ serverUrl });
    defaultVerifiers.set(serverUrl, v);
  }
  return v.verifyTicket(ticket, options);
}
