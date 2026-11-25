import type * as crypto from 'node:crypto';
import { ApiError } from '../errors.js';
import { Clock } from '../util.js';
import {
  AttestationPolicy,
  AttestationResult,
  attestationSummary,
  noAttestationResult,
  verifyKeyAttestation,
} from './android.js';

/**
 * One place that decides whether a request's Android key attestation is
 * good enough on this server (PROTOCOL.md 4c.3):
 *  - production: required, with every check, and only when
 *    V18_ANDROID_CERT_DIGESTS is set (otherwise the attested methods are
 *    "not configured");
 *  - dev mode: emulator, software or missing attestation is let through,
 *    and the response says exactly what was let through.
 */
export class AttestationGate {
  constructor(
    private readonly policy: AttestationPolicy,
    private readonly clock: Clock
  ) {}

  get devMode(): boolean {
    return this.policy.devMode;
  }

  /** Attested methods work on this server. */
  get configured(): boolean {
    return this.policy.devMode || this.policy.certDigests.length > 0;
  }

  async check(chain: unknown, challenge: string, devicePublicKey: crypto.KeyObject): Promise<AttestationResult> {
    if (!this.configured) {
      throw new ApiError(
        503,
        'METHOD_NOT_CONFIGURED',
        'Android key attestation is not set up on this server (V18_ANDROID_CERT_DIGESTS is empty)'
      );
    }
    if (chain === undefined || chain === null) {
      if (this.policy.devMode) return noAttestationResult();
      throw new ApiError(400, 'ATTESTATION_REQUIRED', 'keyAttestation (the Android Keystore certificate chain) is required', {
        reason: 'missing',
      });
    }
    return verifyKeyAttestation(
      { chain, allowedChallenges: [challenge], devicePublicKey, nowMs: this.clock() },
      this.policy
    );
  }

  summary(r: AttestationResult) {
    return attestationSummary(r);
  }
}
