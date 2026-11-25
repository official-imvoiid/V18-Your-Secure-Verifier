import { ApiError, badRequest } from '../errors.js';
import { NULLIFIER_KEY_ID } from '../nullifier/service.js';
import { isPlainObject } from '../util.js';
import { CARD_VALIDITY_DAYS, DAY_MS, IssuerResult } from './types.js';

/**
 * Methods where the PHONE checks a chip or signed document and the server
 * trusts the phone because its key is hardware-attested (PROTOCOL.md 4c.3,
 * 4c.4, 4d.3):
 *
 *  - emrtd_attested (alias passport_attested): any ICAO 9303 chip document
 *    (passports, chip ID cards, residence permits). The phone does MRZ/CAN,
 *    BAC or PACE, reads DG1 and SOD, runs passive authentication against the
 *    CSCA master list, and chip or active authentication where available.
 *  - philsys_qr_attested: Philippines PhilSys QR, PSA signature checked on the phone.
 *  - mynumber_attested: Japan My Number Card JPKI signature certificate,
 *    chain to the J-LIS root checked on the phone.
 *
 * The phone sends NO name, birth date or document number. The nullifier comes
 * from the 4c.2 nullifier service (the server never sees the document).
 *
 * What the server can and cannot check: it checks the attestation (the
 * request really comes from the genuine V18 app on a locked, verified phone)
 * and the shape and dates below. It cannot re-check the chip data itself,
 * because the phone does not send it (that would reveal identity).
 */

export type AttestedMethod = 'emrtd_attested' | 'philsys_qr_attested' | 'mynumber_attested';

/** passport_attested (4c.4) is kept as an alias of emrtd_attested (4d.3). */
export function canonicalAttestedMethod(method: string): AttestedMethod | null {
  if (method === 'passport_attested' || method === 'emrtd_attested') return 'emrtd_attested';
  if (method === 'philsys_qr_attested' || method === 'mynumber_attested') return method;
  return null;
}

const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const NULLIFIER = /^[A-Za-z0-9_-]{43}$/;

const invalid = (reason: string, message: string) => new ApiError(400, 'PROOF_INVALID', message, { reason });

/** End of the given UTC day, or a 400 error. */
function endOfDay(value: unknown, field: string): number {
  if (typeof value !== 'string') throw invalid('malformed', `proof.${field} must be "YYYY-MM-DD"`);
  const m = DATE.exec(value);
  if (!m) throw invalid('malformed', `proof.${field} must be "YYYY-MM-DD"`);
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const ms = Date.UTC(y, mo - 1, d);
  const check = new Date(ms);
  if (check.getUTCFullYear() !== y || check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== d) {
    throw invalid('malformed', `proof.${field} is not a real date`);
  }
  return ms + DAY_MS;
}

function commonChecks(p: Record<string, unknown>): string {
  if (p.over18 === false) throw new ApiError(403, 'UNDER_AGE', 'The document shows the holder is under 18');
  if (p.over18 !== true) throw invalid('malformed', 'proof.over18 must be true');
  if (p.nullifierKeyId !== NULLIFIER_KEY_ID) {
    throw invalid('wrong_nullifier_key', `proof.nullifierKeyId must be "${NULLIFIER_KEY_ID}"`);
  }
  if (typeof p.nullifier !== 'string' || !NULLIFIER.test(p.nullifier)) {
    throw invalid('malformed', 'proof.nullifier must be base64url(SHA-256(signature)): 43 characters');
  }
  return `${NULLIFIER_KEY_ID}:${p.nullifier}`;
}

/** Only these fields may be in the proof, so nothing identifying slips in by mistake. */
function onlyFields(p: Record<string, unknown>, allowed: string[]): void {
  for (const k of Object.keys(p)) {
    if (!allowed.includes(k)) throw invalid('unexpected_field', `proof.${k} is not allowed (send no personal data)`);
  }
}

export interface AttestedProofResult extends IssuerResult {
  docType: string | null;
}

export function verifyAttestedProof(method: AttestedMethod, proof: unknown, nowMs: number, aliasUsed: boolean): AttestedProofResult {
  if (!isPlainObject(proof)) throw badRequest('proof must be an object');
  const maxValid = nowMs + CARD_VALIDITY_DAYS[method] * DAY_MS;

  if (method === 'emrtd_attested') {
    onlyFields(proof, ['over18', 'docExpiry', 'issuingState', 'docType', 'passiveAuth', 'chipAuth', 'nullifier', 'nullifierKeyId']);
    const raw = commonChecks(proof);
    // 4d.3: the first MRZ letter. passport_attested (4c.4) had no docType, so it means "P".
    const docType = proof.docType === undefined && aliasUsed ? 'P' : proof.docType;
    if (typeof docType !== 'string' || !/^[PIAC]$/.test(docType)) {
      throw invalid('malformed', 'proof.docType must be "P", "I", "A" or "C" (the first letter of the MRZ)');
    }
    if (typeof proof.issuingState !== 'string' || !/^(?=.*[A-Z])[A-Z<]{3}$/.test(proof.issuingState)) {
      throw invalid('malformed', 'proof.issuingState must be the 3-letter ICAO code from the MRZ, for example "IND" or "D<<"');
    }
    if (proof.passiveAuth !== 'ok') {
      throw invalid('passive_auth_failed', 'Passive authentication (document signature against the CSCA master list) must be "ok"');
    }
    if (!['chip_auth', 'active_auth', 'none'].includes(proof.chipAuth as string)) {
      throw invalid('malformed', 'proof.chipAuth must be "chip_auth", "active_auth" or "none"');
    }
    const expiry = endOfDay(proof.docExpiry, 'docExpiry');
    if (expiry <= nowMs) throw new ApiError(400, 'ID_EXPIRED', 'The document has expired');
    return {
      rawNullifier: raw,
      assuranceLevel: 'substantial',
      minAgeCertified: 18,
      validUntilMs: Math.min(maxValid, expiry),
      docType,
    };
  }

  if (method === 'philsys_qr_attested') {
    onlyFields(proof, ['over18', 'qrSignature', 'nullifier', 'nullifierKeyId']);
    const raw = commonChecks(proof);
    if (proof.qrSignature !== 'ok') {
      throw invalid('qr_signature_failed', 'proof.qrSignature must be "ok" (the PSA signature was checked on the phone)');
    }
    // PhilSys IDs for citizens do not expire, so the card gets the method's full validity.
    return { rawNullifier: raw, assuranceLevel: 'substantial', minAgeCertified: 18, validUntilMs: maxValid, docType: null };
  }

  // mynumber_attested
  onlyFields(proof, ['over18', 'jpkiChain', 'certExpiry', 'nullifier', 'nullifierKeyId']);
  const raw = commonChecks(proof);
  if (proof.jpkiChain !== 'ok') {
    throw invalid('jpki_chain_failed', 'proof.jpkiChain must be "ok" (the JPKI certificate chain to the J-LIS root was checked on the phone)');
  }
  const expiry = endOfDay(proof.certExpiry, 'certExpiry');
  if (expiry <= nowMs) throw new ApiError(400, 'ID_EXPIRED', 'The JPKI signature certificate has expired');
  return { rawNullifier: raw, assuranceLevel: 'substantial', minAgeCertified: 18, validUntilMs: Math.min(maxValid, expiry), docType: null };
}

// ---- face_estimate (PROTOCOL.md 4c.6) ----------------------------------------------

export function verifyFaceProof(proof: unknown, opts: { models: string[]; minChallengeAge: number; thumbprint: string; nowMs: number }): IssuerResult {
  if (!isPlainObject(proof)) throw badRequest('proof must be an object');
  onlyFields(proof, ['estimator', 'challengeAge', 'passed', 'liveness']);
  if (typeof proof.estimator !== 'string' || !opts.models.includes(proof.estimator)) {
    throw invalid('unknown_estimator', 'proof.estimator is not a face model this server accepts (V18_FACE_MODELS)');
  }
  if (!Number.isInteger(proof.challengeAge) || (proof.challengeAge as number) < opts.minChallengeAge) {
    throw invalid('challenge_age_too_low', `proof.challengeAge must be at least ${opts.minChallengeAge}`);
  }
  if (proof.liveness !== 'passed') throw invalid('liveness_failed', 'proof.liveness must be "passed"');
  if (proof.passed !== true) {
    throw new ApiError(403, 'UNDER_AGE', 'The face estimate did not pass the challenge age', { reason: 'face_estimate_not_passed' });
  }
  return {
    // No ID behind a face estimate: the "nullifier" is the device key, so one key gets one card.
    rawNullifier: `face:${opts.thumbprint}`,
    assuranceLevel: 'low',
    minAgeCertified: 18,
    validUntilMs: opts.nowMs + CARD_VALIDITY_DAYS.face_estimate * DAY_MS,
  };
}
