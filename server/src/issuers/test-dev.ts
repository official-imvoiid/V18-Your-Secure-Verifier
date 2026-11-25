import { ApiError } from '../errors.js';
import { isPlainObject } from '../util.js';
import { CARD_VALIDITY_DAYS, DAY_MS, IssuerResult } from './types.js';

/**
 * `test_dev` issuer: TEST ONLY, dev mode only (protocol 3.5).
 *
 * proof = { testSubjectId, birthDate: "YYYY-MM-DD", idValidUntil?: "YYYY-MM-DD" }
 *
 * `idValidUntil` is an optional V18 extension so tests can check the rule
 * "a card never outlives the ID". Nothing from the proof is stored: the
 * subject ID only feeds the nullifier hash, and the birth date is thrown away.
 */
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

function parseDate(value: unknown, field: string): { y: number; m: number; d: number; ms: number } {
  if (typeof value !== 'string') throw new ApiError(400, 'BAD_REQUEST', `proof.${field} must be "YYYY-MM-DD"`);
  const match = DATE.exec(value);
  if (!match) throw new ApiError(400, 'BAD_REQUEST', `proof.${field} must be "YYYY-MM-DD"`);
  const y = Number(match[1]);
  const m = Number(match[2]);
  const d = Number(match[3]);
  const ms = Date.UTC(y, m - 1, d);
  const check = new Date(ms);
  if (check.getUTCFullYear() !== y || check.getUTCMonth() !== m - 1 || check.getUTCDate() !== d) {
    throw new ApiError(400, 'BAD_REQUEST', `proof.${field} is not a real date`);
  }
  return { y, m, d, ms };
}

/** Whole years between a birth date and `nowMs` (UTC). */
export function ageOn(birth: { y: number; m: number; d: number }, nowMs: number): number {
  const now = new Date(nowMs);
  let age = now.getUTCFullYear() - birth.y;
  const monthDiff = now.getUTCMonth() + 1 - birth.m;
  if (monthDiff < 0 || (monthDiff === 0 && now.getUTCDate() < birth.d)) age--;
  return age;
}

export function verifyTestDevProof(proof: unknown, nowMs: number): IssuerResult {
  if (!isPlainObject(proof)) throw new ApiError(400, 'BAD_REQUEST', 'proof must be an object');
  const subject = proof.testSubjectId;
  if (typeof subject !== 'string' || subject.length < 1 || subject.length > 128) {
    throw new ApiError(400, 'BAD_REQUEST', 'proof.testSubjectId must be 1 to 128 characters');
  }
  const birth = parseDate(proof.birthDate, 'birthDate');
  if (birth.ms > nowMs) throw new ApiError(400, 'BAD_REQUEST', 'proof.birthDate is in the future');
  if (ageOn(birth, nowMs) < 18) {
    throw new ApiError(403, 'UNDER_AGE', 'The test subject is under 18');
  }

  let validUntilMs = nowMs + CARD_VALIDITY_DAYS.test_dev * DAY_MS;
  if (proof.idValidUntil !== undefined) {
    const idEnd = parseDate(proof.idValidUntil, 'idValidUntil').ms + DAY_MS; // valid through that whole day
    if (idEnd <= nowMs) throw new ApiError(400, 'ID_EXPIRED', 'The test ID has expired');
    validUntilMs = Math.min(validUntilMs, idEnd);
  }

  return {
    rawNullifier: subject,
    assuranceLevel: 'test',
    minAgeCertified: 18,
    validUntilMs,
  };
}
