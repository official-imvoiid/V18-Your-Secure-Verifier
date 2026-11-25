/** What an issuer (ID check method) hands back after a proof checks out. */
export interface IssuerResult {
  /** The method's own nullifier. It is hashed before storage. */
  rawNullifier: string;
  assuranceLevel: AssuranceLevel;
  minAgeCertified: number;
  /** Card end date, already capped by the ID's own validity where known. */
  validUntilMs: number;
}

/**
 * Assurance levels (PROTOCOL.md 4b item 4, 4c, 4d.4):
 *  - `test`: test data only (`test_dev`, or an Anon Aadhaar TEST key). Never real.
 *  - `low`: face estimate (4c.6).
 *  - `substantial`: a government ID checked by zero-knowledge proof, by an
 *    attested phone, by a wallet, or by a login connector.
 *  - `high`: eIDAS-high or national login schemes (4d.4).
 */
export type AssuranceLevel = 'test' | 'low' | 'substantial' | 'high';

export const DAY_MS = 86_400_000;

export const CARD_VALIDITY_DAYS = {
  test_dev: 30,
  anon_aadhaar: 180,
  emrtd_attested: 180,
  philsys_qr_attested: 180,
  mynumber_attested: 180,
  face_estimate: 30,
  mdoc_app: 180,
  connector: 180,
} as const;
