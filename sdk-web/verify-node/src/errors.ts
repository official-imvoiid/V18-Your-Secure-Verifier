/**
 * Every reason a ticket can be refused. The rule numbers point at PROTOCOL.md section 3.7.
 */
export type VerifyErrorCode =
  | 'CONFIG_ERROR' // the website called verifyTicket with a bad origin or age
  | 'CHALLENGE_REQUIRED' // the website did not say which challenge it issued (rule 5)
  | 'INVALID_FORMAT' // not "<keyId>.<prepared>.<signature>" in base64url
  | 'KEYS_UNAVAILABLE' // could not load the V18 public keys (JWKS)
  | 'UNKNOWN_KEY' // rule 1: keyId is not in the JWKS
  | 'KEY_EXPIRED' // rule 1: now > exp + 600
  | 'KEY_NOT_YET_VALID' // now < nbf - 60 (see report: the protocol lists nbf but no rule)
  | 'INVALID_SIGNATURE' // rule 2
  | 'MALFORMED_PAYLOAD' // the signed message is not the protocol's JSON ticket
  | 'UNSUPPORTED_VERSION' // rule 3: payload.v is not 1
  | 'ORIGIN_MISMATCH' // rule 4
  | 'CHALLENGE_MISMATCH' // rule 5
  | 'AGE_INSUFFICIENT' // rule 6: the key's v18_min_age is below what the site needs
  | 'TICKET_NOT_YET_VALID' // rule 7: now < iat - 60
  | 'TICKET_EXPIRED' // rule 7: now > expiresAt + 60
  | 'TICKET_LIFETIME_INVALID' // rule 7: expiresAt - iat > 300 (or negative)
  | 'REPLAY_DETECTED'; // rule 8

/** Numbers fixed by PROTOCOL.md 3.7. They are constants on purpose: a site cannot loosen them. */
export const RULES = Object.freeze({
  KEY_EXPIRY_GRACE_SECONDS: 600,
  CLOCK_SKEW_SECONDS: 60,
  MAX_TICKET_LIFETIME_SECONDS: 300,
  ALGORITHM: 'RSABSSA-SHA384-PSS-Randomized',
  PSS_SALT_LENGTH: 48,
  PREPARE_PREFIX_BYTES: 32,
  MAX_TICKET_LENGTH: 8192,
});
