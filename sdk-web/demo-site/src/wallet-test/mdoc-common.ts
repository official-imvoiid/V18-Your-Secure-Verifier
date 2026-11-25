/**
 * Shared pieces for phone wallet IDs (mdoc, ISO/IEC 18013-5) over the browser's Digital
 * Credentials API, using OpenID4VP 1.0 Appendix A (protocol "openid4vp-v1-unsigned").
 *
 * Used by the TEST phone wallet (test-phone-wallet.ts) and the MOCK V18 server's wallet endpoints.
 * Both sides must build the SessionTranscript the same way, or the device signature fails.
 */
import * as crypto from 'node:crypto';
// @auth0/mdl's own CBOR settings (no tagged byte strings, maps not records), so both sides match.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const mdlCbor: { cborEncode(v: unknown): Buffer; cborDecode(b: Uint8Array): any; DataItem: any } = require('@auth0/mdl/lib/cbor');

export const OPENID4VP_UNSIGNED = 'openid4vp-v1-unsigned';

/** Documents V18 accepts, and where `age_over_18` lives in each. */
export const AGE_DOCS = [
  { id: 'mdl', docType: 'org.iso.18013.5.1.mDL', nameSpace: 'org.iso.18013.5.1' },
  { id: 'pid', docType: 'eu.europa.ec.eudi.pid.1', nameSpace: 'eu.europa.ec.eudi.pid.1' },
] as const;

export type AgeDoc = (typeof AGE_DOCS)[number];

export const cborEncode = (v: unknown): Buffer => mdlCbor.cborEncode(v);
export const cborDecode = (b: Uint8Array): any => mdlCbor.cborDecode(b);

/** RFC 7638 thumbprint (SHA-256) of an EC P-256 public JWK, as raw bytes. */
export function ecJwkThumbprintBytes(jwk: { kty?: string; crv?: string; x?: string; y?: string }): Buffer {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new Error('Encryption key must be an EC P-256 JWK');
  }
  return crypto.createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`).digest();
}

/**
 * OpenID4VP 1.0, B.2.6.2 (DC API):
 *   OpenID4VPDCAPIHandoverInfo = [origin, nonce, jwkThumbprint or null]
 *   OpenID4VPDCAPIHandover     = ["OpenID4VPDCAPIHandover", SHA-256(CBOR(HandoverInfo))]
 *   SessionTranscript          = [null, null, OpenID4VPDCAPIHandover]
 * Returned as the Tag 24 CBOR bytes that @auth0/mdl's DeviceResponse and Verifier both take.
 * `origin` is the website's web origin without any "origin:" prefix.
 */
export function openId4VpDcApiSessionTranscript(origin: string, nonce: string, encryptionJwkThumbprint: Buffer | null): Buffer {
  const info = cborEncode([origin, nonce, encryptionJwkThumbprint]);
  const infoHash = crypto.createHash('sha256').update(info).digest();
  return cborEncode(mdlCbor.DataItem.fromData([null, null, ['OpenID4VPDCAPIHandover', infoHash]]));
}

/** The DCQL query V18 sends: only `age_over_18`, from an mDL or an EU PID, never kept. */
export function ageOver18DcqlQuery() {
  return {
    credentials: AGE_DOCS.map((d) => ({
      id: d.id,
      format: 'mso_mdoc',
      meta: { doctype_value: d.docType },
      claims: [{ path: [d.nameSpace, 'age_over_18'], intent_to_retain: false }],
    })),
    credential_sets: [{ options: AGE_DOCS.map((d) => [d.id]) }],
  };
}
