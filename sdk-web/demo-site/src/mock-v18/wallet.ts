/**
 * MOCK V18 SERVER: phone wallet endpoints (PROTOCOL.md 4c.5). TEST ONLY.
 *
 * The real server (server/) does this for real users. This copy lets the web SDK test the whole
 * flow. It still does every check for real:
 *   - the request asks only for age_over_18 (mDL or EU PID), with a fresh nonce and a fresh
 *     encryption key (OpenID4VP 1.0, "openid4vp-v1-unsigned", response_mode "dc_api.jwt");
 *   - the answer is decrypted, and @auth0/mdl checks the document signer chain up to a trusted
 *     IACA, the issuer signature, the value digests, and the device signature over the session
 *     transcript (which binds the website's origin, the nonce and the encryption key);
 *   - age_over_18 must be true. Each request can be answered once.
 * Nothing from the answer is stored or logged.
 */
import * as crypto from 'node:crypto';
import * as jose from 'jose';
import { Verifier } from '@auth0/mdl';
import { AGE_DOCS, OPENID4VP_UNSIGNED, ageOver18DcqlQuery, ecJwkThumbprintBytes, openId4VpDcApiSessionTranscript } from '../wallet-test/mdoc-common.js';

export class WalletCheckError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message);
  }
}

export interface WalletRequestState {
  nonce: string;
  kid: string;
  encPublicJwk: jose.JWK;
  encPrivateKey: crypto.KeyObject;
  used: boolean;
}

export function buildWalletRequest(): { request: { protocol: string; data: unknown }; state: WalletRequestState } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pub = publicKey.export({ format: 'jwk' }) as jose.JWK;
  const kid = crypto.randomBytes(8).toString('base64url');
  const encPublicJwk: jose.JWK = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, use: 'enc', alg: 'ECDH-ES', kid };
  const nonce = crypto.randomBytes(32).toString('base64url');
  return {
    request: {
      protocol: OPENID4VP_UNSIGNED,
      data: {
        response_type: 'vp_token',
        response_mode: 'dc_api.jwt',
        nonce,
        dcql_query: ageOver18DcqlQuery(),
        client_metadata: {
          jwks: { keys: [encPublicJwk] },
          encrypted_response_enc_values_supported: ['A128GCM'],
          vp_formats_supported: { mso_mdoc: { issuerauth_alg_values: [-7], deviceauth_alg_values: [-7] } },
        },
      },
    },
    state: { nonce, kid, encPublicJwk, encPrivateKey: privateKey, used: false },
  };
}

/**
 * Checks a wallet answer for a pairing session on `origin`. Returns normally only if the answer
 * is genuine, made for this origin and this request, and says age_over_18 = true.
 */
export async function verifyWalletAnswer(state: WalletRequestState, origin: string, response: any, trustedIacaPems: string[]): Promise<{ docType: string }> {
  if (!response || typeof response !== 'object' || response.protocol !== OPENID4VP_UNSIGNED) {
    throw new WalletCheckError(400, 'WALLET_PROTOCOL_UNSUPPORTED', `response.protocol must be "${OPENID4VP_UNSIGNED}"`);
  }
  let data: any = response.data;
  if (typeof data === 'string') {
    try {
      data = JSON.parse(data);
    } catch {
      throw new WalletCheckError(400, 'WALLET_BAD_RESPONSE', 'response.data is not JSON');
    }
  }
  if (typeof data?.response !== 'string') throw new WalletCheckError(400, 'WALLET_BAD_RESPONSE', 'Expected an encrypted answer (data.response)');

  let payload: any;
  try {
    const { plaintext, protectedHeader } = await jose.compactDecrypt(data.response, state.encPrivateKey, {
      keyManagementAlgorithms: ['ECDH-ES'],
      contentEncryptionAlgorithms: ['A128GCM'],
    });
    if (protectedHeader.kid !== undefined && protectedHeader.kid !== state.kid) throw new Error('wrong kid');
    payload = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new WalletCheckError(400, 'WALLET_BAD_RESPONSE', 'The answer could not be decrypted with this request\'s key');
  }

  const vp = payload?.vp_token;
  const entries = vp && typeof vp === 'object' ? Object.entries(vp) : [];
  if (entries.length !== 1) throw new WalletCheckError(400, 'WALLET_BAD_RESPONSE', 'Expected exactly one presentation');
  const [credId, presentations] = entries[0] as [string, unknown];
  const want = AGE_DOCS.find((d) => d.id === credId);
  if (!want || !Array.isArray(presentations) || presentations.length !== 1 || typeof presentations[0] !== 'string') {
    throw new WalletCheckError(400, 'WALLET_BAD_RESPONSE', 'Unknown credential query ID or bad presentation');
  }

  const failures: Array<{ id?: string; check: string; reason?: string }> = [];
  let mdoc;
  try {
    mdoc = await new Verifier(trustedIacaPems).verify(Buffer.from(presentations[0], 'base64url'), {
      encodedSessionTranscript: openId4VpDcApiSessionTranscript(origin, state.nonce, ecJwkThumbprintBytes(state.encPublicJwk)),
      onCheck: (check: any) => {
        if (check.status === 'FAILED') failures.push(check);
      },
    });
  } catch (e: any) {
    throw new WalletCheckError(400, 'WALLET_INVALID', `The mdoc could not be read (${e?.message ?? e})`);
  }
  if (failures.some((f) => f.id === 'ISSUER_CERTIFICATE_VALIDITY')) {
    throw new WalletCheckError(403, 'WALLET_UNTRUSTED_ISSUER', 'The ID was not issued under a trusted IACA');
  }
  if (failures.length > 0) {
    throw new WalletCheckError(400, 'WALLET_INVALID', `Check failed: ${failures[0].check}`);
  }
  if (mdoc.documents.length !== 1) throw new WalletCheckError(400, 'WALLET_INVALID', 'Expected exactly one document');
  const doc: any = mdoc.documents[0];
  if (doc.docType !== want.docType || doc.issuerSigned?.issuerAuth?.decodedPayload?.docType !== want.docType) {
    throw new WalletCheckError(400, 'WALLET_INVALID', 'Document type does not match the request');
  }
  const value = doc.getIssuerNameSpace(want.nameSpace)?.age_over_18;
  if (typeof value !== 'boolean') throw new WalletCheckError(400, 'WALLET_INVALID', 'The answer has no age_over_18');
  if (value !== true) throw new WalletCheckError(403, 'UNDER_AGE', 'The ID says age_over_18 is false');
  return { docType: want.docType };
}
