/**
 * TEST PHONE WALLET. TEST ONLY. Not a real wallet, and its ID is not a real ID.
 *
 * It plays the visitor's phone wallet (and the browser's Digital Credentials API) so the whole
 * `mdoc_wallet` flow (PROTOCOL.md 4c.5) can be tested without a phone:
 *   - it holds one TEST mdoc (a mobile driving licence or an EU PID) sealed by a TEST IACA's
 *     document signer, bound to a device key it keeps in memory;
 *   - it answers an OpenID4VP 1.0 "openid4vp-v1-unsigned" request by disclosing ONLY the claims
 *     the request names, device-signing the session transcript (origin + nonce + encryption key),
 *     and, for response_mode "dc_api.jwt", encrypting the answer to the verifier's key (JWE).
 * The person data in the TEST mdoc is fake ("TEST"). It is never disclosed: only age_over_18 is.
 */
import * as crypto from 'node:crypto';
import { DeviceResponse, Document, MDoc } from '@auth0/mdl';
import * as jose from 'jose';
import { AGE_DOCS, AgeDoc, OPENID4VP_UNSIGNED, ecJwkThumbprintBytes, openId4VpDcApiSessionTranscript } from './mdoc-common.js';
import type { TestIssuer } from './test-iaca.js';

export interface TestPhoneWalletOptions {
  issuer: TestIssuer;
  /** The TEST ID's age_over_18 value. Default true. */
  ageOver18?: boolean;
  /** Which TEST document the wallet holds. Default "mdl". */
  doc?: 'mdl' | 'pid';
  /** ATTACK TESTS ONLY: answer as if the request came from this origin (a phishing site). */
  pretendOrigin?: string;
}

/** Shaped like the DOMException browsers throw, so the widget handles it the same way. */
function domError(name: string, message: string): Error {
  return Object.assign(new Error(message), { name });
}

const ymd = (d: Date) => d.toISOString().slice(0, 10);

export class TestPhoneWallet {
  /** How many answers this wallet gave (tests check nothing was sent when it should not be). */
  public answers = 0;
  /** What the last request asked for, as [nameSpace, element] pairs. */
  public lastRequestedClaims: string[][] = [];

  private constructor(
    private readonly mdoc: MDoc,
    private readonly doc: AgeDoc,
    // @auth0/mdl uses its own jose version, so its JWK type differs from ours.
    private readonly devicePrivateJwk: any,
    private readonly pretendOrigin?: string
  ) {}

  static async create(opts: TestPhoneWalletOptions): Promise<TestPhoneWallet> {
    const doc = AGE_DOCS.find((d) => d.id === (opts.doc ?? 'mdl'))!;
    const adult = opts.ageOver18 !== false;
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const devicePublicJwk: any = publicKey.export({ format: 'jwk' });
    const devicePrivateJwk: any = privateKey.export({ format: 'jwk' });
    const now = new Date();
    const values: Record<string, unknown> =
      doc.id === 'mdl'
        ? {
            family_name: 'TEST',
            given_name: 'TEST',
            birth_date: adult ? '1990-01-01' : '2012-06-01',
            issue_date: ymd(now),
            expiry_date: ymd(new Date(now.getTime() + 365 * 86400_000)),
            issuing_country: opts.issuer.country,
            issuing_authority: 'V18 TEST issuer (test only)',
            document_number: 'TEST0001',
            age_over_18: adult,
            age_over_21: adult,
          }
        : {
            family_name: 'TEST',
            given_name: 'TEST',
            birth_date: adult ? '1990-01-01' : '2012-06-01',
            issuing_country: opts.issuer.country,
            age_over_18: adult,
          };
    const signed = await new Document(doc.docType)
      .addIssuerNameSpace(doc.nameSpace, values)
      .useDigestAlgorithm('SHA-256')
      .addValidityInfo({ signed: now, validFrom: now, validUntil: new Date(now.getTime() + 30 * 86400_000) })
      .addDeviceKeyInfo({ deviceKey: devicePublicJwk })
      .sign({ issuerPrivateKey: opts.issuer.dsPrivateJwk as any, issuerCertificate: opts.issuer.dsPem, alg: 'ES256' });
    return new TestPhoneWallet(new MDoc([signed]), doc, devicePrivateJwk, opts.pretendOrigin);
  }

  /**
   * Answers the Digital Credentials API requests the browser was given, for a page on `origin`.
   * Returns what `navigator.credentials.get` resolves to: `{protocol, data}`.
   */
  async answer(requests: Array<{ protocol: string; data: unknown }>, origin: string): Promise<{ protocol: string; data: unknown }> {
    const req = requests.find((r) => r.protocol === OPENID4VP_UNSIGNED);
    if (!req) throw domError('NotSupportedError', 'The test wallet supports only openid4vp-v1-unsigned');
    const data: any = typeof req.data === 'string' ? JSON.parse(req.data) : req.data;
    if (data?.response_type !== 'vp_token' || typeof data?.nonce !== 'string' || !Array.isArray(data?.dcql_query?.credentials)) {
      throw domError('TypeError', 'Not an OpenID4VP vp_token request');
    }
    const cred = data.dcql_query.credentials.find((c: any) => c?.format === 'mso_mdoc' && c?.meta?.doctype_value === this.doc.docType);
    // Real browsers say NotAllowedError when no ID matches, so a site cannot probe the wallet.
    if (!cred) throw domError('NotAllowedError', 'No matching ID in the wallet');
    const claims: string[][] = (cred.claims ?? []).map((c: any) => c.path);
    this.lastRequestedClaims = claims;
    const pd = {
      id: 'v18-age-check',
      input_descriptors: [
        {
          id: this.doc.docType,
          format: { mso_mdoc: { alg: ['ES256'] } },
          constraints: {
            limit_disclosure: 'required',
            fields: claims.map((p) => ({ path: [`$['${p[0]}']['${p[1]}']`], intent_to_retain: false })),
          },
        },
      ],
    };

    const encrypted = data.response_mode === 'dc_api.jwt';
    let encJwk: any = null;
    if (encrypted) {
      encJwk = (data.client_metadata?.jwks?.keys ?? []).find((k: any) => k?.kty === 'EC' && k?.crv === 'P-256' && (!k.use || k.use === 'enc'));
      if (!encJwk) throw domError('TypeError', 'dc_api.jwt needs an EC P-256 encryption key in client_metadata.jwks');
    }
    const transcript = openId4VpDcApiSessionTranscript(this.pretendOrigin ?? origin, data.nonce, encJwk ? ecJwkThumbprintBytes(encJwk) : null);
    const deviceResponse = await DeviceResponse.from(this.mdoc)
      .usingPresentationDefinition(pd)
      .usingSessionTranscriptBytes(transcript)
      .authenticateWithSignature(this.devicePrivateJwk, 'ES256')
      .sign();
    const vpToken = { [cred.id]: [Buffer.from(deviceResponse.encode()).toString('base64url')] };
    this.answers++;
    if (!encrypted) return { protocol: req.protocol, data: { vp_token: vpToken } };

    const enc = Array.isArray(data.client_metadata?.encrypted_response_enc_values_supported)
      ? data.client_metadata.encrypted_response_enc_values_supported[0]
      : 'A128GCM';
    const key = await jose.importJWK({ kty: 'EC', crv: 'P-256', x: encJwk.x, y: encJwk.y }, 'ECDH-ES');
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(JSON.stringify({ vp_token: vpToken })))
      .setProtectedHeader({ alg: 'ECDH-ES', enc, ...(encJwk.kid ? { kid: encJwk.kid } : {}) })
      .encrypt(key);
    return { protocol: req.protocol, data: { response: jwe } };
  }

  /**
   * A stand-in for `navigator.credentials` on a page at `origin` (what the widget calls).
   * Like a browser, it needs the `digital` member and honours the abort signal.
   */
  credentialsFor(origin: string) {
    return {
      get: async (options: any) => {
        if (!Array.isArray(options?.digital?.requests)) throw domError('TypeError', 'Only digital credential requests are supported');
        if (options.signal?.aborted) throw domError('AbortError', 'Aborted');
        const answer = await this.answer(options.digital.requests, origin);
        return { type: 'digital', protocol: answer.protocol, data: answer.data };
      },
    };
  }
}
