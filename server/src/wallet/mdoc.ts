import 'reflect-metadata';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { DataItem, parse, Verifier } from '@auth0/mdl';
import { cborEncode } from '@auth0/mdl/lib/cbor';
import { calculateJwkThumbprint, compactDecrypt, decodeProtectedHeader, importJWK } from 'jose';
import { ApiError } from '../errors.js';
import { isPlainObject } from '../util.js';

/**
 * Phone wallet IDs (mDL and EU PID) over the browser's Digital Credentials
 * API, and from another wallet on the same phone (PROTOCOL.md 4c.5, 4d.3).
 *
 * Protocol: OpenID4VP 1.0 over the DC API, unsigned request
 * (`openid4vp-v1-unsigned`), DCQL asking ONLY for `age_over_18`, response
 * mode `dc_api.jwt` (the wallet encrypts its answer to a fresh key made for
 * this one request). Current Chrome supports it. The mdoc itself is checked
 * with the vetted `@auth0/mdl` library: issuer signature and certificate
 * chain to the IACA trust list, MSO validity, value digests, and the device
 * signature over the SessionTranscript, which contains the web origin, the
 * nonce and the encryption key's thumbprint (OpenID4VP 1.0 Appendix B.2.6.2):
 *
 *   SessionTranscript = [null, null, ["OpenID4VPDCAPIHandover",
 *                         SHA-256(CBOR([origin, nonce, jwkThumbprint]))]]
 */

export const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL';
export const MDL_NAMESPACE = 'org.iso.18013.5.1';
export const PID_DOCTYPE = 'eu.europa.ec.eudi.pid.1';
export const PID_NAMESPACE = 'eu.europa.ec.eudi.pid.1';
export const WALLET_PROTOCOL = 'openid4vp-v1-unsigned';

/** What the server keeps for one wallet request (deleted when used or expired). */
export interface WalletRequestState {
  nonce: string;
  encPrivateJwk: JsonWebKey;
  encPublicJwk: JsonWebKey;
  expiresAt: number;
}

export interface DigitalRequest {
  protocol: string;
  data: Record<string, unknown>;
}

/** A fresh request: new nonce (unless given) and a new P-256 key the wallet encrypts to. */
export async function newWalletRequest(nowMs: number, ttlMs: number, nonce?: string): Promise<{ state: WalletRequestState; request: DigitalRequest }> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pub = publicKey.export({ format: 'jwk' });
  const kid = (await calculateJwkThumbprint(pub as never, 'sha256')).slice(0, 16);
  const encPublicJwk: JsonWebKey = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, use: 'enc', alg: 'ECDH-ES', kid } as JsonWebKey;
  const state: WalletRequestState = {
    nonce: nonce ?? crypto.randomBytes(32).toString('base64url'),
    encPrivateJwk: privateKey.export({ format: 'jwk' }) as JsonWebKey,
    encPublicJwk,
    expiresAt: nowMs + ttlMs,
  };
  const claim = (ns: string) => [{ path: [ns, 'age_over_18'], intent_to_retain: false }];
  const request: DigitalRequest = {
    protocol: WALLET_PROTOCOL,
    data: {
      response_type: 'vp_token',
      response_mode: 'dc_api.jwt',
      nonce: state.nonce,
      dcql_query: {
        credentials: [
          { id: 'mdl', format: 'mso_mdoc', meta: { doctype_value: MDL_DOCTYPE }, claims: claim(MDL_NAMESPACE) },
          { id: 'pid', format: 'mso_mdoc', meta: { doctype_value: PID_DOCTYPE }, claims: claim(PID_NAMESPACE) },
        ],
        credential_sets: [{ options: [['mdl'], ['pid']] }],
      },
      client_metadata: {
        jwks: { keys: [encPublicJwk] },
        encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
        vp_formats_supported: { mso_mdoc: { issuerauth_alg_values: [-7, -35, -36], deviceauth_alg_values: [-7, -35, -36] } },
      },
    },
  };
  return { state, request };
}

/** CBOR SessionTranscript bytes (as a tag-24 DataItem, the form @auth0/mdl takes). */
export async function sessionTranscriptBytes(origin: string, nonce: string, encPublicJwk: JsonWebKey | null): Promise<Buffer> {
  const thumb = encPublicJwk
    ? Buffer.from(
        await calculateJwkThumbprint({ kty: 'EC', crv: encPublicJwk.crv, x: encPublicJwk.x, y: encPublicJwk.y } as never, 'sha256'),
        'base64url'
      )
    : null;
  const infoHash = crypto.createHash('sha256').update(cborEncode([origin, nonce, thumb])).digest();
  return cborEncode(DataItem.fromData([null, null, ['OpenID4VPDCAPIHandover', infoHash]]));
}

/** Android app origin as Credential Manager reports it: android:apk-key-hash:<base64url SHA-256 of the signing cert>. */
export function androidAppOrigin(certDigestHex: string): string {
  return `android:apk-key-hash:${Buffer.from(certDigestHex, 'hex').toString('base64url')}`;
}

// ---- Trust list -------------------------------------------------------------------

function toPem(file: string): string[] {
  const raw = fs.readFileSync(file);
  const text = raw.toString('utf8');
  if (text.includes('-----BEGIN CERTIFICATE-----')) {
    return text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  }
  const b64 = raw.toString('base64').match(/.{1,64}/g)!.join('\n');
  return [`-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`];
}

/**
 * IACA root certificates: every certificate file directly in assets/iaca/
 * (production), plus in dev mode only assets/iaca/test/ and V18_DEV_IACA_PEMS.
 */
export function loadIacaTrust(opts: { iacaDir: string; devMode: boolean; devIacaPems: string[] }): { pems: string[]; files: string[] } {
  const files: string[] = [];
  const add = (dir: string) => {
    if (!fs.existsSync(dir)) return;
    for (const f of fs.readdirSync(dir).sort()) {
      if (/\.(pem|crt|cer|der)$/i.test(f) && !/\.key\.pem$/i.test(f)) files.push(path.join(dir, f));
    }
  };
  add(opts.iacaDir);
  if (opts.devMode) {
    add(path.join(opts.iacaDir, 'test'));
    files.push(...opts.devIacaPems);
  }
  const pems = files.flatMap(toPem);
  for (const p of pems) new crypto.X509Certificate(p); // fail fast on a broken file
  return { pems, files };
}

// ---- Verify ---------------------------------------------------------------------------

export interface WalletResult {
  docType: string;
  validUntilMs: number;
  origin: string;
  /**
   * SHA-256 (hex) of the credential's own holder key from the signed MSO.
   * It is the same every time this wallet credential is shown, and says
   * nothing about the person, so it can cap cards per credential.
   */
  credentialKeyHash: string;
}

const invalid = (reason: string, message: string) => new ApiError(400, 'WALLET_INVALID', message, { reason });

function extractVpToken(payload: unknown): string {
  if (!isPlainObject(payload) || !isPlainObject(payload.vp_token)) throw invalid('malformed', 'The wallet answer has no vp_token');
  const entries = Object.entries(payload.vp_token).filter(([id]) => id === 'mdl' || id === 'pid');
  if (entries.length !== 1) throw invalid('malformed', 'The wallet answer must hold exactly one of the requested credentials');
  const v = entries[0][1];
  const list = Array.isArray(v) ? v : [v];
  if (list.length !== 1 || typeof list[0] !== 'string') throw invalid('malformed', 'Exactly one presentation is expected');
  return list[0];
}

interface Failure {
  id: string;
  category: string;
  reason?: string;
}

/**
 * Checks a wallet answer for a request this server made. `expectedOrigins`:
 * the website origin (widget), or the V18 app's Android origin(s) (mdoc_app).
 */
export async function verifyWalletResponse(opts: {
  response: unknown;
  state: WalletRequestState;
  expectedOrigins: string[];
  trustedIacas: string[];
  nowMs: number;
}): Promise<WalletResult> {
  if (opts.trustedIacas.length === 0) {
    throw new ApiError(503, 'METHOD_NOT_CONFIGURED', 'No wallet issuers (IACA certificates) are trusted on this server');
  }
  if (opts.nowMs > opts.state.expiresAt) throw new ApiError(410, 'WALLET_REQUEST_EXPIRED', 'This wallet request has expired');
  const r = opts.response;
  if (!isPlainObject(r) || r.protocol !== WALLET_PROTOCOL) {
    throw invalid('wrong_protocol', `response must be {protocol: "${WALLET_PROTOCOL}", data}`);
  }
  let data: unknown = r.data;
  if (typeof data === 'string') {
    try {
      data = JSON.parse(data);
    } catch {
      throw invalid('malformed', 'response.data is not JSON');
    }
  }
  if (!isPlainObject(data) || typeof data.response !== 'string' || data.response.length > 200_000) {
    throw invalid('not_encrypted', 'response.data.response must be the encrypted wallet answer (compact JWE)');
  }

  // 1. Decrypt with this request's one-time key.
  let payload: unknown;
  try {
    const header = decodeProtectedHeader(data.response);
    if (header.alg !== 'ECDH-ES' || !['A128GCM', 'A256GCM'].includes(String(header.enc))) throw new Error('alg');
    const key = await importJWK(opts.state.encPrivateJwk as never, 'ECDH-ES');
    const { plaintext } = await compactDecrypt(data.response, key as never);
    payload = JSON.parse(Buffer.from(plaintext).toString('utf8'));
  } catch {
    throw invalid('decrypt_failed', 'The wallet answer could not be decrypted for this request');
  }
  let deviceResponse: Buffer;
  try {
    deviceResponse = Buffer.from(extractVpToken(payload), 'base64url');
    parse(deviceResponse);
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw invalid('malformed', 'The presentation is not an mdoc DeviceResponse');
  }

  // 2. Verify with @auth0/mdl. Collect every failed check instead of stopping at the first.
  const verifier = new Verifier(opts.trustedIacas);
  let lastDeviceFailure: Failure | null = null;
  for (const origin of opts.expectedOrigins) {
    const failures: Failure[] = [];
    let mdoc: Awaited<ReturnType<Verifier['verify']>>;
    try {
      mdoc = await verifier.verify(deviceResponse, {
        encodedSessionTranscript: await sessionTranscriptBytes(origin, opts.state.nonce, opts.state.encPublicJwk),
        onCheck: (item) => {
          if (item.status === 'FAILED') failures.push({ id: item.id, category: item.category, reason: item.reason });
        },
      });
    } catch {
      throw invalid('malformed', 'The mdoc could not be read');
    }
    const issuer = failures.filter((f) => f.category === 'ISSUER_AUTH' || f.category === 'DATA_INTEGRITY' || f.category === 'DOCUMENT_FORMAT');
    if (issuer.some((f) => f.id === 'ISSUER_CERTIFICATE_VALIDITY')) {
      throw new ApiError(400, 'WALLET_UNTRUSTED_ISSUER', 'The ID was not issued by a trusted issuer (IACA)', { reason: 'untrusted_issuer' });
    }
    if (issuer.some((f) => f.id === 'MSO_VALIDITY_AT_VERIFICATION_TIME')) throw invalid('expired', 'The wallet ID is not valid right now');
    if (issuer.length > 0) throw invalid('tampered', `The wallet ID failed an issuer check (${issuer[0].id})`);
    const device = failures.filter((f) => f.category === 'DEVICE_AUTH');
    if (device.length > 0) {
      lastDeviceFailure = device[0];
      continue; // maybe another allowed origin
    }

    // 3. age_over_18, issuer-signed, in the right namespace.
    const doc = mdoc.documents[0];
    const ns = doc.docType === MDL_DOCTYPE ? MDL_NAMESPACE : doc.docType === PID_DOCTYPE ? PID_NAMESPACE : null;
    if (!ns || mdoc.documents.length !== 1) throw invalid('wrong_doctype', 'Only one mDL or EU PID is accepted');
    const age = doc.getIssuerNameSpace(ns)?.age_over_18;
    if (age === false) throw new ApiError(403, 'UNDER_AGE', 'The wallet ID says the holder is not over 18');
    if (age !== true) throw invalid('age_over_18_missing', 'The wallet did not share age_over_18');
    const mso = doc.issuerSigned.issuerAuth.decodedPayload;
    const holderKey = mso.deviceKeyInfo?.deviceKey;
    if (!holderKey) throw invalid('malformed', 'The mdoc has no holder key');
    const credentialKeyHash = crypto.createHash('sha256').update(cborEncode(holderKey)).digest('hex');
    return { docType: doc.docType, validUntilMs: new Date(mso.validityInfo.validUntil).getTime(), origin, credentialKeyHash };
  }
  throw invalid('device_auth_failed', `The wallet's device signature does not match this request (nonce or origin) [${lastDeviceFailure?.id ?? 'none'}]`);
}
