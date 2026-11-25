import 'reflect-metadata';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as x509 from '@peculiar/x509';
import { DeviceResponse, Document, MDoc } from '@auth0/mdl';
import { CompactEncrypt, importJWK } from 'jose';
import { MDL_DOCTYPE, MDL_NAMESPACE, PID_DOCTYPE, PID_NAMESPACE, sessionTranscriptBytes, WALLET_PROTOCOL } from './mdoc.js';

/**
 * TEST ONLY. A TEST IACA (issuing authority root), a document signer, test
 * mdocs (mDL or EU PID) and a test wallet answer. A production server never
 * trusts this IACA: it is loaded only when V18_DEV_MODE=1.
 */

x509.cryptoProvider.set(crypto.webcrypto as unknown as Crypto);
const subtle = crypto.webcrypto.subtle;
const EC = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

export interface TestIaca {
  iacaPem: string;
  dsPem: string;
  dsPrivateJwk: JsonWebKey;
}

async function pem(cert: x509.X509Certificate): Promise<string> {
  return cert.toString('pem');
}

export async function createTestIaca(opts: { name?: string; country?: string } = {}): Promise<TestIaca & { iacaPrivateJwk: JsonWebKey }> {
  const c = opts.country ?? 'XX';
  const iacaKeys = (await subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const now = Date.now();
  const iaca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomBytes(8).toString('hex'),
    name: `C=${c}, O=V18 TEST, CN=${opts.name ?? 'V18 TEST IACA (not a real issuer)'}`,
    notBefore: new Date(now - 2 * 86_400_000),
    notAfter: new Date(now + 5 * 365 * 86_400_000),
    keys: iacaKeys,
    signingAlgorithm: SIGN,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  const dsKeys = (await subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const ds = await x509.X509CertificateGenerator.create({
    serialNumber: crypto.randomBytes(8).toString('hex'),
    subject: `C=${c}, O=V18 TEST, CN=V18 TEST document signer`,
    issuer: iaca.subject,
    notBefore: new Date(now - 86_400_000),
    notAfter: new Date(now + 2 * 365 * 86_400_000),
    publicKey: dsKeys.publicKey,
    signingKey: iacaKeys.privateKey,
    signingAlgorithm: SIGN,
    extensions: [
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension(['1.0.18013.5.1.2'], true),
    ],
  });
  return {
    iacaPem: await pem(iaca),
    dsPem: await pem(ds),
    dsPrivateJwk: (await subtle.exportKey('jwk', dsKeys.privateKey)) as JsonWebKey,
    iacaPrivateJwk: (await subtle.exportKey('jwk', iacaKeys.privateKey)) as JsonWebKey,
  };
}

/** Dev mode: keeps one TEST IACA in assets/iaca/test/ so a dev server and the web test wallet share it. */
export async function loadOrCreateDevIaca(iacaDir: string): Promise<TestIaca> {
  const dir = path.join(iacaDir, 'test');
  const files = {
    iaca: path.join(dir, 'v18-test-iaca.pem'),
    ds: path.join(dir, 'v18-test-ds.cert'),
    dsKey: path.join(dir, 'v18-test-ds.key.json'),
  };
  if (fs.existsSync(files.iaca) && fs.existsSync(files.ds) && fs.existsSync(files.dsKey)) {
    // The files start with a "TEST ONLY" comment; keep only the PEM block.
    const pemOf = (f: string) => fs.readFileSync(f, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)![0];
    return {
      iacaPem: pemOf(files.iaca),
      dsPem: pemOf(files.ds),
      dsPrivateJwk: JSON.parse(fs.readFileSync(files.dsKey, 'utf8')) as JsonWebKey,
    };
  }
  const t = await createTestIaca();
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(files.iaca, `# TEST ONLY: V18 TEST IACA. Trusted only by dev-mode servers.\n${t.iacaPem}\n`);
  fs.writeFileSync(files.ds, `# TEST ONLY: V18 TEST document signer (issued by the TEST IACA).\n${t.dsPem}\n`);
  fs.writeFileSync(files.dsKey, JSON.stringify({ _note: 'TEST ONLY private key of the V18 TEST document signer', ...t.dsPrivateJwk }, null, 2));
  return t;
}

export interface TestHolder {
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

export function newHolderKey(): TestHolder {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { publicJwk: publicKey.export({ format: 'jwk' }) as JsonWebKey, privateJwk: privateKey.export({ format: 'jwk' }) as JsonWebKey };
}

/** Issues a TEST mdoc (mDL or EU PID) holding only age_over_18 (plus a dummy test field). */
export async function issueTestMdoc(opts: {
  iaca: TestIaca;
  holder: TestHolder;
  ageOver18: boolean;
  docType?: typeof MDL_DOCTYPE | typeof PID_DOCTYPE;
  validUntil?: Date;
  validFrom?: Date;
}): Promise<Uint8Array> {
  const docType = opts.docType ?? MDL_DOCTYPE;
  const ns = docType === MDL_DOCTYPE ? MDL_NAMESPACE : PID_NAMESPACE;
  const now = new Date();
  const { _note: _drop, ...dsKey } = opts.iaca.dsPrivateJwk as JsonWebKey & { _note?: string };
  const doc = await new Document(docType)
    .addIssuerNameSpace(ns, { age_over_18: opts.ageOver18, issuing_authority: 'V18 TEST' })
    .useDigestAlgorithm('SHA-256')
    .addValidityInfo({
      signed: now,
      validFrom: opts.validFrom ?? new Date(now.getTime() - 60_000),
      validUntil: opts.validUntil ?? new Date(now.getTime() + 365 * 86_400_000),
    })
    .addDeviceKeyInfo({ deviceKey: opts.holder.publicJwk as never })
    .sign({ issuerPrivateKey: dsKey as never, issuerCertificate: opts.iaca.dsPem, alg: 'ES256' });
  return new MDoc([doc]).encode();
}

/**
 * What a wallet sends back through the browser: a DeviceResponse with only
 * age_over_18, device-signed over the SessionTranscript, encrypted to the
 * request's key (OpenID4VP dc_api.jwt).
 */
export async function testWalletAnswer(opts: {
  mdoc: Uint8Array;
  holder: TestHolder;
  request: { data: Record<string, any> };
  origin: string;
  /** Sign over a different nonce (to test the nonce check). */
  nonceOverride?: string;
  docType?: string;
  credentialId?: 'mdl' | 'pid';
}): Promise<{ protocol: string; data: { response: string } }> {
  const docType = opts.docType ?? MDL_DOCTYPE;
  const ns = docType === MDL_DOCTYPE ? MDL_NAMESPACE : PID_NAMESPACE;
  const encJwk = opts.request.data.client_metadata.jwks.keys[0] as JsonWebKey;
  const nonce = opts.nonceOverride ?? (opts.request.data.nonce as string);
  const transcript = await sessionTranscriptBytes(opts.origin, nonce, encJwk);
  const pd = {
    id: 'age',
    input_descriptors: [
      {
        id: docType,
        format: { mso_mdoc: { alg: ['ES256'] } },
        constraints: {
          limit_disclosure: 'required' as const,
          fields: [{ path: [`$['${ns}']['age_over_18']`], intent_to_retain: false }],
        },
      },
    ],
  };
  const dr = await DeviceResponse.from(opts.mdoc)
    .usingPresentationDefinition(pd as never)
    .usingSessionTranscriptBytes(transcript)
    .authenticateWithSignature(opts.holder.privateJwk as never, 'ES256')
    .sign();
  const vpToken = { [opts.credentialId ?? (docType === MDL_DOCTYPE ? 'mdl' : 'pid')]: [Buffer.from(dr.encode()).toString('base64url')] };
  const key = await importJWK({ kty: 'EC', crv: encJwk.crv, x: encJwk.x, y: encJwk.y } as never, 'ECDH-ES');
  const jwe = await new CompactEncrypt(Buffer.from(JSON.stringify({ vp_token: vpToken })))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: (encJwk as { kid?: string }).kid })
    .encrypt(key as never);
  return { protocol: WALLET_PROTOCOL, data: { response: jwe } };
}
