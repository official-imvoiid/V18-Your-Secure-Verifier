import 'reflect-metadata';
import * as crypto from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  AttestationApplicationId,
  AttestationPackageInfo,
  AuthorizationList,
  id_ce_keyDescription,
  IntegerSet,
  KeyDescription,
  RootOfTrust,
} from '@peculiar/asn1-android';

/**
 * TEST ONLY: builds Android-style key attestation chains signed by a
 * generated TEST root (never a Google root). Used by the tests and by
 * `npm run dev-client` against a dev-mode server. A production server only
 * trusts Google's roots, so these chains never pass there.
 */

x509.cryptoProvider.set(crypto.webcrypto as unknown as Crypto);

const subtle = crypto.webcrypto.subtle;
const EC = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

export interface TestAttestationOptions {
  challenge: string;
  packageName?: string;
  /** SHA-256 of the app signing certificate (32 bytes). */
  signingCertDigest?: Buffer;
  securityLevel?: 0 | 1 | 2;
  origin?: number;
  verifiedBootState?: 0 | 1 | 2 | 3;
  deviceLocked?: boolean;
  /** Validity of the intermediate (default: a year around now). */
  intermediateNotAfter?: Date;
  /** Leave out the KeyDescription extension. */
  omitExtension?: boolean;
  /** "Now" for the certificate dates (tests use a fake clock). */
  nowMs?: number;
}

/** AttestationPackageInfo's OCTET STRING members are plain ArrayBuffers in the schema. */
const ab = (b: Buffer) => new Uint8Array(b).buffer as unknown as OctetString;

export const TEST_SIGNING_CERT_DIGEST = crypto.createHash('sha256').update('v18 TEST app signing certificate').digest();

export class TestAttestationRoot {
  private constructor(
    readonly rootCert: x509.X509Certificate,
    private readonly rootKey: CryptoKeyPair
  ) {}

  static async create(name = 'V18 TEST attestation root', nowMs = Date.now()): Promise<TestAttestationRoot> {
    const keys = (await subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
    const now = nowMs - 365 * 86_400_000;
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: crypto.randomBytes(8).toString('hex'),
      name: `CN=${name}, O=V18 TEST`,
      notBefore: new Date(now - 86_400_000),
      notAfter: new Date(now + 3650 * 86_400_000),
      keys,
      signingAlgorithm: SIGN,
      extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
    });
    return new TestAttestationRoot(cert, keys);
  }

  /** A chain (base64 DER, leaf first) attesting `devicePublicKey`. */
  async chainFor(devicePublicKey: crypto.KeyObject, o: TestAttestationOptions): Promise<string[]> {
    const now = o.nowMs ?? Date.now();
    const interKeys = (await subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
    const inter = await x509.X509CertificateGenerator.create({
      serialNumber: crypto.randomBytes(8).toString('hex'),
      subject: 'CN=V18 TEST attestation intermediate, O=V18 TEST',
      issuer: this.rootCert.subject,
      notBefore: new Date(now - 86_400_000),
      notAfter: o.intermediateNotAfter ?? new Date(now + 365 * 86_400_000),
      publicKey: interKeys.publicKey,
      signingKey: this.rootKey.privateKey,
      signingAlgorithm: SIGN,
      extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
    });

    const level = o.securityLevel ?? 1;
    const appId = new AttestationApplicationId({
      packageInfos: [
        new AttestationPackageInfo({ packageName: ab(Buffer.from(o.packageName ?? 'com.v18.app')), version: 1 }),
      ],
      signatureDigests: [ab(o.signingCertDigest ?? TEST_SIGNING_CERT_DIGEST)],
    });
    const kd = new KeyDescription({
      attestationVersion: 300,
      attestationSecurityLevel: level,
      keymasterVersion: 300,
      keymasterSecurityLevel: level,
      attestationChallenge: new OctetString(Buffer.from(o.challenge, 'utf8')),
      uniqueId: new OctetString(new Uint8Array(0)),
      softwareEnforced: new AuthorizationList({
        creationDateTime: now,
        attestationApplicationId: new OctetString(AsnConvert.serialize(appId)),
      }),
      teeEnforced: new AuthorizationList({
        purpose: new IntegerSet([2]),
        algorithm: 3,
        keySize: 256,
        ecCurve: 1,
        origin: o.origin ?? 0,
        rootOfTrust: new RootOfTrust({
          verifiedBootKey: new OctetString(crypto.randomBytes(32)),
          deviceLocked: o.deviceLocked ?? true,
          verifiedBootState: o.verifiedBootState ?? 0,
          verifiedBootHash: new OctetString(crypto.randomBytes(32)),
        }),
        osVersion: 160000,
        osPatchLevel: 202610,
      }),
    });

    const spki = devicePublicKey.export({ type: 'spki', format: 'der' });
    const jwk = devicePublicKey.export({ format: 'jwk' });
    const leafPublic =
      jwk.kty === 'EC'
        ? await subtle.importKey('spki', spki, EC, true, ['verify'])
        : await subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
    const leaf = await x509.X509CertificateGenerator.create({
      serialNumber: '01',
      subject: 'CN=Android Keystore Key',
      issuer: inter.subject,
      notBefore: new Date(0),
      notAfter: new Date(Date.UTC(2048, 0, 1)),
      publicKey: leafPublic,
      signingKey: interKeys.privateKey,
      signingAlgorithm: SIGN,
      extensions: o.omitExtension ? [] : [new x509.Extension(id_ce_keyDescription, false, AsnConvert.serialize(kd))],
    });
    return [leaf, inter, this.rootCert].map((c) => Buffer.from(c.rawData).toString('base64'));
  }
}
