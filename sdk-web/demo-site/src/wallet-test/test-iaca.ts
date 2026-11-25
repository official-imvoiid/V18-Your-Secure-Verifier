/**
 * TEST IACA. TEST ONLY. Never trust it outside tests and dev servers.
 *
 * An IACA (Issuing Authority Certificate Authority) is the root certificate a country or state
 * uses to sign the "document signer" certificates that seal mobile driving licences and PIDs
 * (ISO/IEC 18013-5 Annex B). This makes a throwaway one, in memory, with the country code "UT"
 * (the code ISO 18013-5 test documents use), so tests can make wallet answers that a verifier
 * can check end to end.
 */
import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;
/** ISO/IEC 18013-5 extended key usage for mdoc document signers. */
const EKU_MDL_DS = '1.0.18013.5.1.2';

export interface TestIssuer {
  /** The TEST IACA root certificate (PEM). A verifier trusts this. */
  iacaPem: string;
  /** The TEST document signer certificate (PEM), signed by the IACA. */
  dsPem: string;
  /** The document signer's private key (JWK), used to seal test mdocs. */
  dsPrivateJwk: JsonWebKey;
  country: string;
}

export interface CreateTestIssuerOptions {
  /** Shown in the certificate names. Default "V18 TEST IACA (test only)". */
  label?: string;
  country?: string;
  /** Load an existing IACA (certificate PEM + PKCS#8 private key PEM) instead of making one. */
  iaca?: { certPem: string; keyPem: string };
}

function pemBody(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const buf = Buffer.from(b64, 'base64');
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/** Makes (or loads) a TEST IACA and issues a TEST document signer certificate under it. */
export async function createTestIssuer(opts: CreateTestIssuerOptions = {}): Promise<TestIssuer> {
  const country = opts.country ?? 'UT';
  const label = opts.label ?? 'V18 TEST IACA (test only)';
  const now = Date.now();
  const notBefore = new Date(now - 24 * 3600_000);

  let iacaCert: x509.X509Certificate;
  let iacaPrivate: CryptoKey;
  if (opts.iaca) {
    iacaCert = new x509.X509Certificate(opts.iaca.certPem);
    iacaPrivate = await webcrypto.subtle.importKey('pkcs8', pemBody(opts.iaca.keyPem), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']) as CryptoKey;
  } else {
    const keys = (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
    iacaPrivate = keys.privateKey;
    iacaCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01' + Buffer.from(webcrypto.getRandomValues(new Uint8Array(8))).toString('hex'),
      name: `C=${country}, O=V18 test, CN=${label}`,
      notBefore,
      notAfter: new Date(now + 365 * 24 * 3600_000),
      signingAlgorithm: ALG,
      keys,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      ],
    });
  }

  const dsKeys = (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const dsCert = await x509.X509CertificateGenerator.create({
    serialNumber: '02' + Buffer.from(webcrypto.getRandomValues(new Uint8Array(8))).toString('hex'),
    subject: `C=${country}, O=V18 test, CN=V18 TEST document signer (test only)`,
    issuer: iacaCert.subject,
    notBefore,
    notAfter: new Date(now + 90 * 24 * 3600_000),
    signingAlgorithm: ALG,
    publicKey: dsKeys.publicKey,
    signingKey: iacaPrivate,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([EKU_MDL_DS], true),
      await x509.AuthorityKeyIdentifierExtension.create(await iacaCert.publicKey.export(webcrypto as unknown as Crypto)),
      await x509.SubjectKeyIdentifierExtension.create(dsKeys.publicKey),
    ],
  });

  return {
    iacaPem: iacaCert.toString('pem'),
    dsPem: dsCert.toString('pem'),
    dsPrivateJwk: await webcrypto.subtle.exportKey('jwk', dsKeys.privateKey),
    country,
  };
}
