/** TEST ONLY: throwaway keys and certificates for the local mock providers. */
import { webcrypto } from 'node:crypto';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export async function jwkPair(alg: string, kid: string, use: 'sig' | 'enc'): Promise<{ privateJwk: JWK; publicJwk: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true, ...(alg.startsWith('RS') || alg.startsWith('RSA') ? { modulusLength: 2048 } : {}) });
  const privateJwk = { ...(await exportJWK(privateKey)), kid, alg, use };
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg, use };
  return { privateJwk, publicJwk };
}

function pem(label: string, der: ArrayBuffer): string {
  const b64 = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

export interface CertAndKey {
  certPem: string;
  keyPem: string;
  cert: x509.X509Certificate;
  keys: CryptoKeyPair;
}

const RSA = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

/** A self-signed RSA certificate (SAML signing). */
export async function selfSignedRsa(cn: string): Promise<CertAndKey> {
  const keys = (await webcrypto.subtle.generateKey(RSA, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${cn}`,
    notBefore: new Date(Date.now() - 86400000),
    notAfter: new Date(Date.now() + 365 * 86400000),
    signingAlgorithm: RSA,
    keys,
  });
  return { certPem: cert.toString('pem'), keyPem: pem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)), cert, keys };
}

/** A small test PKI for mutual TLS: a CA, a server certificate for 127.0.0.1 and a client certificate. */
export async function testPki(): Promise<{ ca: CertAndKey; server: CertAndKey; client: CertAndKey }> {
  const caKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=V18 TEST CA',
    notBefore: new Date(Date.now() - 86400000),
    notAfter: new Date(Date.now() + 365 * 86400000),
    signingAlgorithm: EC,
    keys: caKeys,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)],
  });
  const ca: CertAndKey = { certPem: caCert.toString('pem'), keyPem: pem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', caKeys.privateKey)), cert: caCert, keys: caKeys };

  async function leaf(cn: string, serial: string, server: boolean): Promise<CertAndKey> {
    const keys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
    const extensions: x509.Extension[] = [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.ExtendedKeyUsageExtension([server ? x509.ExtendedKeyUsage.serverAuth : x509.ExtendedKeyUsage.clientAuth]),
    ];
    if (server) extensions.push(new x509.SubjectAlternativeNameExtension([{ type: 'ip', value: '127.0.0.1' }, { type: 'dns', value: 'localhost' }]));
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: serial,
      subject: `CN=${cn}`,
      issuer: caCert.subject,
      notBefore: new Date(Date.now() - 86400000),
      notAfter: new Date(Date.now() + 365 * 86400000),
      signingAlgorithm: EC,
      publicKey: keys.publicKey,
      signingKey: caKeys.privateKey,
      extensions,
    });
    return { certPem: cert.toString('pem'), keyPem: pem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)), cert, keys };
  }
  return { ca, server: await leaf('127.0.0.1', '02', true), client: await leaf('V18 TEST RP', '03', false) };
}

/** A date string for someone who turns `age` years old `offsetDays` days from today (negative = already). */
export function birthDateForAge(age: number, offsetDays = -30): { y: number; m: number; d: number; iso: string } {
  const t = new Date();
  const b = new Date(Date.UTC(t.getUTCFullYear() - age, t.getUTCMonth(), t.getUTCDate() + offsetDays));
  const y = b.getUTCFullYear();
  const m = b.getUTCMonth() + 1;
  const d = b.getUTCDate();
  return { y, m, d, iso: `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}` };
}

export const pad = (n: number) => String(n).padStart(2, '0');
