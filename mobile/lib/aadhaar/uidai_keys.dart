import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart' as asn1;
import 'package:pointycastle/export.dart' as pc;

/// A public key that may have signed an Aadhaar Secure QR.
class AadhaarSigningKey {
  const AadhaarSigningKey({
    required this.name,
    required this.spkiPem,
    required this.isTestKey,
  });

  final String name;
  final String spkiPem;

  /// True for the Anon Aadhaar TEST key. Accepted only when the V18 server is
  /// in dev mode (PROTOCOL 3.1).
  final bool isTestKey;

  pc.RSAPublicKey get rsaKey => parseRsaSpkiPem(spkiPem);
}

/// UIDAI public keys (public certificates, safe to ship).
///
/// Source: the certificates bundled by Anon Aadhaar
/// (packages/circuits/assets/*.cer), which come from uidai.gov.in.
/// The public keys were taken out with `openssl x509 -pubkey`.
const List<AadhaarSigningKey> uidaiProductionKeys = [
  AadhaarSigningKey(
    name: 'UIDAI offline key (cert 26 Feb 2021)',
    isTestKey: false,
    spkiPem: '''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAonIsDl8t5bpwftk/A27C
sfC5VZMjkPrMDwvL8gyAoVwIi0iGhmty6yWrC/VaL+Brae29XMg7dMdwnbIUHmwH
xovN+FnT2vfz/O0kHQcgVdwVSIR0tFwsmC+pVKpSqm//skgYYcZQhdhLZBWOn0PZ
81ymm0jOkwBSIQKkyuCTv/1HSwjTLR0EBvaH9+Vb0iaiOEv1ikHDhMOXTxx8URWB
nJJt463z7LuZBMSG8fXVMDl3vqY1hDZzKbXBaK/clRIXMff0jUOvfPMfabHju+eU
nceosQwL3eurq96+oHahz4FmrfBqikHe3xQ7/4NdvSvVuwth0kcsI0ptRBG8m1Ng
lQIDAQAB
-----END PUBLIC KEY-----''',
  ),
  AadhaarSigningKey(
    name: 'UIDAI document signer key (cert 8 Jun 2017)',
    isTestKey: false,
    spkiPem: '''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv0HjbFpvu/kR+gTI2+sv
GNmW4eZHhTVBG/N+byaq3GH0SDM+jO5RW4BbXNzaSKc0I5mIyN1vQf2KmNV/3Xai
6MokiiZrBRfM8a497zCMteHTAzSP1L0DmohUuBQh/s1hfqRIIWpfEu7noW2G8toK
0ZOQR1E0FtinWNtqEeuxlNEKgfxkN4/vRzgvGFw+PPcoG5uMdcd7/DjDE1i20zmT
+55DgIBrneCwrW7nIM0Md3BPOTV8iBwzjdVcdDHhMtSpi9UKUHw80sDRZp7ygB4Z
0QmhSxCMCg9g7KPHYY+PVRC2sFreZBC6rtmIL+HMUPciRCCqMZLx3f6xRSD97lZr
/wIDAQAB
-----END PUBLIC KEY-----''',
  ),
];

/// Anon Aadhaar TEST signing key (packages/circuits/assets/testPublicKey.pem).
/// Its private key is public, so it proves nothing about a real person.
const AadhaarSigningKey anonAadhaarTestKey = AadhaarSigningKey(
  name: 'Anon Aadhaar TEST key',
  isTestKey: true,
  spkiPem: '''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlegfdQZZXMJirdz93TXY
BAVbKt9G3HGcVrWO7hmZle+hoyVHEGIKx4Ael29E475FTbDxkOP31ONZiXIRc0Te
Uvz3gm+ElIipWaez0h623QNFFmLqiD7u796ImhSZuaR/lQTF8JbCYrltI9GXUDMt
npfrYUHSYd6XmU1MQWPKnL4+B3IhtEJT3PgWCUKLaDUe4+m2DSs1H9qm7owoqEUj
n5fefMD+XRROR0gT+0PsWD+BtO4yjCIWczSJjSELoBeibsaJQPBd8ivZzIa7w6Q1
Q5I3LVZhZ3abc1uhLKNYD5GcG9i6cMTCqwrPKwm8L66YHzwClabh6fJI9QBzCU/6
8QIDAQAB
-----END PUBLIC KEY-----''',
);

/// Keys the phone trusts for this server. The test key only in dev mode.
List<AadhaarSigningKey> trustedAadhaarKeys({required bool devMode}) => [
      ...uidaiProductionKeys,
      if (devMode) anonAadhaarTestKey,
    ];

/// Parses an RSA SubjectPublicKeyInfo PEM with pointycastle's ASN.1 parser.
pc.RSAPublicKey parseRsaSpkiPem(String pem) {
  final b64 = pem
      .split('\n')
      .where((l) => !l.startsWith('-----'))
      .join()
      .replaceAll(RegExp(r'\s'), '');
  return parseRsaSpkiDer(Uint8List.fromList(base64.decode(b64)));
}

pc.RSAPublicKey parseRsaSpkiDer(Uint8List der) {
  final spki = asn1.ASN1Parser(der).nextObject() as asn1.ASN1Sequence;
  final alg = spki.elements![0] as asn1.ASN1Sequence;
  final oid = (alg.elements![0] as asn1.ASN1ObjectIdentifier).objectIdentifierAsString;
  if (oid != '1.2.840.113549.1.1.1') {
    throw const FormatException('Not an RSA public key');
  }
  final bitString = spki.elements![1] as asn1.ASN1BitString;
  final rsa = asn1.ASN1Parser(Uint8List.fromList(bitString.stringValues!))
      .nextObject() as asn1.ASN1Sequence;
  final n = (rsa.elements![0] as asn1.ASN1Integer).integer!;
  final e = (rsa.elements![1] as asn1.ASN1Integer).integer!;
  return pc.RSAPublicKey(n, e);
}
