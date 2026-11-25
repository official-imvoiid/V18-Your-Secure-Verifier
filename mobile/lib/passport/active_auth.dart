// =============================================================================
// NEEDS SECURITY REVIEW
//
// Active Authentication ("copy test", ICAO Doc 9303 part 11 section 6.1): the
// phone sends the chip a fresh random 8-byte challenge; the chip signs it with
// a private key that cannot be read out; the phone checks the signature with
// the public key from DG15 (whose hash is sealed in EF.SOD, so passive
// authentication must pass first). A copied chip has no private key.
//
// Supported here: ECDSA keys (BSI TR-03111 plain r||s signatures), with the
// hash named in DG14's ActiveAuthenticationInfo. RSA keys (ISO/IEC 9796-2)
// are NOT checked in this version: the result is then "notSupported" and the
// card request says chipAuth "none". Signature maths is pointycastle's.
// =============================================================================

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'passive_auth.dart';

enum ActiveAuthResult {
  /// The chip's signature over our challenge checked out.
  passed,

  /// The chip answered, but the signature is wrong: treat as a copied chip.
  failed,

  /// The document has no DG15 (no Active Authentication).
  notOffered,

  /// The chip uses a key type this version cannot check (RSA ISO 9796-2).
  notSupported,
}

/// ECDSA-plain signature algorithm OIDs (BSI TR-03111) -> hash.
const Map<String, String> _plainEcdsa = {
  '0.4.0.127.0.7.1.1.4.1.1': 'SHA-1',
  '0.4.0.127.0.7.1.1.4.1.2': 'SHA-224',
  '0.4.0.127.0.7.1.1.4.1.3': 'SHA-256',
  '0.4.0.127.0.7.1.1.4.1.4': 'SHA-384',
  '0.4.0.127.0.7.1.1.4.1.5': 'SHA-512',
  // X9.62 ecdsa-with-SHAxxx are also seen in DG14.
  '1.2.840.10045.4.1': 'SHA-1',
  '1.2.840.10045.4.3.1': 'SHA-224',
  '1.2.840.10045.4.3.2': 'SHA-256',
  '1.2.840.10045.4.3.3': 'SHA-384',
  '1.2.840.10045.4.3.4': 'SHA-512',
};

/// The signature algorithm OID from DG14's ActiveAuthenticationInfo
/// (2.23.136.1.1.5), or null if DG14 has none.
String? activeAuthAlgorithm(Uint8List? dg14) {
  if (dg14 == null) return null;
  try {
    var root = Der.read(dg14);
    if (root.tag == 0x6E) root = root.children.first; // DG14 wrapper -> SecurityInfos SET
    for (final info in root.children) {
      final c = info.children;
      if (c.isNotEmpty && c[0].tag == 0x06 && c[0].oid == '2.23.136.1.1.5' && c.length >= 3) {
        return c[2].oid;
      }
    }
  } on Object {
    return null;
  }
  return null;
}

/// True for the key type in DG15 that this version can check.
bool activeAuthSupported(Uint8List dg15) {
  try {
    return _spki(dg15)[0].children.first.oid == '1.2.840.10045.2.1';
  } on Object {
    return false;
  }
}

List<Der> _spki(Uint8List dg15) {
  var root = Der.read(dg15);
  if (root.tag == 0x6F) root = root.children.first; // DG15 wrapper
  return root.children;
}

/// Checks the chip's answer [signature] to [challenge].
ActiveAuthResult verifyActiveAuth({
  required Uint8List dg15,
  required Uint8List? dg14,
  required Uint8List challenge,
  required Uint8List signature,
}) {
  final List<Der> spki;
  try {
    spki = _spki(dg15);
  } on Object {
    return ActiveAuthResult.failed;
  }
  final keyOid = spki[0].children.first.oid;
  if (keyOid != '1.2.840.10045.2.1') return ActiveAuthResult.notSupported;
  final algOid = activeAuthAlgorithm(dg14);
  // ICAO 9303-11 6.1: for ECDSA, DG14 must name the signature algorithm.
  final hash = algOid == null ? null : _plainEcdsa[algOid];
  if (hash == null) return ActiveAuthResult.failed;
  try {
    final domain = ecDomain(spki[0].children[1]);
    final point = domain.curve.decodePoint(Uint8List.sublistView(spki[1].value, 1));
    final n = (domain.n.bitLength + 7) ~/ 8;
    if (signature.length != 2 * n) return ActiveAuthResult.failed;
    BigInt os2ip(List<int> b) => b.fold(BigInt.zero, (a, x) => (a << 8) | BigInt.from(x));
    final r = os2ip(signature.sublist(0, n));
    final s = os2ip(signature.sublist(n));
    final v = pc.ECDSASigner(pc.Digest(hash))
      ..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(pc.ECPublicKey(point, domain)));
    return v.verifySignature(challenge, pc.ECSignature(r, s)) ? ActiveAuthResult.passed : ActiveAuthResult.failed;
  } on Object {
    return ActiveAuthResult.failed;
  }
}
