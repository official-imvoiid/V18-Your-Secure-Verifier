// =============================================================================
// NEEDS SECURITY REVIEW
//
// Passive authentication of an ePassport / eID chip, on the phone
// (ICAO Doc 9303 part 11 section 5.1):
//   1. The hash of each data group read (DG1, ...) matches the hash stored in
//      EF.SOD's LDS Security Object.
//   2. EF.SOD's CMS signature is valid for the Document Signer certificate
//      inside EF.SOD.
//   3. The Document Signer certificate is signed by a country (CSCA)
//      certificate from the bundled CSCA master list (csca.dart), and the
//      dates fit. Without step 3 a chip re-signed by a home-made certificate
//      would pass steps 1-2.
//
// Signature maths is done by pointycastle (RSA PKCS#1 v1.5, RSA-PSS, ECDSA).
// This file only walks the DER structure to find the right bytes.
// =============================================================================

import 'dart:typed_data';

import 'package:pointycastle/ecc/ecc_fp.dart' as fp;
import 'package:pointycastle/export.dart' as pc;

import '../crypto/b64.dart';
import 'csca.dart';

/// A DER TLV node (definite lengths only).
class Der {
  Der._(this.tag, this.encoded, this.valueOffset);

  /// Reads one TLV from [bytes] at [offset].
  factory Der.read(Uint8List bytes, [int offset = 0]) {
    var p = offset;
    if (p >= bytes.length) throw const FormatException('DER: no data');
    var tag = bytes[p++];
    if (tag & 0x1F == 0x1F) {
      // High tag number form.
      int b;
      do {
        if (p >= bytes.length) throw const FormatException('DER: bad tag');
        b = bytes[p++];
        tag = (tag << 8) | b;
      } while (b & 0x80 != 0);
    }
    if (p >= bytes.length) throw const FormatException('DER: no length');
    var len = bytes[p++];
    if (len == 0x80) {
      throw const FormatException('DER: indefinite length not supported');
    }
    if (len & 0x80 != 0) {
      final n = len & 0x7F;
      if (n > 4) throw const FormatException('DER: length too long');
      len = 0;
      for (var i = 0; i < n; i++) {
        len = (len << 8) | bytes[p++];
      }
    }
    if (p + len > bytes.length) throw const FormatException('DER: truncated');
    return Der._(tag, Uint8List.sublistView(bytes, offset, p + len), p - offset);
  }

  final int tag;

  /// The whole TLV.
  final Uint8List encoded;
  final int valueOffset;

  Uint8List get value => Uint8List.sublistView(encoded, valueOffset);

  List<Der> get children {
    final out = <Der>[];
    final v = value;
    var p = 0;
    while (p < v.length) {
      final d = Der.read(v, p);
      out.add(d);
      p += d.encoded.length;
    }
    return out;
  }

  String get oid {
    if (tag != 0x06) throw const FormatException('DER: not an OID');
    final v = value;
    final parts = <int>[v[0] ~/ 40, v[0] % 40];
    var acc = 0;
    for (var i = 1; i < v.length; i++) {
      acc = (acc << 7) | (v[i] & 0x7F);
      if (v[i] & 0x80 == 0) {
        parts.add(acc);
        acc = 0;
      }
    }
    return parts.join('.');
  }

  BigInt get integer {
    final v = value;
    var r = BigInt.zero;
    for (final b in v) {
      r = (r << 8) | BigInt.from(b);
    }
    if (v.isNotEmpty && v[0] & 0x80 != 0) {
      r -= BigInt.one << (v.length * 8);
    }
    return r;
  }
}

class LdsSecurityObject {
  LdsSecurityObject(this.hashAlgorithmOid, this.dataGroupHashes);
  final String hashAlgorithmOid;
  final Map<int, Uint8List> dataGroupHashes;
}

/// Result of passive authentication. Every field is shown honestly in the UI.
class PassiveAuthResult {
  PassiveAuthResult({
    required this.dataGroupsChecked,
    required this.dataGroupHashesMatch,
    required this.signatureValid,
    required this.signatureAlgorithm,
    this.countryChainChecked = false,
    this.cscaCountry,
    this.problem,
  });

  /// Data group numbers whose hashes were compared.
  final List<int> dataGroupsChecked;
  final bool dataGroupHashesMatch;

  /// The SOD signature checks out against the Document Signer certificate.
  final bool signatureValid;
  final String signatureAlgorithm;

  /// The Document Signer certificate is signed by a CSCA certificate from
  /// the bundled master list, and its dates are valid.
  final bool countryChainChecked;

  /// The CSCA's country (C= in its name), for the confirmation screen.
  final String? cscaCountry;

  final String? problem;

  bool get passed => dataGroupHashesMatch && signatureValid && countryChainChecked;
}

/// Parses EF.SOD and checks it against the data groups that were read.
/// [dataGroups] maps DG number -> the full EF bytes as read from the chip.
///
/// With [trust] (the CSCA master list) the Document Signer certificate must
/// also chain to a CSCA from that list (step 3). Without it, step 3 is
/// reported as not checked and [PassiveAuthResult.passed] is false.
PassiveAuthResult passiveAuthenticate(
  Uint8List efSod,
  Map<int, Uint8List> dataGroups, {
  CscaTrust? trust,
  DateTime? now,
}) {
  try {
    final sod = _SignedSod.parse(efSod);
    final lds = sod.lds;
    final digestName = _hashNames[lds.hashAlgorithmOid];
    if (digestName == null) {
      return _fail('Unknown hash algorithm ${lds.hashAlgorithmOid}');
    }
    var allMatch = dataGroups.isNotEmpty;
    for (final entry in dataGroups.entries) {
      final expected = lds.dataGroupHashes[entry.key];
      final actual = pc.Digest(digestName).process(entry.value);
      if (expected == null || !bytesEqual(expected, actual)) allMatch = false;
    }
    final (sigOk, algName) = sod.verifySignature();
    ChainCheck? chain;
    if (trust != null) chain = trust.check(X509.parse(sod.certificate), now ?? DateTime.now());
    final chainOk = chain?.ok == true;
    return PassiveAuthResult(
      dataGroupsChecked: dataGroups.keys.toList()..sort(),
      dataGroupHashesMatch: allMatch,
      signatureValid: sigOk,
      signatureAlgorithm: algName,
      countryChainChecked: chainOk,
      cscaCountry: chain?.cscaCountry,
      problem: !(allMatch && sigOk)
          ? 'The chip data does not match its seal.'
          : trust == null
          ? 'The country certificate was not checked.'
          : chainOk
          ? null
          : chain!.problem,
    );
  } on Object catch (e) {
    return _fail('Could not read the chip seal ($e)');
  }
}

PassiveAuthResult _fail(String why) => PassiveAuthResult(
  dataGroupsChecked: const [],
  dataGroupHashesMatch: false,
  signatureValid: false,
  signatureAlgorithm: 'unknown',
  problem: why,
);

const Map<String, String> _hashNames = {
  '1.3.14.3.2.26': 'SHA-1',
  '2.16.840.1.101.3.4.2.4': 'SHA-224',
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
};

// RSA signature OIDs -> hash name
const Map<String, String> _rsaSigHashes = {
  '1.2.840.113549.1.1.5': 'SHA-1',
  '1.2.840.113549.1.1.14': 'SHA-224',
  '1.2.840.113549.1.1.11': 'SHA-256',
  '1.2.840.113549.1.1.12': 'SHA-384',
  '1.2.840.113549.1.1.13': 'SHA-512',
};

// ECDSA signature OIDs -> hash name
const Map<String, String> _ecdsaSigHashes = {
  '1.2.840.10045.4.1': 'SHA-1',
  '1.2.840.10045.4.3.1': 'SHA-224',
  '1.2.840.10045.4.3.2': 'SHA-256',
  '1.2.840.10045.4.3.3': 'SHA-384',
  '1.2.840.10045.4.3.4': 'SHA-512',
};

const Map<String, String> _digestInfoPrefix = {
  'SHA-1': '06052b0e03021a',
  'SHA-224': '0609608648016503040204',
  'SHA-256': '0609608648016503040201',
  'SHA-384': '0609608648016503040202',
  'SHA-512': '0609608648016503040203',
};

const Map<String, String> _namedCurves = {
  '1.2.840.10045.3.1.7': 'prime256v1',
  '1.3.132.0.33': 'secp224r1',
  '1.3.132.0.34': 'secp384r1',
  '1.3.132.0.35': 'secp521r1',
  '1.3.36.3.3.2.8.1.1.5': 'brainpoolp224r1',
  '1.3.36.3.3.2.8.1.1.7': 'brainpoolp256r1',
  '1.3.36.3.3.2.8.1.1.9': 'brainpoolp320r1',
  '1.3.36.3.3.2.8.1.1.11': 'brainpoolp384r1',
  '1.3.36.3.3.2.8.1.1.13': 'brainpoolp512r1',
};

class _SignedSod {
  _SignedSod(this.lds, this._eContent, this._signerInfo, this._certificate, this._digestOid);

  factory _SignedSod.parse(Uint8List efSod) {
    var root = Der.read(efSod);
    if (root.tag == 0x77) root = root.children.first; // EF.SOD wrapper
    final contentInfo = root.children;
    if (contentInfo[0].oid != '1.2.840.113549.1.7.2') {
      throw const FormatException('EF.SOD is not CMS SignedData');
    }
    final signedData = contentInfo[1].children.first.children;
    // version, digestAlgorithms, encapContentInfo, [0] certs?, [1] crls?, signerInfos
    final encap = signedData[2].children;
    final eContent = encap[1].children.first.value; // [0] EXPLICIT OCTET STRING
    Der? certs;
    for (final d in signedData.skip(3)) {
      if (d.tag == 0xA0) certs = d;
    }
    final signerInfos = signedData.last;
    if (signerInfos.tag != 0x31) throw const FormatException('No signerInfos');
    final signerInfo = signerInfos.children.first;
    if (certs == null || certs.children.isEmpty) {
      throw const FormatException('No Document Signer certificate in EF.SOD');
    }
    final ldsSeq = Der.read(eContent).children;
    final hashOid = ldsSeq[1].children.first.oid;
    final hashes = <int, Uint8List>{};
    for (final dgh in ldsSeq[2].children) {
      final c = dgh.children;
      hashes[c[0].integer.toInt()] = Uint8List.fromList(c[1].value);
    }
    final digestOid = signerInfo.children[2].children.first.oid;
    return _SignedSod(
      LdsSecurityObject(hashOid, hashes),
      eContent,
      signerInfo,
      certs.children.first,
      digestOid,
    );
  }

  final LdsSecurityObject lds;
  final Uint8List _eContent;
  final Der _signerInfo;
  final Der _certificate;
  final String _digestOid;

  /// The Document Signer certificate inside EF.SOD.
  Der get certificate => _certificate;

  (bool, String) verifySignature() {
    final si = _signerInfo.children;
    // version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature
    var idx = 3;
    Uint8List signedBytes = _eContent;
    final digestName = _hashNames[_digestOid];
    if (digestName == null) return (false, 'unknown digest $_digestOid');
    if (si[idx].tag == 0xA0) {
      final attrs = si[idx];
      // messageDigest attribute must equal hash(eContent).
      Uint8List? md;
      for (final attr in attrs.children) {
        final a = attr.children;
        if (a[0].oid == '1.2.840.113549.1.9.4') {
          md = a[1].children.first.value;
        }
      }
      final contentHash = pc.Digest(digestName).process(_eContent);
      if (md == null || !bytesEqual(md, contentHash)) {
        return (false, 'messageDigest mismatch');
      }
      // Signed attributes are signed as a DER SET (tag 0x31), not [0].
      signedBytes = Uint8List.fromList(attrs.encoded)..[0] = 0x31;
      idx++;
    }
    final signature = Uint8List.fromList(si[idx + 1].value);
    final spki = _subjectPublicKeyInfo(_certificate);
    return verifySignatureWithKey(spki, si[idx], signedBytes, signature, fallbackDigest: digestName);
  }

  static List<Der> _subjectPublicKeyInfo(Der cert) => subjectPublicKeyInfo(cert);
}

/// SubjectPublicKeyInfo children of an X.509 certificate: [algorithm, key].
List<Der> subjectPublicKeyInfo(Der cert) {
  final tbs = cert.children.first.children;
  var i = 0;
  if (tbs[0].tag == 0xA0) i = 1; // [0] version
  // serial, signature, issuer, validity, subject, subjectPublicKeyInfo
  return tbs[i + 5].children;
}

/// Verifies [signature] over [data] with the public key in [spki]
/// (RSA PKCS#1 v1.5, RSA-PSS or ECDSA, named or explicit curves). [sigAlg]
/// is the AlgorithmIdentifier of the signature. [inheritedEcParams] is used
/// when an EC key has no parameters of its own (they come from the issuer).
(bool, String) verifySignatureWithKey(
  List<Der> spki,
  Der sigAlgId,
  Uint8List data,
  Uint8List signature, {
  String? fallbackDigest,
  Der? inheritedEcParams,
}) {
  final sigAlg = sigAlgId.children;
  final sigAlgOid = sigAlg[0].oid;
  final keyAlgOid = spki[0].children.first.oid;
  if (keyAlgOid == '1.2.840.113549.1.1.1' || keyAlgOid == '1.2.840.113549.1.1.10') {
    final key = _rsaKey(spki);
    if (sigAlgOid == '1.2.840.113549.1.1.10') {
      return (_verifyRsaPss(key, sigAlg, data, signature), 'RSA-PSS');
    }
    final hash = _rsaSigHashes[sigAlgOid] ?? (sigAlgOid == '1.2.840.113549.1.1.1' ? fallbackDigest : null);
    if (hash == null) return (false, 'unknown RSA algorithm $sigAlgOid');
    final signer = pc.RSASigner(pc.Digest(hash), _digestInfoPrefix[hash]!)
      ..init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(key));
    try {
      return (signer.verifySignature(data, pc.RSASignature(signature)), 'RSA $hash');
    } on Object {
      return (false, 'RSA $hash');
    }
  }
  if (keyAlgOid == '1.2.840.10045.2.1') {
    final hash = _ecdsaSigHashes[sigAlgOid] ?? fallbackDigest;
    if (hash == null) return (false, 'unknown ECDSA algorithm $sigAlgOid');
    final algChildren = spki[0].children;
    final params = algChildren.length > 1 && algChildren[1].tag != 0x05 ? algChildren[1] : inheritedEcParams;
    if (params == null) return (false, 'EC key without curve parameters');
    final domain = ecDomain(params);
    final point = domain.curve.decodePoint(_bitString(spki[1]));
    final signer = pc.ECDSASigner(pc.Digest(hash))
      ..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(pc.ECPublicKey(point, domain)));
    try {
      final rs = Der.read(signature).children;
      return (signer.verifySignature(data, pc.ECSignature(rs[0].integer, rs[1].integer)), 'ECDSA $hash');
    } on Object {
      return (false, 'ECDSA $hash');
    }
  }
  return (false, 'unknown key type $keyAlgOid');
}

Uint8List _bitString(Der d) => Uint8List.sublistView(d.value, 1);

pc.RSAPublicKey _rsaKey(List<Der> spki) {
  final rsa = Der.read(_bitString(spki[1])).children;
  return pc.RSAPublicKey(rsa[0].integer, rsa[1].integer);
}

bool _verifyRsaPss(pc.RSAPublicKey key, List<Der> sigAlg, Uint8List data, Uint8List sig) {
  // RSASSA-PSS-params: [0] hashAlgorithm, [1] maskGenAlgorithm, [2] saltLength
  var hash = 'SHA-1';
  var mgfHash = 'SHA-1';
  var saltLen = 20;
  if (sigAlg.length > 1) {
    for (final p in sigAlg[1].children) {
      final inner = p.children.first;
      switch (p.tag) {
        case 0xA0:
          hash = _hashNames[inner.children.first.oid] ?? hash;
        case 0xA1:
          mgfHash = _hashNames[inner.children[1].children.first.oid] ?? mgfHash;
        case 0xA2:
          saltLen = inner.integer.toInt();
      }
    }
  }
  final signer = pc.PSSSigner(pc.RSAEngine(), pc.Digest(hash), pc.Digest(mgfHash));
  signer.init(
    false,
    pc.ParametersWithSaltConfiguration(
      pc.PublicKeyParameter<pc.RSAPublicKey>(key),
      pc.FortunaRandom()..seed(pc.KeyParameter(Uint8List(32))),
      saltLen,
    ),
  );
  try {
    return signer.verifySignature(data, pc.PSSSignature(sig));
  } on Object {
    return false;
  }
}

/// EC domain parameters from a named curve OID or explicit parameters.
pc.ECDomainParameters ecDomain(Der params) {
  if (params.tag == 0x06) {
    final name = _namedCurves[params.oid];
    if (name == null) throw FormatException('Unknown curve ${params.oid}');
    return pc.ECDomainParameters(name);
  }
  // Explicit parameters (used by some countries, for example Germany).
  final c = params.children;
  final prime = c[1].children[1].integer;
  final curveSeq = c[2].children;
  final a = _os2ip(curveSeq[0].value);
  final b = _os2ip(curveSeq[1].value);
  final curve = fp.ECCurve(prime, a, b);
  final g = curve.decodePoint(c[3].value)!;
  final n = c[4].integer;
  final h = c.length > 5 ? c[5].integer : BigInt.one;
  return pc.ECDomainParametersImpl('explicit', curve, g, n, h, null);
}

BigInt _os2ip(List<int> b) {
  var r = BigInt.zero;
  for (final x in b) {
    r = (r << 8) | BigInt.from(x);
  }
  return r;
}
