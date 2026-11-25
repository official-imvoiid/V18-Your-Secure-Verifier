// =============================================================================
// NEEDS SECURITY REVIEW
//
// Country (CSCA) trust for passive authentication (ICAO Doc 9303 part 11
// section 5.1, part 12): the Document Signer (DS) certificate inside EF.SOD
// must be signed by a CSCA certificate from a trusted list, and the dates must
// fit. The trusted list is the German BSI CSCA Master List, bundled as
// assets/csca/master_list.ml exactly as BSI signed it (see
// tool/master_list/update_master_list.py, which checks BSI's signature before
// bundling, and docs/mobile/WALKTHROUGH.md for how to update it).
//
// Signature maths is pointycastle's (via passive_auth.dart). This file only
// reads DER and compares names, key identifiers and dates.
// =============================================================================

import 'dart:typed_data';

import 'package:flutter/services.dart' show rootBundle;
import 'package:pointycastle/export.dart' as pc;

import '../crypto/b64.dart';
import 'passive_auth.dart';

/// The parts of an X.509 certificate passive authentication needs.
class X509 {
  X509._(
    this.der,
    this.tbs,
    this.sigAlg,
    this.signature,
    this.issuer,
    this.subject,
    this.notBefore,
    this.notAfter,
    this.spki,
    this.subjectKeyId,
    this.authorityKeyId,
  );

  factory X509.parse(Der cert) {
    final parts = cert.children;
    final tbs = parts[0];
    final t = tbs.children;
    final i = t[0].tag == 0xA0 ? 1 : 0;
    final validity = t[i + 3].children;
    Uint8List? ski;
    Uint8List? aki;
    for (final d in t.skip(i + 6)) {
      if (d.tag != 0xA3) continue; // [3] extensions
      for (final ext in d.children.first.children) {
        final e = ext.children;
        final oid = e[0].oid;
        final value = e.last.value; // OCTET STRING contents
        if (oid == '2.5.29.14') {
          ski = Uint8List.fromList(Der.read(value).value);
        } else if (oid == '2.5.29.35') {
          for (final c in Der.read(value).children) {
            if (c.tag == 0x80) aki = Uint8List.fromList(c.value);
          }
        }
      }
    }
    return X509._(
      cert,
      tbs,
      parts[1],
      Uint8List.fromList(Uint8List.sublistView(parts[2].value, 1)),
      t[i + 2],
      t[i + 4],
      _time(validity[0]),
      _time(validity[1]),
      t[i + 5].children,
      ski,
      aki,
    );
  }

  static X509 fromBytes(Uint8List b) => X509.parse(Der.read(b));

  final Der der;
  final Der tbs;
  final Der sigAlg;
  final Uint8List signature;
  final Der issuer;
  final Der subject;
  final DateTime notBefore;
  final DateTime notAfter;
  final List<Der> spki;
  final Uint8List? subjectKeyId;
  final Uint8List? authorityKeyId;

  /// Curve parameters of this certificate's EC key, if any (for DS keys that inherit them).
  Der? get ecParams {
    final a = spki[0].children;
    return a.length > 1 && a[1].tag != 0x05 ? a[1] : null;
  }

  /// C= in a name (two letters), if present.
  static String? countryOf(Der name) {
    for (final rdn in name.children) {
      for (final atv in rdn.children) {
        final kv = atv.children;
        if (kv.length >= 2 && kv[0].tag == 0x06 && kv[0].oid == '2.5.4.6') {
          return String.fromCharCodes(kv[1].value).toUpperCase();
        }
      }
    }
    return null;
  }

  String? get subjectCountry => countryOf(subject);
  String? get issuerCountry => countryOf(issuer);

  /// Verifies this certificate's signature with [issuerCert]'s public key.
  bool signedBy(X509 issuerCert) {
    final (ok, _) = verifySignatureWithKey(
      issuerCert.spki,
      sigAlg,
      tbs.encoded,
      signature,
      inheritedEcParams: issuerCert.ecParams,
    );
    return ok;
  }

  static DateTime _time(Der d) {
    final s = String.fromCharCodes(d.value);
    // UTCTime YYMMDDHHMM[SS]Z or GeneralizedTime YYYYMMDDHHMM[SS]Z.
    final m = RegExp(r'^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$').firstMatch(s);
    if (m == null) throw FormatException('Unsupported certificate time $s');
    var y = int.parse(m[1]!);
    if (d.tag == 0x17) y = y >= 50 ? 1900 + y : 2000 + y;
    return DateTime.utc(
      y,
      int.parse(m[2]!),
      int.parse(m[3]!),
      int.parse(m[4]!),
      int.parse(m[5]!),
      int.parse(m[6] ?? '0'),
    );
  }
}

class ChainCheck {
  ChainCheck.ok(this.cscaCountry) : ok = true, problem = null;
  ChainCheck.fail(this.problem, [this.cscaCountry]) : ok = false;

  final bool ok;
  final String? cscaCountry;
  final String? problem;
}

/// Trusted CSCA certificates (a CSCA master list).
class CscaTrust {
  CscaTrust(List<X509> cscas) : _bySubject = {} {
    for (final c in cscas) {
      _bySubject.putIfAbsent(bytesToHex(c.subject.encoded), () => []).add(c);
    }
    count = cscas.length;
  }

  final Map<String, List<X509>> _bySubject;
  late final int count;

  /// SHA-256 of the bundled assets/csca/master_list.ml (from master_list.json).
  static const String bundledSha256 = '2bc0f28b35d83f2fc2d1495b1c715add358dfb9ba343e9788bc27a19ced13a9f';
  static const String bundledAsset = 'assets/csca/master_list.ml';

  static CscaTrust? _bundled;

  /// The bundled BSI master list, checked against its SHA-256 pin.
  static Future<CscaTrust> bundled() async {
    if (_bundled != null) return _bundled!;
    final data = await rootBundle.load(bundledAsset);
    final bytes = data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
    return _bundled = fromMasterList(bytes, expectSha256: bundledSha256);
  }

  /// Parses an ICAO CSCA master list (CMS SignedData with a CscaMasterList,
  /// ICAO 9303 part 12 section 9). The CMS signature itself is checked when
  /// the file is bundled (tool/master_list/update_master_list.py); here the
  /// file must match its SHA-256 pin.
  static CscaTrust fromMasterList(Uint8List ml, {String? expectSha256}) {
    if (expectSha256 != null && bytesToHex(pc.SHA256Digest().process(ml)) != expectSha256) {
      throw const FormatException('The bundled CSCA master list does not match its SHA-256 pin');
    }
    final contentInfo = Der.read(ml).children;
    if (contentInfo[0].oid != '1.2.840.113549.1.7.2') {
      throw const FormatException('Not a CMS SignedData master list');
    }
    final signedData = contentInfo[1].children.first.children;
    final encap = signedData[2].children;
    if (encap[0].oid != '2.23.136.1.1.2') {
      throw const FormatException('Not an ICAO CSCA master list (wrong content type)');
    }
    final content = encap[1].children.first.value; // [0] EXPLICIT OCTET STRING
    final list = Der.read(content).children; // version, certList
    final certs = <X509>[];
    for (final c in list[1].children) {
      try {
        certs.add(X509.parse(c));
      } on Object {
        // Skip an entry this parser cannot read; it then simply is not trusted.
      }
    }
    return CscaTrust(certs);
  }

  /// Checks a Document Signer certificate (ICAO 9303-11 5.1 step 3):
  /// - a CSCA in the list has the DS certificate's issuer name (and, when both
  ///   are present, the DS's authority key ID equals the CSCA's subject key ID);
  /// - the DS certificate's signature verifies with that CSCA's key;
  /// - the CSCA was valid when the DS certificate was issued;
  /// - the DS certificate is valid now (documents keep working during the DS
  ///   certificate's whole validity, which covers the document's own life).
  ChainCheck check(X509 dsc, DateTime now) {
    final candidates = _bySubject[bytesToHex(dsc.issuer.encoded)] ?? const [];
    if (candidates.isEmpty) {
      return ChainCheck.fail(
        "This document's country certificate is not in V18's list of trusted countries.",
        dsc.issuerCountry,
      );
    }
    for (final csca in candidates) {
      final aki = dsc.authorityKeyId;
      final ski = csca.subjectKeyId;
      if (aki != null && ski != null && !bytesEqual(aki, ski)) continue;
      if (!dsc.signedBy(csca)) continue;
      if (dsc.notBefore.isBefore(csca.notBefore) || dsc.notBefore.isAfter(csca.notAfter)) continue;
      if (now.isBefore(dsc.notBefore) || now.isAfter(dsc.notAfter)) {
        return ChainCheck.fail("The document signer's certificate is not valid today.", csca.subjectCountry);
      }
      return ChainCheck.ok(csca.subjectCountry);
    }
    return ChainCheck.fail(
      "The document's seal was not made by its country's certificate.",
      dsc.issuerCountry,
    );
  }

  /// Every CSCA (for tests and the "about" screen).
  Iterable<X509> get all => _bySubject.values.expand((l) => l);
}
