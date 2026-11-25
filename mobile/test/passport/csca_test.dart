// Real data: the German BSI CSCA master list bundled in assets/csca/.
// Every CSCA certificate in it is a real country certificate, so checking
// their signatures exercises the phone's RSA, RSA-PSS and ECDSA (named and
// explicit curve) code on real-world certificates from ~120 countries.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:v18/crypto/b64.dart';
import 'package:v18/passport/csca.dart';

void main() {
  final ml = File('assets/csca/master_list.ml').readAsBytesSync();
  final meta = jsonDecode(File('assets/csca/master_list.json').readAsStringSync()) as Map;

  test('the bundled master list matches its pin in the app and in master_list.json', () {
    final sha = bytesToHex(pc.SHA256Digest().process(ml));
    expect(sha, CscaTrust.bundledSha256);
    expect(sha, meta['sha256']);
    expect(() => CscaTrust.fromMasterList(Uint8List.fromList([...ml]..[100] ^= 1),
        expectSha256: CscaTrust.bundledSha256), throwsFormatException);
  });

  test('every certificate in the real BSI master list is read', () {
    final trust = CscaTrust.fromMasterList(ml, expectSha256: CscaTrust.bundledSha256);
    expect(trust.count, meta['certificates']);
    final countries = trust.all.map((c) => c.subjectCountry).toSet();
    for (final c in ['IN', 'DE', 'FR', 'GB', 'JP', 'SG', 'PH', 'NL', 'IT', 'CH']) {
      expect(countries, contains(c), reason: c);
    }
  });

  test('real CSCA signatures verify with the phone code (roots and link certificates)', () {
    final trust = CscaTrust.fromMasterList(ml);
    final all = trust.all.toList();
    var ok = 0, noIssuerInList = 0, bad = 0;
    final badList = <String>[];
    for (final c in all) {
      // Issuer: same name, and (when both are there) its subject key ID equals
      // this certificate's authority key ID. Link certificates share the name
      // but are signed by the country's previous key.
      final issuers = all.where((i) =>
          bytesEqual(i.subject.encoded, c.issuer.encoded) &&
          (c.authorityKeyId == null || i.subjectKeyId == null || bytesEqual(c.authorityKeyId!, i.subjectKeyId!)));
      if (issuers.isEmpty) {
        noIssuerInList++;
      } else if (issuers.any(c.signedBy)) {
        ok++;
      } else {
        bad++;
        badList.add('${c.subjectCountry}/${c.sigAlg.children.first.oid}');
      }
    }
    // ignore: avoid_print
    print('CSCA signatures ok=$ok bad=$bad issuerNotInList=$noIssuerInList bad: $badList');
    expect(ok, greaterThan(500));
    // A few odd certificates may use encodings the phone does not support;
    // they are then simply not trusted. It must stay a tiny share.
    expect(bad, 0);
  });

  test('a certificate is not "signed by" an unrelated CSCA', () {
    final trust = CscaTrust.fromMasterList(ml);
    final de = trust.all.firstWhere((c) => c.subjectCountry == 'DE');
    final fr = trust.all.firstWhere((c) => c.subjectCountry == 'FR');
    expect(de.signedBy(fr), isFalse);
    expect(fr.signedBy(de), isFalse);
  });
}
