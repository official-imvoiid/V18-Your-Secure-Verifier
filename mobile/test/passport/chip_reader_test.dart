// The whole chip path with a TEST chip (test/helpers/test_chip.dart): dmrtd's
// real BAC and secure messaging, real file reads, passive authentication up to
// a CSCA, and Active Authentication. TEST documents only (tool/make_emrtd_fixtures.py).
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:v18/passport/active_auth.dart';
import 'package:v18/passport/chip_reader.dart';
import 'package:v18/passport/csca.dart';
import 'package:v18/passport/mrz_reader.dart';
import 'package:v18/passport/passive_auth.dart';

import '../helpers/test_chip.dart';

void main() {
  final testCsca = X509.fromBytes(File('test/fixtures/emrtd/test_csca.der').readAsBytesSync());
  final realList = CscaTrust.fromMasterList(File('assets/csca/master_list.ml').readAsBytesSync());

  ChipReader reader(TestDocument doc, {CscaTrust? trust, bool breakAa = false}) => ChipReader(
        provider: () => TestChip(doc, random: Random(7), breakAa: breakAa),
        trust: () async => trust ?? CscaTrust([testCsca]),
        nfcEnabled: () async => true,
      );

  MrzKey keyOf(TestDocument d) =>
      MrzKey(documentNumber: d.documentNumber, dateOfBirth: d.dateOfBirth, dateOfExpiry: d.dateOfExpiry);

  test('adult TEST passport: BAC, passive auth to the CSCA, Active Authentication', () async {
    final doc = TestDocument.fromFixtures('adult');
    final steps = <String>[];
    final r = await reader(doc).read(MrzAccess(keyOf(doc)), onProgress: (_, s) => steps.add(s));
    expect(r.accessProtocol, 'BAC');
    expect(r.passiveAuth.dataGroupHashesMatch, isTrue);
    expect(r.passiveAuth.signatureValid, isTrue);
    expect(r.passiveAuth.countryChainChecked, isTrue);
    expect(r.passiveAuth.cscaCountry, 'UT');
    expect(r.activeAuth, ActiveAuthResult.passed);
    expect(r.chipAuthWire, 'active_auth');
    expect(r.docType, 'P');
    expect(r.issuingState, 'UTO');
    expect(r.docExpiry, DateTime(2035, 12, 31));
    expect(r.over18, isTrue);
    expect(r.nullifierMessage, 'v18-doc-v1|UTO|V18T00001');
    expect(steps, contains('Chip unlocked'));

    // The proof has ONLY the protocol fields: no name, birth date or number.
    final proof = r.proof(nullifier: 'n' * 43, nullifierKeyId: 'v18-nullifier-1');
    expect(proof.keys.toSet(),
        {'over18', 'docExpiry', 'issuingState', 'docType', 'passiveAuth', 'chipAuth', 'nullifier', 'nullifierKeyId'});
    expect(proof['docExpiry'], '2035-12-31');
    expect(jsonEncode(proof), isNot(contains('V18T00001')));
    expect(jsonEncode(proof), isNot(contains('TESTER')));
    expect(jsonEncode(proof), isNot(contains('1990')));
    r.wipe();
    expect(() => r.nullifierMessage, throwsStateError);
  });

  test('under-18 TEST passport reads fine but is not over 18', () async {
    final doc = TestDocument.fromFixtures('minor');
    final r = await reader(doc).read(MrzAccess(keyOf(doc)));
    expect(r.passiveAuth.passed, isTrue);
    expect(r.over18, isFalse);
  });

  test('wrong MRZ details: the chip refuses BAC', () async {
    final doc = TestDocument.fromFixtures('adult');
    final wrong = MrzKey(documentNumber: 'V18T00009', dateOfBirth: doc.dateOfBirth, dateOfExpiry: doc.dateOfExpiry);
    await expectLater(reader(doc).read(MrzAccess(wrong)), throwsA(isA<ChipReadException>()));
  });

  test('the TEST CSCA is not trusted by the real BSI list alone', () async {
    final doc = TestDocument.fromFixtures('adult');
    await expectLater(
        reader(doc, trust: realList).read(MrzAccess(keyOf(doc))),
        throwsA(isA<ChipReadException>()
            .having((e) => e.sealProblem, 'sealProblem', isTrue)
            .having((e) => e.message, 'message', contains('trusted countries'))));
  });

  test('a copied chip (wrong AA answer) is refused', () async {
    final doc = TestDocument.fromFixtures('adult');
    await expectLater(reader(doc, breakAa: true).read(MrzAccess(keyOf(doc))),
        throwsA(isA<ChipReadException>().having((e) => e.message, 'message', contains('copy test'))));
  });

  test('a changed DG1 breaks the seal', () async {
    final good = TestDocument.fromFixtures('adult');
    final dg1 = Uint8List.fromList(good.files[0x01]!);
    dg1[5 + 6] = 0x46; // 'TESTER' -> 'TFSTER': names have no check digit, so only the seal catches it
    final doc = TestDocument(
        files: {...good.files, 0x01: dg1},
        documentNumber: good.documentNumber,
        dateOfBirth: good.dateOfBirth,
        dateOfExpiry: good.dateOfExpiry,
        aaPrivateKey: good.aaPrivateKey);
    await expectLater(reader(doc).read(MrzAccess(keyOf(doc))),
        throwsA(isA<ChipReadException>().having((e) => e.sealProblem, 'sealProblem', isTrue)));
  });

  test('passive auth reports a missing CSCA check honestly', () {
    final doc = TestDocument.fromFixtures('adult');
    final r = passiveAuthenticate(doc.files[0x1D]!, {1: doc.files[0x01]!});
    expect(r.dataGroupHashesMatch, isTrue);
    expect(r.signatureValid, isTrue);
    expect(r.countryChainChecked, isFalse);
    expect(r.passed, isFalse);
  });

  test('DSC dates: a document signer that is not valid yet is refused', () {
    final doc = TestDocument.fromFixtures('adult');
    final r = passiveAuthenticate(doc.files[0x1D]!, {1: doc.files[0x01]!},
        trust: CscaTrust([testCsca]), now: DateTime.utc(2020));
    expect(r.countryChainChecked, isFalse);
  });

  test('nullifier message and age rules', () {
    expect(docNullifierMessage('D<<', 'c01x00t47<'), 'v18-doc-v1|D<<|C01X00T47');
    expect(isAtLeast18(DateTime(2008, 11, 24), DateTime(2026, 11, 24)), isTrue);
    expect(isAtLeast18(DateTime(2008, 11, 25), DateTime(2026, 11, 24)), isFalse);
    expect(isAtLeast18(DateTime(2008, 2, 29), DateTime(2026, 2, 28)), isFalse);
    expect(isAtLeast18(DateTime(2008, 2, 29), DateTime(2026, 3, 1)), isTrue);
  });
}
