import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:v18/passport/mrz_reader.dart';
import 'package:v18/passport/passive_auth.dart';

/// Uses only the ICAO Doc 9303 specimen data (fictional "Utopia" documents).
void main() {
  group('MRZ from OCR text', () {
    test('TD3 passport specimen', () {
      const ocr = '''
UTOPIA PASSPORT
P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
L898902C36UTO7408122F1204159ZE184226B<<<<<10
''';
      final key = mrzKeyFromOcrText(ocr)!;
      expect(key.documentNumber, 'L898902C3');
      expect(key.dateOfBirth, DateTime(1974, 8, 12));
      expect(key.dateOfExpiry, DateTime(2012, 4, 15));
    });

    test('TD1 ID card specimen', () {
      const ocr = '''
I<UTOD231458907<<<<<<<<<<<<<<<
7408122F1204159UTO<<<<<<<<<<<6
ERIKSSON<<ANNA<MARIA<<<<<<<<<<
''';
      final key = mrzKeyFromOcrText(ocr)!;
      expect(key.documentNumber, 'D23145890');
      expect(key.dateOfBirth, DateTime(1974, 8, 12));
    });

    test('fixes common OCR mix-ups in number fields (O for 0, spaces, «)', () {
      const ocr = '''
P«UTOERIKSSON««ANNA«MARIA«««««««««««««««««««
L898902C36UTO74O8122F12O4159ZE184226B<<<<< 1O
''';
      final key = mrzKeyFromOcrText(ocr);
      expect(key, isNotNull);
      expect(key!.dateOfBirth, DateTime(1974, 8, 12));
    });

    test('a wrong check digit is refused', () {
      const ocr = '''
P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
L898902C37UTO7408122F1204159ZE184226B<<<<<10
''';
      expect(mrzKeyFromOcrText(ocr), isNull);
    });

    test('text with no MRZ gives null', () {
      expect(mrzKeyFromOcrText('hello world'), isNull);
    });
  });

  group('passive authentication (synthetic EF.SOD, test keys)', () {
    final dg1 = File('test/fixtures/sod/dg1.bin').readAsBytesSync();
    for (final name in const [
      'ec_p256',
      'ec_brainpool_explicit',
      'rsa',
      'rsa_pss'
    ]) {
      final sod = File('test/fixtures/sod/sod_$name.bin').readAsBytesSync();

      test('$name: DG1 hash and SOD signature check out (no country list given)', () {
        final r = passiveAuthenticate(sod, {1: dg1});
        expect(r.dataGroupHashesMatch, isTrue);
        expect(r.signatureValid, isTrue, reason: r.signatureAlgorithm);
        // Without a CSCA check the document is NOT accepted.
        expect(r.countryChainChecked, isFalse);
        expect(r.passed, isFalse);
        expect(r.problem, contains('country'));
      });

      test('$name: a changed DG1 fails', () {
        final changed = Uint8List.fromList(dg1);
        changed[20] ^= 0x01;
        final r = passiveAuthenticate(sod, {1: changed});
        expect(r.dataGroupHashesMatch, isFalse);
        expect(r.passed, isFalse);
      });

      test('$name: a changed SOD signature fails', () {
        final bad = Uint8List.fromList(sod);
        bad[bad.length - 5] ^= 0x01;
        final r = passiveAuthenticate(bad, {1: dg1});
        expect(r.passed, isFalse);
      });
    }

    test('garbage SOD is reported, not thrown', () {
      final r = passiveAuthenticate(Uint8List.fromList([1, 2, 3]), {1: dg1});
      expect(r.passed, isFalse);
      expect(r.problem, isNotNull);
    });
  });
}
