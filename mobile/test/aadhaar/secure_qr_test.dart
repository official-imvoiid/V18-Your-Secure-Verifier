import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/asn1.dart' as asn1;
import 'package:pointycastle/export.dart' as pc;
import 'package:v18/aadhaar/anon_aadhaar.dart';
import 'package:v18/aadhaar/secure_qr.dart';
import 'package:v18/aadhaar/uidai_keys.dart';
import 'package:v18/crypto/b64.dart';

void main() {
  final testQr = (jsonDecode(
          File('test/fixtures/anon_aadhaar_test_qr.json').readAsStringSync())
      as Map<String, dynamic>)['testQRData'] as String;

  group('Anon Aadhaar test QR', () {
    test('decodes, and the seal matches the TEST key only', () {
      final qr = AadhaarSecureQr.decode(testQr);
      expect(qr.version, 'V2');
      expect(qr.signature.length, 256);
      expect(qr.verifySeal(uidaiProductionKeys), isNull);
      final key = qr.verifySeal(trustedAadhaarKeys(devMode: true));
      expect(key, isNotNull);
      expect(key!.isTestKey, isTrue);
    });

    test('the TEST key is not trusted when the server is not in dev mode', () {
      final qr = AadhaarSecureQr.decode(testQr);
      expect(qr.verifySeal(trustedAadhaarKeys(devMode: false)), isNull);
    });

    test('a changed byte breaks the seal', () {
      final qr = AadhaarSecureQr.decode(testQr);
      qr.signedData[40] ^= 0x01;
      expect(qr.verifySeal(trustedAadhaarKeys(devMode: true)), isNull);
    });

    test('age is worked out on the phone (sample DOB 01-01-1984)', () {
      final qr = AadhaarSecureQr.decode(testQr);
      expect(qr.ageOn(DateTime(2026, 11, 10)), 42);
      expect(qr.ageOn(DateTime(2001, 12, 31)), 17);
      expect(qr.ageOn(DateTime(2002, 1, 1)), 18);
    });

    test('wipe clears the data', () {
      final qr = AadhaarSecureQr.decode(testQr);
      qr.wipe();
      expect(qr.signedData, isEmpty);
      expect(qr.signature, isEmpty);
    });

    test('circuit inputs follow @anon-aadhaar/core generateArgs', () {
      final qr = AadhaarSecureQr.decode(testQr);
      final signal = anonAadhaarSignal('a' * 64, 'thumb');
      final inputs = AnonAadhaarInputs.build(
        qr: qr,
        uidaiModulus: anonAadhaarTestKey.rsaKey.modulus!,
        nullifierSeed: devAadhaarNullifierSeed,
        signal: signal,
      ).circuitInputs;
      expect((inputs['qrDataPadded'] as List).length, 1536);
      expect(int.parse(inputs['qrDataPaddedLength'] as String) % 64, 0);
      expect((inputs['delimiterIndices'] as List).length, 18);
      expect((inputs['signature'] as List).length, 17);
      expect((inputs['pubKey'] as List).length, 17);
      expect(inputs['revealAgeAbove18'], '1');
      expect(inputs['revealGender'], '0');
      expect(inputs['revealPinCode'], '0');
      expect(inputs['revealState'], '0');
      // pubKey words put back together give the modulus.
      var n = BigInt.zero;
      for (final w in (inputs['pubKey'] as List).reversed) {
        n = (n << 121) | BigInt.parse(w as String);
      }
      expect(n, anonAadhaarTestKey.rsaKey.modulus);
    });

    test('a prover answer that reveals more than 18+ is refused', () {
      Map<String, dynamic> answer(Map<String, String> over) => {
            'proof': {'pi_a': ['1', '2', '1'], 'pi_b': [], 'pi_c': [], 'protocol': 'groth16'},
            'named': {
              'pubkeyHash': '1', 'nullifier': '2', 'timestamp': '3', 'ageAbove18': '1',
              'gender': '0', 'pincode': '0', 'state': '0', 'nullifierSeed': '4', 'signalHash': '5',
              ...over,
            },
            'timingsMs': {'total': 10},
          };
      final ok = AnonAadhaarProof.fromProver(answer(const {}));
      final j = ok.toJson('id1');
      expect(j['type'], 'anon-aadhaar');
      expect((j['proof'] as Map)['ageAbove18'], '1');
      expect((j['proof'] as Map)['gender'], '0');
      for (final bad in [
        {'gender': '77'},
        {'pincode': '110001'},
        {'state': '9'},
        {'ageAbove18': '0'},
      ]) {
        expect(() => AnonAadhaarProof.fromProver(answer(bad)), throwsA(isA<ProverFailed>()),
            reason: '$bad');
      }
    });
  });

  group('synthetic QR signed by a key made in this test', () {
    test('round trip with zlib and a fresh RSA key', () {
      final keys = _rsaKeyPair();
      final dob = '15-08-2010';
      final fields = ['V2', '0', '0000test', 'Test Person', dob, 'F', '', '', '', '', '', '000000'];
      final signed = <int>[];
      for (final f in fields) {
        signed
          ..addAll(latin1.encode(f))
          ..add(255);
      }
      final signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201')
        ..init(true, pc.PrivateKeyParameter<pc.RSAPrivateKey>(keys.privateKey));
      final sig = signer.generateSignature(Uint8List.fromList(signed)).bytes;
      final raw = Uint8List.fromList([...signed, ...sig]);
      final compressed = ZLibCodec().encode(raw);
      var n = BigInt.zero;
      for (final b in compressed) {
        n = (n << 8) | BigInt.from(b);
      }
      final qr = AadhaarSecureQr.decode(n.toString());
      final key = AadhaarSigningKey(
          name: 'unit-test key',
          isTestKey: true,
          spkiPem: _spkiPem(keys.publicKey));
      expect(qr.verifySeal([key]), same(key));
      expect(qr.verifySeal(uidaiProductionKeys), isNull);
      expect(qr.ageOn(DateTime(2026, 11, 10)), 16);
    });

    test('rejects text that is not a Secure QR', () {
      expect(() => AadhaarSecureQr.decode('https://example.com'),
          throwsA(isA<AadhaarQrException>()));
      expect(() => AadhaarSecureQr.decode('12345'),
          throwsA(isA<AadhaarQrException>()));
    });
  });

  group('Anon Aadhaar helpers', () {
    test('hash(1) matches keccak256(uint256(1)) >> 3', () {
      final expected = BigInt.parse(
              'b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6',
              radix: 16) >>
          3;
      expect(anonAadhaarHash(BigInt.one), expected);
    });

    test('signal string and signal follow the protocol', () {
      expect(anonAadhaarSignalString('abc', 'xyz'), 'abc|xyz');
      final s = anonAadhaarSignal('abc', 'xyz');
      expect(s, startsWith('0x'));
      expect(s.length, 66);
    });

    test('sha256Pad', () {
      final (padded, len) = sha256Pad(Uint8List.fromList([1, 2, 3]), 128);
      expect(len, 64);
      expect(padded.length, 128);
      expect(padded[3], 0x80);
      expect(padded[63], 24);
      expect(bytesToHex(padded.sublist(64)), '00' * 64);
    });

    test('splitToWords', () {
      expect(splitToWords(BigInt.from(5), 2, 3), ['1', '1', '0']);
      expect(() => splitToWords(BigInt.from(64), 2, 3), throwsArgumentError);
    });
  });
}

pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey> _rsaKeyPair() {
  final rnd = pc.FortunaRandom()
    ..seed(pc.KeyParameter(Uint8List.fromList(
        List<int>.generate(32, (_) => Random.secure().nextInt(256)))));
  final gen = pc.RSAKeyGenerator()
    ..init(pc.ParametersWithRandom(
        pc.RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64), rnd));
  final pair = gen.generateKeyPair();
  return pc.AsymmetricKeyPair(
      pair.publicKey as pc.RSAPublicKey, pair.privateKey as pc.RSAPrivateKey);
}

String _spkiPem(pc.RSAPublicKey key) {
  final rsa = asn1.ASN1Sequence(elements: [
    asn1.ASN1Integer(key.modulus),
    asn1.ASN1Integer(key.exponent),
  ]);
  final spki = asn1.ASN1Sequence(elements: [
    asn1.ASN1Sequence(elements: [
      asn1.ASN1ObjectIdentifier.fromIdentifierString('1.2.840.113549.1.1.1'),
      asn1.ASN1Null(),
    ]),
    asn1.ASN1BitString(stringValues: rsa.encode()),
  ]);
  final b64 = base64.encode(spki.encode());
  return '-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----';
}
