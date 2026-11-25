import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:v18/crypto/b64.dart';
import 'package:v18/crypto/rfc9474.dart';

/// Every RFC 9474 Appendix A test vector (A.1 to A.4). A.1 is the variant V18
/// uses (RSABSSA-SHA384-PSS-Randomized); the other three use the same code
/// with a different salt length or prepare step, so they are checked too.
void main() {
  final fixture = jsonDecode(
          File('test/fixtures/rfc9474_appendix_a.json').readAsStringSync())
      as Map<String, dynamic>;
  final vectors = fixture['vectors'] as Map<String, dynamic>;

  test('fixture has all four Appendix A vectors', () {
    expect(vectors.keys, hasLength(4));
  });

  for (final variant in BlindRsaVariant.values) {
    group('RFC 9474 Appendix A: ${variant.name}', () {
      final v = (vectors[variant.name] as Map).cast<String, String>();
      BigInt big(String k) => BigInt.parse(v[k]!, radix: 16);
      Uint8List bytes(String k) => hexToBytes(v[k]!);

      final pk = BlindRsaPublicKey(big('n'), big('e'));
      final client = BlindRsaClient(variant);

      test('key parameters are consistent (n = p*q)', () {
        expect(big('p') * big('q'), big('n'));
      });

      test('prepare gives prepared_msg', () {
        final prepared = variant.randomized
            ? client.prepareWithPrefix(bytes('msg'), bytes('msg_prefix'))
            : client.prepare(bytes('msg'));
        expect(bytesToHex(prepared), v['prepared_msg']);
      });

      test('EMSA-PSS-ENCODE gives encoded_msg', () {
        final encoded = client.emsaPssEncode(
            bytes('prepared_msg'), pk.modulusBits - 1, bytes('salt'));
        expect(bytesToHex(encoded), v['encoded_msg']);
      });

      test('blind gives blinded_msg and inv', () {
        final r = big('inv').modInverse(pk.n);
        final result = client.blindWith(pk, bytes('prepared_msg'),
            salt: bytes('salt'), r: r);
        expect(bytesToHex(result.blindedMessage), v['blinded_msg']);
        expect(result.inverse, big('inv'));
        expect(result.blindedMessage.length, pk.modulusLength);
      });

      test('BlindSign of blinded_msg gives blind_sig (server step, for '
          'checking the vector)', () {
        final s = big('blinded_msg').modPow(big('d'), pk.n);
        expect(bytesToHex(i2osp(s, pk.modulusLength)), v['blind_sig']);
      });

      test('finalize gives sig and verifies', () {
        final sig = client.finalize(
            pk, bytes('prepared_msg'), bytes('blind_sig'), big('inv'));
        expect(bytesToHex(sig), v['sig']);
        expect(client.verify(pk, bytes('prepared_msg'), sig), isTrue);
      });

      test('finalize rejects a changed message', () {
        final changed = bytes('prepared_msg');
        changed[changed.length - 1] ^= 0x01;
        expect(
            () => client.finalize(pk, changed, bytes('blind_sig'), big('inv')),
            throwsA(isA<BlindRsaException>()
                .having((e) => e.kind, 'kind', 'invalid signature')));
      });

      test('finalize rejects a changed blind signature', () {
        final bad = bytes('blind_sig');
        bad[10] ^= 0x80;
        expect(
            () => client.finalize(pk, bytes('prepared_msg'), bad, big('inv')),
            throwsA(isA<BlindRsaException>()));
      });

      test('finalize rejects a wrong-length blind signature', () {
        final short = bytes('blind_sig').sublist(1);
        expect(
            () =>
                client.finalize(pk, bytes('prepared_msg'), short, big('inv')),
            throwsA(isA<BlindRsaException>()
                .having((e) => e.kind, 'kind', 'unexpected input size')));
      });

      test('a full random round trip with this key works', () {
        final msg = Uint8List.fromList(utf8.encode('V18 round trip'));
        final prepared = client.prepare(msg);
        expect(prepared.length,
            msg.length + (variant.randomized ? 32 : 0));
        final b = client.blind(pk, prepared);
        final blindSig = i2osp(
            os2ip(b.blindedMessage).modPow(big('d'), pk.n), pk.modulusLength);
        final sig = client.finalize(pk, prepared, blindSig, b.inverse);
        expect(client.verify(pk, prepared, sig), isTrue);
      });
    });
  }

  group('helpers', () {
    test('I2OSP / OS2IP round trip and errors', () {
      final x = BigInt.parse('0102030405', radix: 16);
      expect(bytesToHex(i2osp(x, 7)), '00000102030405');
      expect(os2ip(i2osp(x, 7)), x);
      expect(() => i2osp(x, 4), throwsA(isA<BlindRsaException>()));
    });

    test('two blinds of the same message differ (randomized)', () {
      final v = (vectors['RSABSSA-SHA384-PSS-Randomized'] as Map)
          .cast<String, String>();
      final pk = BlindRsaPublicKey(
          BigInt.parse(v['n']!, radix: 16), BigInt.parse(v['e']!, radix: 16));
      final client = BlindRsaClient(BlindRsaVariant.sha384PssRandomized);
      final msg = Uint8List.fromList(utf8.encode('same'));
      final a = client.blind(pk, client.prepare(msg));
      final b = client.blind(pk, client.prepare(msg));
      expect(bytesEqual(a.blindedMessage, b.blindedMessage), isFalse);
    });
  });
}
