import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:v18/crypto/b64.dart';
import 'package:v18/crypto/rfc9474.dart';

/// Cross-test against @cloudflare/blindrsa-ts, the library the V18 server
/// uses (PROTOCOL.md section 2).
///
/// Part 1 uses a saved fixture made by mobile/tool/blindrsa_crosscheck
/// (`node crosscheck.mjs fixture ...`), so it always runs.
/// Part 2 runs the Node library live, if Node and the tool's node_modules are
/// present: Dart blinds, blindrsa-ts signs, Dart finalizes, blindrsa-ts
/// verifies.
void main() {
  final fixture = jsonDecode(
          File('test/fixtures/blindrsa_ts_cases.json').readAsStringSync())
      as Map<String, dynamic>;
  final jwk = (fixture['jwk'] as Map).cast<String, dynamic>();
  final pk = BlindRsaPublicKey(
      _b64Int(jwk['n'] as String), _b64Int(jwk['e'] as String));
  final client = BlindRsaClient(BlindRsaVariant.sha384PssRandomized);
  final cases = (fixture['cases'] as List).cast<Map<String, dynamic>>();

  group('blindrsa-ts fixture', () {
    for (var i = 0; i < cases.length; i++) {
      final c = cases[i].cast<String, String>();
      Uint8List h(String k) => hexToBytes(c[k]!);

      test('case $i: Dart finalize gives the same sig as blindrsa-ts', () {
        final inv = os2ip(h('inv'));
        final sig = client.finalize(pk, h('prepared'), h('blindSig'), inv);
        expect(bytesToHex(sig), c['sig']);
      });

      test('case $i: Dart blind gives the same blinded message '
          '(same salt and r)', () {
        final inv = os2ip(h('inv'));
        final r = inv.modInverse(pk.n);
        // m = blinded * inv^e mod n is the EMSA-PSS encoded message.
        final m = (os2ip(h('blindedMsg')) * inv.modPow(pk.e, pk.n)) % pk.n;
        final emLen = (pk.modulusBits - 1 + 7) ~/ 8;
        final salt = _recoverSalt(i2osp(m, emLen), pk.modulusBits - 1);
        final result = client.blindWith(pk, h('prepared'), salt: salt, r: r);
        expect(bytesToHex(result.blindedMessage), c['blindedMsg']);
      });
    }
  });

  final toolDir = Directory('tool/blindrsa_crosscheck/node_modules');
  final haveNode = toolDir.existsSync() && _nodeAvailable();

  test('live: Dart blind -> blindrsa-ts sign -> Dart finalize -> '
      'blindrsa-ts verify', () async {
    final prepared = <Uint8List>[];
    final inverses = <BigInt>[];
    final blinded = <String>[];
    for (var i = 0; i < 3; i++) {
      final p = client.prepare(Uint8List.fromList(utf8.encode('live $i')));
      final b = client.blind(pk, p);
      prepared.add(p);
      inverses.add(b.inverse);
      blinded.add(bytesToHex(b.blindedMessage));
    }
    final signed = await _runNode({'jwk': jwk, 'blindedMsgs': blinded});
    final blindSigs = (signed['blindSigs'] as List).cast<String>();
    final verifyReq = <Map<String, String>>[];
    for (var i = 0; i < 3; i++) {
      final sig = client.finalize(
          pk, prepared[i], hexToBytes(blindSigs[i]), inverses[i]);
      verifyReq.add({'prepared': bytesToHex(prepared[i]), 'sig': bytesToHex(sig)});
    }
    final verified = await _runNode({'jwk': jwk, 'verify': verifyReq});
    expect(verified['verified'], [true, true, true]);
  },
      skip: haveNode
          ? false
          : 'Node or tool/blindrsa_crosscheck/node_modules missing '
              '(run npm install in mobile/tool/blindrsa_crosscheck)');
}

BigInt _b64Int(String s) => os2ip(b64urlDecode(s));

Uint8List _recoverSalt(Uint8List em, int emBits) {
  const hLen = 48;
  const sLen = 48;
  final emLen = em.length;
  final dbLen = emLen - hLen - 1;
  final h = em.sublist(dbLen, dbLen + hLen);
  final mask = mgf1Sha384(h, dbLen);
  final db = Uint8List(dbLen);
  for (var i = 0; i < dbLen; i++) {
    db[i] = em[i] ^ mask[i];
  }
  db[0] &= 0xFF >> (8 * emLen - emBits);
  expect(db[dbLen - sLen - 1], 0x01);
  return db.sublist(dbLen - sLen);
}

bool _nodeAvailable() {
  try {
    return Process.runSync('node', ['--version']).exitCode == 0;
  } on Object {
    return false;
  }
}

Future<Map<String, dynamic>> _runNode(Map<String, dynamic> request) async {
  final p = await Process.start(
      'node', ['crosscheck.mjs', 'serve'],
      workingDirectory: 'tool/blindrsa_crosscheck');
  p.stdin.write(jsonEncode(request));
  await p.stdin.close();
  final out = await p.stdout.transform(utf8.decoder).join();
  final err = await p.stderr.transform(utf8.decoder).join();
  final code = await p.exitCode;
  if (code != 0) fail('node failed ($code): $err');
  return jsonDecode(out) as Map<String, dynamic>;
}
