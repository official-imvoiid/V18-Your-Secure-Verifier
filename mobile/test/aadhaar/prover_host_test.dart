// Host check of the native Anon Aadhaar prover (mobile/native/v18_prover).
//
// Skipped unless these are set:
//   V18_PROVER_EXE   path to the host build of the prover example
//                    (cargo build --release --example prove)
//   V18_AA_WASM      official aadhaar-verifier.wasm
//   V18_AA_ZKEY      official circuit_final.zkey
//   V18_AA_VKEY      official vkey.json
// Optional:
//   V18_AA_OUT       folder to write inputs.json and proof.json into (for the
//                    snarkjs cross-check in tool/aadhaar_verify/)
//
// It builds the circuit inputs from the official Anon Aadhaar TEST QR with the
// app's own Dart code, runs the real prover on the PC, and checks the answer.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:v18/aadhaar/anon_aadhaar.dart';
import 'package:v18/aadhaar/secure_qr.dart';
import 'package:v18/aadhaar/uidai_keys.dart';

void main() {
  final env = Platform.environment;
  final exe = env['V18_PROVER_EXE'];
  final wasm = env['V18_AA_WASM'];
  final zkey = env['V18_AA_ZKEY'];
  final vkey = env['V18_AA_VKEY'];
  final skip = (exe == null || wasm == null || zkey == null || vkey == null)
      ? 'Set V18_PROVER_EXE, V18_AA_WASM, V18_AA_ZKEY and V18_AA_VKEY to run the host prover check'
      : null;

  test('native prover makes a proof that reveals only age above 18', () async {
    final fixture = jsonDecode(
        File('test/fixtures/anon_aadhaar_test_qr.json').readAsStringSync()) as Map;
    final qr = AadhaarSecureQr.decode(fixture['testQRData'] as String);
    const challenge = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const thumb = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
    final signal = anonAadhaarSignal(challenge, thumb);
    final inputs = AnonAadhaarInputs.build(
      qr: qr,
      uidaiModulus: anonAadhaarTestKey.rsaKey.modulus!,
      nullifierSeed: devAadhaarNullifierSeed,
      signal: signal,
    );
    final dir = env['V18_AA_OUT'] != null
        ? Directory(env['V18_AA_OUT']!)
        : Directory.systemTemp.createTempSync('v18_prover');
    dir.createSync(recursive: true);
    final inFile = File('${dir.path}/inputs.json')
      ..writeAsStringSync(jsonEncode(inputs.circuitInputs));
    final res = await Process.run(exe!, [wasm!, zkey!, vkey!, inFile.path, dir.path]);
    expect(res.exitCode, 0, reason: res.stderr.toString());
    final out = jsonDecode(res.stdout as String) as Map<String, dynamic>;
    expect(out['error'], isNull, reason: out['error']?.toString());
    File('${dir.path}/proof.json').writeAsStringSync(jsonEncode(out));

    final named = out['named'] as Map<String, dynamic>;
    expect(named['ageAbove18'], '1');
    expect(named['gender'], '0');
    expect(named['pincode'], '0');
    expect(named['state'], '0');
    expect(named['pubkeyHash'],
        '15134874015316324267425466444584014077184337590635665158241104437045239495873');
    expect(named['nullifierSeed'], devAadhaarNullifierSeed);
    expect(named['signalHash'],
        anonAadhaarHash(BigInt.parse(signal.substring(2), radix: 16)).toString());
    final proof = out['proof'] as Map<String, dynamic>;
    expect(proof['protocol'], 'groth16');
    expect((proof['pi_b'] as List).length, 3);
    // ignore: avoid_print
    print('Prover timings (ms): ${out['timingsMs']}');
  }, skip: skip, timeout: const Timeout(Duration(minutes: 10)));
}
