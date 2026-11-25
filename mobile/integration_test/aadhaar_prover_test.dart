// On-device check of the native Anon Aadhaar prover (emulator or phone).
//
// Uses the app's real code: ArtifactStore downloads the official circuit files
// from the dev server's GET /v1/artifacts/* and checks each SHA-256, then the
// native prover makes a proof from the official Anon Aadhaar TEST QR.
// Run: flutter test integration_test/aadhaar_prover_test.dart -d emulator-5554
//      --dart-define=V18_TEST_SERVER=http://10.0.2.2:8080
// It prints V18_PROOF_JSON=... so the PC can check the proof with snarkjs.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path_provider/path_provider.dart';
import 'package:v18/aadhaar/anon_aadhaar.dart';
import 'package:v18/aadhaar/artifacts.dart';
import 'package:v18/aadhaar/native_prover.dart';
import 'package:v18/aadhaar/secure_qr.dart';
import 'package:v18/aadhaar/uidai_keys.dart';

import 'test_fixtures.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('real Anon Aadhaar proof on this device', (tester) async {
    const server = String.fromEnvironment('V18_TEST_SERVER', defaultValue: 'http://10.0.2.2:8080');
    final store = ArtifactStore(dir: getApplicationSupportDirectory);
    final dl = Stopwatch()..start();
    final paths = (await tester.runAsync(() async {
      final files = await store.manifest(server);
      return store.ensure(server, files);
    }))!;
    dl.stop();
    final qr = AadhaarSecureQr.decode(anonAadhaarTestQr);
    const challenge = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const thumb = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
    final inputs = AnonAadhaarInputs.build(
      qr: qr,
      uidaiModulus: anonAadhaarTestKey.rsaKey.modulus!,
      nullifierSeed: devAadhaarNullifierSeed,
      signal: anonAadhaarSignal(challenge, thumb),
    );
    final prover = NativeAnonAadhaarProver(cacheDir: getApplicationCacheDirectory);
    expect(prover.available, isTrue, reason: prover.loadError);
    final stages = <String>[];
    final clock = Stopwatch()..start();
    final proof = await tester.runAsync(() => prover.prove(
          inputs,
          paths,
          onStage: (s) => stages.add(s.name),
        ));
    clock.stop();
    expect(proof, isNotNull);
    expect(proof!.signals['ageAbove18'], '1');
    expect(proof.signals['gender'], '0');
    final report = jsonEncode({
      'proof': proof.groth16Proof,
      'publicSignals': [
        for (final k in ['pubkeyHash', 'nullifier', 'timestamp', 'ageAbove18', 'gender', 'pincode', 'state', 'nullifierSeed', 'signalHash'])
          proof.signals[k]
      ],
      'named': proof.signals,
      'timingsMs': proof.timingsMs,
      'wallMs': clock.elapsedMilliseconds,
      'cpus': Platform.numberOfProcessors,
      'downloadAndCheckMs': dl.elapsedMilliseconds,
    });
    // ignore: avoid_print
    print('V18_PROOF_TIMING wall=${clock.elapsedMilliseconds}ms download=${dl.elapsedMilliseconds}ms '
        'native=${proof.timingsMs} stages=$stages');
    // ignore: avoid_print
    print('V18_PROOF_JSON=$report');
  }, timeout: const Timeout(Duration(minutes: 15)));
}
