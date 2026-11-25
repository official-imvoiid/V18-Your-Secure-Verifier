// Protocol 4c and 4d checks against a LIVE dev server, with the app's real Dart
// code over real HTTP. Skipped unless V18_LIVE_SERVER is set:
//
//   V18_LIVE_SERVER=http://localhost:8080 flutter test test/integration
//
// The real-proof Aadhaar test also needs the host prover and the official files
// (see test/aadhaar/prover_host_test.dart): V18_PROVER_EXE, V18_AA_WASM,
// V18_AA_ZKEY, V18_AA_VKEY.
//
// Device keys here are software P-256 keys with NO attestation chain; a dev
// server accepts that and lists it in attestation.devModeExceptions
// ("no_attestation"). The emulator run sends real (emulator-level) chains.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:v18/aadhaar/anon_aadhaar.dart';
import 'package:v18/aadhaar/artifacts.dart';
import 'package:v18/aadhaar/secure_qr.dart';
import 'package:v18/aadhaar/uidai_keys.dart';
import 'package:v18/api/v18_api.dart';
import 'package:v18/catalog/catalog.dart';
import 'package:v18/device/device_key.dart';
import 'package:v18/device/platform_checks.dart';
import 'package:v18/flows/flows.dart';
import 'package:v18/passport/chip_reader.dart';
import 'package:v18/passport/mrz_reader.dart';
import 'package:v18/protocol/deep_links.dart';
import 'package:v18/protocol/signing_strings.dart';

import '../helpers/fakes.dart';
import '../helpers/test_chip.dart';

/// Software keys without any attestation chain (dev servers accept that).
class NoChainKeys extends FakeDeviceKeyService {
  @override
  Future<DeviceKeyInfo> createKey(String alias, {String? attestationChallenge, bool userAuth = true}) async {
    final k = await super.createKey(alias, userAuth: userAuth);
    return k;
  }
}

void main() {
  final serverUrl = Platform.environment['V18_LIVE_SERVER'];
  final skip = serverUrl == null ? 'Set V18_LIVE_SERVER to run against a live server' : false;
  final client = http.Client();
  final keys = NoChainKeys();
  final s = V18Services(keys: keys, checks: PlatformChecks(), apiFor: (server) => V18Api(server, client: client));
  final server = ServerAllowlist.forBuild(debug: true).normalize(serverUrl) ?? 'http://localhost:8080';
  final api = V18Api(server, client: client);

  test('catalog: countries and methods, filtered by the server', () async {
    final c = Catalog.fromJson(await api.catalog(platform: 'android'));
    expect(c.countries.length, greaterThan(20));
    final india = c.byCode('IN')!;
    expect(india.methods.map((m) => m.method), containsAll(['anon_aadhaar', 'emrtd_attested']));
    // Face is never in the catalog of this deployment (no model in V18_FACE_MODELS).
    expect(c.countries.expand((x) => x.methods).where((m) => m.method == 'face_estimate'), isEmpty);
    const caps = AppCapabilities(aadhaarProver: true, nfc: true, digitalCredentials: true, customTabs: true);
    expect(caps.visible(india).first.method, 'anon_aadhaar'); // zero-knowledge first
  }, skip: skip);

  test('artifacts manifest: the three official files with SHA-256 pins', () async {
    final store = ArtifactStore(dir: () async => Directory.systemTemp.createTempSync('v18_live'), client: client);
    final a = await store.manifest(server);
    expect(a.zkey.sha256, '0d443ea85279b0370b53202f5e768ca9098cfcb5bb14f8ca8323d2266822c492');
    expect(a.wasm.sha256, '4894923663fafda95beb70abca4112ea97a62058c9a46419a274f04236f10d4f');
    expect(a.vkey.sha256, '40f2ea24b56ffe2b6e6e3578053cbda15e773cb560697bac883a404077fcf177');
    expect(a.zkey.bytes, 612082146);
  }, skip: skip);

  test('nullifier service: deterministic per document, blind to the server', () async {
    final m1 = docNullifierMessage('UTO', 'V18T00001');
    final a = await obtainNullifier(s, server: server, message: m1);
    final b = await obtainNullifier(s, server: server, message: m1);
    final c = await obtainNullifier(s, server: server, message: docNullifierMessage('UTO', 'V18T00002'));
    expect(a.nullifier, b.nullifier);
    expect(a.nullifier, isNot(c.nullifier));
    expect(a.keyId, 'v18-nullifier-1');
  }, skip: skip);

  test('emrtd_attested card from the TEST chip (passport read, checked, nullifier)', () async {
    final doc = TestDocument.fromFixtures('adult');
    final r = await ChipReader(
      provider: () => TestChip(doc),
      trust: () async => testCscaTrust(),
      nfcEnabled: () async => true,
    ).read(MrzAccess(
        MrzKey(documentNumber: doc.documentNumber, dateOfBirth: doc.dateOfBirth, dateOfExpiry: doc.dateOfExpiry)));
    final n = await obtainNullifier(s, server: server, message: r.nullifierMessage);
    r.wipe();
    final challenge = await api.challenge();
    const alias = 'v18_card_live_emrtd';
    final key = await keys.createKey(alias);
    final sig = await keys.sign(alias, cardIssueSigningString(challenge: challenge, deviceKeyThumbprint: key.thumbprint),
        title: '', subtitle: '');
    final card = await api.issueCard(
      method: 'emrtd_attested',
      challenge: challenge,
      devicePublicKey: key.jwkWithAlg,
      deviceSignature: sig,
      proof: r.proof(nullifier: n.nullifier, nullifierKeyId: n.keyId),
    );
    expect(card.method, 'emrtd_attested');
    expect(card.raw['assuranceLevel'], 'substantial');
    expect((card.raw['attestation'] as Map)['devModeExceptions'], contains('no_attestation'));
    // A name or number in the proof is refused (only the protocol fields are allowed).
    final ch2 = await api.challenge();
    final key2 = await keys.createKey('v18_card_live_emrtd2');
    final sig2 = await keys.sign('v18_card_live_emrtd2',
        cardIssueSigningString(challenge: ch2, deviceKeyThumbprint: key2.thumbprint),
        title: '', subtitle: '');
    await expectLater(
        api.issueCard(
            method: 'emrtd_attested',
            challenge: ch2,
            devicePublicKey: key2.jwkWithAlg,
            deviceSignature: sig2,
            proof: {...r.proof(nullifier: n.nullifier, nullifierKeyId: n.keyId), 'documentNumber': 'X'}),
        throwsA(isA<V18ApiException>().having((e) => e.code, 'code', 'PROOF_INVALID')));
  }, skip: skip);

  final exe = Platform.environment['V18_PROVER_EXE'];
  final wasm = Platform.environment['V18_AA_WASM'];
  final zkey = Platform.environment['V18_AA_ZKEY'];
  final vkey = Platform.environment['V18_AA_VKEY'];
  test('anon_aadhaar card with a REAL proof bound to this request', () async {
    final fixture = jsonDecode(File('test/fixtures/anon_aadhaar_test_qr.json').readAsStringSync()) as Map;
    final card = await issueCard(s, server: server, method: 'anon_aadhaar', buildProof: (challenge, thumb) async {
      final inputs = AnonAadhaarInputs.build(
        qr: AadhaarSecureQr.decode(fixture['testQRData'] as String),
        uidaiModulus: anonAadhaarTestKey.rsaKey.modulus!,
        nullifierSeed: (await api.health()).aadhaarNullifierSeed!,
        signal: anonAadhaarSignal(challenge, thumb),
      );
      final dir = Directory.systemTemp.createTempSync('v18_live_aa');
      final f = File('${dir.path}/inputs.json')..writeAsStringSync(jsonEncode(inputs.circuitInputs));
      final res = await Process.run(exe!, [wasm!, zkey!, vkey!, f.path, dir.path]);
      f.deleteSync();
      final out = jsonDecode(res.stdout as String) as Map<String, dynamic>;
      expect(out['error'], isNull);
      return AnonAadhaarProof.fromProver(out).toJson('live-test');
    });
    expect(card.method, 'anon_aadhaar');
  },
      skip: skip != false
          ? skip
          : (exe == null || wasm == null || zkey == null || vkey == null)
              ? 'Set V18_PROVER_EXE, V18_AA_WASM, V18_AA_ZKEY and V18_AA_VKEY for the real-proof test'
              : false,
      timeout: const Timeout(Duration(minutes: 5)));
}
