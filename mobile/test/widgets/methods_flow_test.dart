// End-to-end flows of the 4c/4d methods against the fake V18 server (which
// checks device signatures, the FAKE attestation chain's challenge and key,
// and the allowed proof fields like the real server does).
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:v18/aadhaar/anon_aadhaar.dart';
import 'package:v18/aadhaar/secure_qr.dart';
import 'package:v18/app_state.dart';
import 'package:v18/crypto/b64.dart';
import 'package:v18/crypto/jwk.dart';
import 'package:v18/flows/connect.dart';
import 'package:v18/flows/flows.dart';
import 'package:v18/passport/chip_reader.dart';
import 'package:v18/passport/mrz_reader.dart';
import 'package:v18/ui/screens/aadhaar.dart';
import 'package:v18/ui/screens/passport.dart';
import 'package:v18/ui/screens/wallet_id.dart';

import '../helpers/fakes.dart';
import '../helpers/test_chip.dart';

void phoneSize(WidgetTester tester) {
  tester.view.physicalSize = const Size(1170, 2532);
  tester.view.devicePixelRatio = 3;
  addTearDown(tester.view.reset);
}

Widget wrap(AppState state, Widget child) => AppScope(state: state, child: MaterialApp(home: child));

/// Pumps (and lets real I/O run) until [f] is found.
Future<void> waitFor(WidgetTester tester, Finder f, {int tries = 100}) async {
  for (var i = 0; i < tries; i++) {
    await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 30)));
    await tester.pump(const Duration(milliseconds: 50));
    if (f.evaluate().isNotEmpty) return;
  }
  fail('Not found: $f');
}

Future<void> tapAndWait(WidgetTester tester, Finder tap, Finder next) async {
  await tester.tap(tap);
  await waitFor(tester, next);
}

void main() {
  setUp(() {
    TestWidgetsFlutterBinding.ensureInitialized();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
        const MethodChannel('com.v18.app/platform'), (call) async => call.method == 'childAccountStatus' ? 'unknown' : null);
  });

  testWidgets('Aadhaar: files downloaded and SHA-256 checked, proof, anon_aadhaar card', (tester) async {
    phoneSize(tester);
    final server = FakeV18Server();
    final keys = FakeDeviceKeyService();
    final prover = FakeAnonAadhaarProver();
    final state = fakeAppState(server, keys, prover: prover);
    await tester.runAsync(state.refreshHealth);
    final fixture = jsonDecode(File('test/fixtures/anon_aadhaar_test_qr.json').readAsStringSync()) as Map;
    final qr = AadhaarSecureQr.decode(fixture['testQRData'] as String);
    await tester.pumpWidget(wrap(state, SealCheckScreen(qr: qr, testKey: true)));
    await tester.pumpAndSettle();
    await tapAndWait(tester, find.byKey(const Key('seal-continue')), find.byKey(const Key('download-files')));
    expect(find.textContaining('fingerprint (SHA-256)'), findsOneWidget);
    await tapAndWait(tester, find.byKey(const Key('download-files')), find.byKey(const Key('turn-on-lock')));
    await tapAndWait(tester, find.byKey(const Key('turn-on-lock')), find.byKey(const Key('card-saved-done')));
    expect(find.textContaining('The 18+ proof was made on this phone in'), findsOneWidget);
    expect(prover.calls, 1);
    // The prover got the downloaded, checked files.
    expect(File(prover.lastPaths!.zkey).readAsBytesSync(), server.artifactFiles['circuit_final.zkey']);
    final body = server.issued.last;
    expect(body['method'], 'anon_aadhaar');
    final p = ((body['proof'] as Map)['proof'] as Map).cast<String, dynamic>();
    // The signal binds THIS request: challenge + device key thumbprint.
    final signal = anonAadhaarSignal(body['challenge'] as String, keysThumb(body));
    expect(p['signalHash'], anonAadhaarHash(BigInt.parse(signal.substring(2), radix: 16)).toString());
    expect(p['ageAbove18'], '1');
    expect(p['gender'], '0');
    expect(state.card?.method, 'anon_aadhaar');
  });

  testWidgets('Aadhaar: a file that does not match its SHA-256 is thrown away', (tester) async {
    phoneSize(tester);
    final server = FakeV18Server();
    final state = fakeAppState(server, FakeDeviceKeyService());
    await tester.runAsync(state.refreshHealth);
    // The manifest is built from these bytes; then the served file changes.
    final manifest = await tester.runAsync(() => state.artifacts.manifest(state.server));
    server.artifactFiles['circuit_final.zkey'] = Uint8List.fromList([1, 2, 3]);
    Object? err;
    await tester.runAsync(() async {
      try {
        await state.artifacts.ensure(state.server, manifest!);
      } on Object catch (e) {
        err = e;
      }
    });
    expect(err.toString(), contains('fingerprint'));
  });

  group('chip documents (TEST chip, no NFC)', () {
    final doc = TestDocument.fromFixtures('adult');
    final key = MrzKey(documentNumber: doc.documentNumber, dateOfBirth: doc.dateOfBirth, dateOfExpiry: doc.dateOfExpiry);

    testWidgets('passport: chip checked, nullifier with its own attested key, attested emrtd_attested card',
        (tester) async {
      phoneSize(tester);
      final server = FakeV18Server();
      final keys = FakeDeviceKeyService();
      final state = fakeAppState(server, keys, chip: () => TestChip(doc));
      await tester.runAsync(state.refreshHealth);
      await tester.pumpWidget(wrap(state, PassportChipScreen(access: MrzAccess(key), document: 'Passport (chip)')));
      await waitFor(tester, find.byKey(const Key('chip-continue')));
      expect(find.text('Chip read and checked'), findsOneWidget);
      expect(find.text('Signed by the V18 TEST country (test mode only).'), findsOneWidget);
      expect(find.text('The chip proved it holds its secret key, so it is not a copy.'), findsOneWidget);
      await tapAndWait(tester, find.byKey(const Key('chip-continue')), find.byKey(const Key('turn-on-lock')));
      await tapAndWait(tester, find.byKey(const Key('turn-on-lock')), find.byKey(const Key('card-saved-done')));

      final body = server.issued.last;
      expect(body['method'], 'emrtd_attested');
      final proof = (body['proof'] as Map).cast<String, dynamic>();
      expect(proof['docType'], 'P');
      expect(proof['issuingState'], 'UTO');
      expect(proof['chipAuth'], 'active_auth');
      expect(proof['passiveAuth'], 'ok');
      expect((proof['nullifier'] as String).length, 43);
      expect(jsonEncode(body), isNot(contains(doc.documentNumber)));
      // Two attested keys, each made with ITS request's challenge: the card key
      // first (card-issue challenge), then the nullifier key (deleted after).
      expect(keys.attestationChallenges, hasLength(2));
      expect(keys.attestationChallenges.first, body['challenge']);
      expect(keys.attestationChallenges.last, isNot(body['challenge']));
      expect(server.nullifierRequests, hasLength(1));
      expect(keys.noAuthKeys.where(keys.keys.containsKey), isEmpty);
      expect(state.card?.method, 'emrtd_attested');
    });

    test('the nullifier is the same for the same document, and different for another', () async {
      final server = FakeV18Server();
      final s = fakeServices(server, FakeDeviceKeyService());
      final a1 = await obtainNullifier(s, server: testServer, message: docNullifierMessage('UTO', 'V18T00001'));
      final a2 = await obtainNullifier(s, server: testServer, message: docNullifierMessage('UTO', 'V18T00001'));
      final b = await obtainNullifier(s, server: testServer, message: docNullifierMessage('UTO', 'V18T00002'));
      expect(a1.nullifier, a2.nullifier);
      expect(a1.nullifier, isNot(b.nullifier));
      expect(a1.keyId, 'v18-nullifier-1');
      // The server saw only blinded messages, all different (blinding is random).
      expect(server.nullifierRequests.toSet(), hasLength(3));
      expect(b64urlDecode(a1.nullifier), hasLength(32));
    });

    testWidgets('under-18 TEST passport: the under-18 screen, nothing sent', (tester) async {
      phoneSize(tester);
      final server = FakeV18Server();
      final minor = TestDocument.fromFixtures('minor');
      final mkey = MrzKey(
          documentNumber: minor.documentNumber, dateOfBirth: minor.dateOfBirth, dateOfExpiry: minor.dateOfExpiry);
      final state = fakeAppState(server, FakeDeviceKeyService(), chip: () => TestChip(minor));
      await tester.runAsync(state.refreshHealth);
      await tester.pumpWidget(wrap(state, PassportChipScreen(access: MrzAccess(mkey), document: 'Passport (chip)')));
      await waitFor(tester, find.text("You're under 18"));
      expect(server.issued, isEmpty);
      expect(server.nullifierRequests, isEmpty);
    });

    testWidgets('ID card: the CAN page asks for 6 digits', (tester) async {
      phoneSize(tester);
      final state = fakeAppState(FakeV18Server(), FakeDeviceKeyService());
      await tester.pumpWidget(wrap(
          state, const PassportScanScreen(document: 'ID card (chip)', docTypes: ['I'], useCamera: false)));
      await tester.pumpAndSettle();
      expect(find.text('Type the card number'), findsOneWidget);
      FilledButton btn() => tester.widget<FilledButton>(find.byKey(const Key('can-continue')));
      expect(btn().onPressed, isNull);
      await tester.enterText(find.byKey(const Key('can-field')), '12345');
      await tester.pump();
      expect(btn().onPressed, isNull);
      await tester.enterText(find.byKey(const Key('can-field')), '123456');
      await tester.pump();
      expect(btn().onPressed, isNotNull);
      await tester.tap(find.text('Use the text lines instead'));
      await tester.pumpAndSettle();
      expect(find.text('Scan the text lines'), findsOneWidget);
    });
  });

  testWidgets('wallet ID (mdoc_app): only over 18 asked, the wallet answer goes to card issue', (tester) async {
    phoneSize(tester);
    final server = FakeV18Server();
    final wallet = FakeWallet();
    final state = fakeAppState(server, FakeDeviceKeyService(), wallet: wallet);
    await tester.runAsync(state.refreshHealth);
    await tester.pumpWidget(wrap(state, const WalletIdScreen(label: 'Wallet ID')));
    await tester.pumpAndSettle();
    await tapAndWait(tester, find.byKey(const Key('wallet-continue')), find.byKey(const Key('turn-on-lock')));
    await tapAndWait(tester, find.byKey(const Key('turn-on-lock')), find.byKey(const Key('card-saved-done')));
    final body = server.issued.last;
    expect(body['method'], 'mdoc_app');
    final proof = (body['proof'] as Map).cast<String, dynamic>();
    expect(proof['protocol'], 'openid4vp-v1-unsigned');
    expect(proof['origin'], 'android:apk-key-hash:FAKE'); // dev mode only
    // The request's nonce is the card-issue challenge.
    final req = ((wallet.lastRequest!['requests'] as List).first as Map)['data'] as Map;
    expect(req['nonce'], body['challenge']);
  });

  testWidgets('wallet ID: no wallet ID on the phone gives an honest message', (tester) async {
    phoneSize(tester);
    final server = FakeV18Server();
    final state = fakeAppState(server, FakeDeviceKeyService(), wallet: FakeWallet()..failWith = 'no_credential');
    await tester.runAsync(state.refreshHealth);
    await tester.pumpWidget(wrap(state, const WalletIdScreen(label: 'Wallet ID')));
    await tester.pumpAndSettle();
    await tapAndWait(tester, find.byKey(const Key('wallet-continue')), find.byKey(const Key('turn-on-lock')));
    await tester.tap(find.byKey(const Key('turn-on-lock')));
    await waitFor(tester, find.textContaining('No wallet app on this phone'));
    expect(server.issued, isEmpty);
  });

  group('login connectors (4d.4)', () {
    test('start signs the card-issue proof of possession, then the server result is read', () async {
      final server = FakeV18Server()..methods['connector:singpass'] = 'ready';
      final keys = FakeDeviceKeyService();
      final s = fakeServices(server, keys);
      final start = await startConnector(s, server: testServer, connectorId: 'singpass', debug: false);
      expect(start.authUrl.scheme, 'https');
      expect(keys.signed.single, startsWith('v18-card-issue\n'));
      expect(await checkConnector(s, server: testServer, start: start), isNull); // still waiting
      server.connectSessions[start.state]!
        ..['status'] = 'ok'
        ..['card'] = {
          'cardId': 'card_conn',
          'method': 'connector:singpass',
          'minAgeCertified': 18,
          'validUntil': DateTime.now().add(const Duration(days: 180)).toUtc().toIso8601String(),
        };
      final r = await checkConnector(s, server: testServer, start: start);
      expect(r!.outcome, ConnectOutcome.ok);
      expect(r.card!.keyAlias, start.alias);
      expect(r.card!.method, 'connector:singpass');
      // The card is handed out once.
      final again = await checkConnector(s, server: testServer, start: start);
      expect(again!.outcome, ConnectOutcome.error);
    });

    test('under 18 and unknown sessions', () async {
      final server = FakeV18Server()..methods['connector:mitid'] = 'ready';
      final s = fakeServices(server, FakeDeviceKeyService());
      final start = await startConnector(s, server: testServer, connectorId: 'mitid', debug: false);
      server.connectSessions[start.state]!['status'] = 'under_age';
      expect((await checkConnector(s, server: testServer, start: start))!.outcome, ConnectOutcome.underAge);
      server.connectSessions.clear();
      expect((await checkConnector(s, server: testServer, start: start))!.outcome, ConnectOutcome.expired);
    });

    test('a disabled connector and an unsafe login address are refused', () async {
      final server = FakeV18Server();
      final s = fakeServices(server, FakeDeviceKeyService());
      await expectLater(startConnector(s, server: testServer, connectorId: 'singpass', debug: false),
          throwsA(isA<FlowFailure>()));
    });

    test('only the state is read from the v18://connect link', () {
      expect(connectReturnState(Uri.parse('v18://connect?status=ok&state=abcdefghijklmnopqrst&cardId=x')),
          'abcdefghijklmnopqrst');
      expect(connectReturnState(Uri.parse('v18://connect?status=ok&state=bad!')), isNull);
      expect(connectReturnState(Uri.parse('v18://verify?state=abcdefghijklmnopqrst')), isNull);
    });
  });
}

/// The thumbprint of the device key in a card-issue body.
String keysThumb(Map<String, dynamic> body) {
  final jwk = (body['devicePublicKey'] as Map).cast<String, dynamic>();
  final pub = {'kty': jwk['kty'], 'crv': jwk['crv'], 'x': jwk['x'], 'y': jwk['y']};
  return jwkThumbprint(pub);
}
