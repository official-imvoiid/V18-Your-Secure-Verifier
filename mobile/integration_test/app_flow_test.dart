// The real app on the Android emulator against the real dev server
// (http://10.0.2.2:8080 = the PC's localhost:8080). Real Android Keystore keys,
// real key attestation (emulator level), real unlock prompts (the host types
// the emulator's TEST screen-lock PIN: tool/run_emulator_tests.ps1), real HTTP.
//
// TEST-only parts, labelled: the website and the PC are played by this test
// over HTTP; the Aadhaar QR is the official Anon Aadhaar TEST QR handed to the
// screen that follows the camera scan; the chip document is the TEST chip
// simulator (the emulator has no NFC) with a made-up TEST passport.
//
// Run with screenshots:
//   flutter drive --driver=test_driver/integration_test.dart
//     --target=integration_test/app_flow_test.dart -d emulator-5554
import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:integration_test/integration_test.dart';
import 'package:v18/aadhaar/secure_qr.dart';
import 'package:v18/api/v18_api.dart';
import 'package:v18/app.dart';
import 'package:v18/app_state.dart';
import 'package:v18/crypto/b64.dart';
import 'package:v18/crypto/rfc9474.dart';
import 'package:v18/device/device_key.dart';
import 'package:v18/device/platform_checks.dart';
import 'package:v18/flows/flows.dart';
import 'package:v18/passport/chip_reader.dart';
import 'package:v18/passport/mrz_reader.dart';
import 'package:v18/protocol/signing_strings.dart';
import 'package:v18/storage/card_store.dart';
import 'package:v18/ui/screens/aadhaar.dart';
import 'package:v18/ui/screens/card_flow.dart';
import 'package:v18/ui/screens/passport.dart';

import '../test/helpers/fakes.dart' show FakeDeviceKeyService;
import '../test/helpers/test_chip.dart';
import 'emrtd_fixtures.dart';
import 'test_fixtures.dart';

const server = String.fromEnvironment('V18_TEST_SERVER', defaultValue: 'http://10.0.2.2:8080');
const demoOrigin = 'http://localhost:3000';

late final IntegrationTestWidgetsFlutterBinding binding;
late AppState state;
final links = StreamController<Uri>.broadcast();
final http.Client client = http.Client();
final List<String> timings = [];

TestDocument testDoc() => TestDocument.fromParts(
      com: base64.decode(testDocumentFiles['ef_com']!),
      dg1: base64.decode(testDocumentFiles['dg1']!),
      dg14: base64.decode(testDocumentFiles['dg14']!),
      dg15: base64.decode(testDocumentFiles['dg15']!),
      sod: base64.decode(testDocumentFiles['sod']!),
      meta: testDocumentMeta,
    );

Future<void> until(WidgetTester t, Finder f, {Duration timeout = const Duration(seconds: 90)}) async {
  final end = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(end)) {
    await Future<void>.delayed(const Duration(milliseconds: 150));
    await t.pump();
    if (f.evaluate().isNotEmpty) return;
  }
  throw TestFailure('Timed out waiting for $f');
}

bool _surface = false;
Future<void> shot(WidgetTester t, String name) async {
  if (!_surface) {
    await binding.convertFlutterSurfaceToImage();
    _surface = true;
  }
  await t.pump();
  await binding.takeScreenshot(name);
}

Future<void> startApp(WidgetTester t) async {
  await t.pumpWidget(V18App(state: state, links: links.stream));
  await until(t, find.byType(Scaffold));
}

NavigatorState nav(WidgetTester t) => t.state<NavigatorState>(find.byType(Navigator).first);

Future<Map<String, dynamic>> post(String path, Map<String, Object?> body, {Map<String, String>? headers}) async {
  final r = await client.post(Uri.parse('$server/v1$path'),
      headers: {'Content-Type': 'application/json', ...?headers}, body: jsonEncode(body));
  expect(r.statusCode, inInclusiveRange(200, 201), reason: '${r.statusCode} ${r.body}');
  return jsonDecode(r.body) as Map<String, dynamic>;
}

Future<Map<String, dynamic>> get(String path, {Map<String, String>? headers}) async {
  final r = await client.get(Uri.parse('$server/v1$path'), headers: headers);
  return jsonDecode(r.body) as Map<String, dynamic>;
}

/// Deep links from the server name its public URL (localhost:8080). The
/// emulator reaches the same server as 10.0.2.2:8080, so the test swaps it.
Uri forEmulator(String deepLink) => Uri.parse(deepLink.replaceAll(
    'server=http%3A%2F%2Flocalhost%3A8080', 'server=${Uri.encodeComponent(server)}'));

void main() {
  // Must run before any testWidgets (a lazy top-level would be too late).
  binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(() async {
    final kv = SecureKeyValueStore();
    await kv.delete('card');
    await kv.delete('settings');
    state = AppState(
      store: CardStore(kv),
      services: V18Services(
        keys: AndroidDeviceKeyService(),
        checks: PlatformChecks(),
        apiFor: (s) => V18Api(s, client: client, timeout: const Duration(seconds: 60)),
      ),
      // TEST chip: the emulator has no NFC. The trust is the app's real one
      // (BSI master list + the TEST CSCA because the server is in dev mode).
      chipReaderFactory: (app) =>
          ChipReader(provider: () => TestChip(testDoc()), trust: app.cscaTrust, nfcEnabled: () async => true),
    );
    await state.services.keys.deleteAllKeys();
    await state.load();
    // The dev server may still be starting: wait up to 2 minutes for it.
    for (var i = 0; i < 60 && !state.devMode; i++) {
      await Future<void>.delayed(const Duration(seconds: 2));
      await state.refreshHealth();
    }
  });

  // The screenshot surface is reset after every test.
  setUp(() => _surface = false);

  tearDownAll(() {
    // ignore: avoid_print
    print('V18_TIMINGS ${timings.join(' | ')}');
  });

  testWidgets('01 onboarding, then home with no card', (t) async {
    await startApp(t);
    await until(t, find.text("Prove you're 18+ without saying who you are"));
    await shot(t, '01_onboarding');
    await t.tap(find.text('Next'));
    await until(t, find.text('We never keep your details'));
    await t.tap(find.text('Next'));
    await until(t, find.text('Two simple steps'));
    await t.tap(find.text('Get started'));
    await until(t, find.text('No age card yet'));
    expect(state.devMode, isTrue, reason: 'the dev server must be running on the PC port 8080');
    expect(find.textContaining('TEST MODE'), findsOneWidget);
    await shot(t, '02_home_no_card');
  });

  testWidgets('02 countries and methods from the server catalog', (t) async {
    await startApp(t);
    await t.tap(find.text('Get an age card'));
    await until(t, find.byKey(const Key('country-search')));
    await shot(t, '03_countries_from_catalog');
    await t.enterText(find.byKey(const Key('country-search')), 'India');
    await until(t, find.byKey(const Key('country-IN')));
    await t.tap(find.byKey(const Key('country-IN')));
    await until(t, find.text('Choose a way to prove your age'));
    expect(find.text('Aadhaar QR'), findsOneWidget);
    expect(find.text('Passport (chip)'), findsOneWidget);
    // The emulator has no NFC: the chip method says so honestly.
    expect(find.text('This phone has no NFC, so it cannot read a chip.'), findsOneWidget);
    await shot(t, '04_india_methods');
  });

  testWidgets('03 test_dev card with a real Keystore key and unlock', (t) async {
    await startApp(t);
    await t.tap(find.text('Get an age card'));
    await until(t, find.byKey(const Key('country-search')));
    await t.enterText(find.byKey(const Key('country-search')), 'India');
    await until(t, find.byKey(const Key('country-IN')));
    await t.tap(find.byKey(const Key('country-IN')));
    await until(t, find.text('Choose a way to prove your age'));
    await t.scrollUntilVisible(find.byKey(const Key('method-test_dev')), 200, scrollable: find.byType(Scrollable).last);
    await t.tap(find.byKey(const Key('method-test_dev')));
    await until(t, find.text('Make a test card'));
    await t.tap(find.text('Continue'));
    await until(t, find.text('Turn on lock'));
    await shot(t, '05_lock');
    await t.tap(find.byKey(const Key('turn-on-lock')));
    await until(t, find.byKey(const Key('card-saved-done')), timeout: const Duration(minutes: 2));
    await shot(t, '06_test_card_saved');
    await t.tap(find.byKey(const Key('card-saved-done')));
    await until(t, find.text('18+'));
    expect(state.card?.method, 'test_dev');
    await shot(t, '07_home_with_card');
  });

  testWidgets('04 website ticket through a v18://verify deep link', (t) async {
    await startApp(t);
    final challenge = bytesToHex(randomBytes(32));
    final session = await post('/pairing/session',
        {'origin': demoOrigin, 'challenge': challenge, 'minAge': 18, 'ttlSeconds': 300},
        headers: {'Origin': demoOrigin});
    links.add(forEmulator(session['deepLink'] as String));
    await until(t, find.text('Send 18+ ticket'));
    await shot(t, '08_site_request');
    await t.tap(find.text('Send 18+ ticket'));
    await until(t, find.text('Ticket sent'), timeout: const Duration(minutes: 2));
    await shot(t, '09_ticket_sent');
    // What the website's server does (PROTOCOL 3.7): get the ticket once, check it.
    final poll = await get('/pairing/${session['sessionId']}', headers: {'Origin': demoOrigin});
    final ticket = poll['ticket'] as String;
    final parts = ticket.split('.');
    final keys = await V18Api(server, client: client).keys();
    final key = keys.firstWhere((k) => k.kid == parts[0]);
    final prepared = b64urlDecode(parts[1]);
    expect(BlindRsaClient(BlindRsaVariant.sha384PssRandomized).verify(key.publicKey, prepared, b64urlDecode(parts[2])),
        isTrue);
    final payload = jsonDecode(utf8.decode(prepared.sublist(32))) as Map;
    expect(payload['origin'], demoOrigin);
    expect(payload['challenge'], challenge);
    expect(payload['minAge'], 18);
  });

  testWidgets('05 device link: the PC gets its own card', (t) async {
    await startApp(t);
    // The "PC": a software TEST key, like the Windows app's test flag.
    final pc = FakeDeviceKeyService();
    final pcKey = await pc.createKey('pc');
    final ch = (await post('/challenge', {}))['challenge'] as String;
    final sig = await pc.sign('pc', cardIssueSigningString(challenge: ch, deviceKeyThumbprint: pcKey.thumbprint),
        title: '', subtitle: '');
    final start = await post('/card/link/start',
        {'devicePublicKey': pcKey.jwkWithAlg, 'challenge': ch, 'deviceSignature': sig.toJson()});
    links.add(forEmulator(start['deepLink'] as String));
    await until(t, find.text('Approve with fingerprint'));
    await shot(t, '10_link_approve');
    await t.tap(find.text('Approve with fingerprint'));
    await until(t, find.text('Your PC has its own age card'), timeout: const Duration(minutes: 2));
    await shot(t, '11_link_done');
    final status = await get('/card/link/${start['linkId']}');
    expect(status['status'], 'approved');
    expect((status['card'] as Map)['cardId'], startsWith('card_'));
  });

  testWidgets('06 Aadhaar: official files downloaded and checked, real proof on the phone, card', (t) async {
    await startApp(t);
    // TEST QR: the official Anon Aadhaar TEST QR, given to the screen the camera scan opens.
    final qr = AadhaarSecureQr.decode(anonAadhaarTestQr);
    unawaited(nav(t).push(MaterialPageRoute(builder: (_) => SealCheckScreen(qr: qr, testKey: true))));
    await until(t, find.byKey(const Key('seal-continue')));
    await shot(t, '12_aadhaar_seal_valid');
    await t.tap(find.byKey(const Key('seal-continue')));
    await until(
        t,
        find.byWidgetPredicate(
            (w) => w.key == const Key('download-files') || w.key == const Key('turn-on-lock')),
        timeout: const Duration(minutes: 2));
    if (find.byKey(const Key('download-files')).evaluate().isNotEmpty) {
      await shot(t, '13_aadhaar_files');
      final dl = Stopwatch()..start();
      await t.tap(find.byKey(const Key('download-files')));
      await until(t, find.byKey(const Key('turn-on-lock')), timeout: const Duration(minutes: 15));
      timings.add('aadhaar files download+check ${dl.elapsed.inSeconds}s');
    }
    await t.tap(find.byKey(const Key('turn-on-lock')));
    await until(t, find.textContaining('·'), timeout: const Duration(minutes: 1));
    await shot(t, '14_aadhaar_proving');
    await until(t, find.byKey(const Key('card-saved-done')), timeout: const Duration(minutes: 5));
    final line = t.widget<Text>(find.textContaining('The 18+ proof was made on this phone in')).data!;
    timings.add('aadhaar: $line');
    await shot(t, '15_aadhaar_card');
    expect(state.card?.method, 'anon_aadhaar');
    await t.tap(find.byKey(const Key('card-saved-done')));
    await until(t, find.text('18+'));
  });

  testWidgets('07 passport (TEST chip): checked on the phone, attested emrtd_attested card', (t) async {
    await startApp(t);
    final d = testDoc();
    final key = MrzKey(documentNumber: d.documentNumber, dateOfBirth: d.dateOfBirth, dateOfExpiry: d.dateOfExpiry);
    unawaited(nav(t).push(MaterialPageRoute(
        builder: (_) => PassportChipScreen(access: MrzAccess(key), document: 'Passport (chip)'))));
    await until(t, find.byKey(const Key('chip-continue')), timeout: const Duration(minutes: 1));
    expect(find.text('The chip proved it holds its secret key, so it is not a copy.'), findsOneWidget);
    await shot(t, '16_chip_checked');
    await t.tap(find.byKey(const Key('chip-continue')));
    await until(t, find.byKey(const Key('turn-on-lock')));
    await t.tap(find.byKey(const Key('turn-on-lock')));
    await until(t, find.byKey(const Key('card-saved-done')), timeout: const Duration(minutes: 2));
    await shot(t, '17_passport_card');
    expect(state.card?.method, anyOf('emrtd_attested', 'passport_attested'));
    await t.tap(find.byKey(const Key('card-saved-done')));
    await until(t, find.text('18+'));
  });

  testWidgets('08 delete the card (signed DELETE)', (t) async {
    await startApp(t);
    final cardId = state.card!.cardId;
    await t.tap(find.byTooltip('Settings'));
    await until(t, find.text('Delete age card'));
    await t.tap(find.text('Delete age card'));
    await until(t, find.text('Delete your age card?'));
    await shot(t, '18_delete_card');
    await t.tap(find.text('Delete'));
    await until(t, find.text('No age card yet'), timeout: const Duration(minutes: 2));
    final status = await get('/card/$cardId/status');
    expect(status['status'], 'revoked');
  });

  testWidgets('09 error screens: under 18 and offline', (t) async {
    await startApp(t);
    // Under 18: a TEST card with a made-up birth date 12 years ago; the real server says UNDER_AGE.
    final birth = DateTime.now().subtract(const Duration(days: 365 * 12));
    final ymd = '${birth.year}-${birth.month.toString().padLeft(2, '0')}-${birth.day.toString().padLeft(2, '0')}';
    unawaited(nav(t).push(MaterialPageRoute(
        builder: (_) => SetLockScreen(
              methodTitle: 'Test ID',
              next: (_) => IssueProgressScreen(
                methodTitle: 'Test ID',
                stepLabel: 'TEST MODE',
                method: 'test_dev',
                steps: const [IssueStep('Test details entered', alreadyDone: true), IssueStep('Sending')],
                proofStepIndex: 1,
                buildProof: (c, th, r) async => {'testSubjectId': 'v18-e2e-under18', 'birthDate': ymd},
              ),
            ))));
    await until(t, find.byKey(const Key('turn-on-lock')));
    await t.tap(find.byKey(const Key('turn-on-lock')));
    await until(t, find.text("You're under 18"), timeout: const Duration(minutes: 2));
    await shot(t, '19_under_18');
    await t.tap(find.text('Back to home'));
    await until(t, find.text('No age card yet'));

    // Offline: localhost:8080 is allowlisted in debug builds, but on the
    // emulator nothing listens there.
    await state.setServer('http://localhost:8080');
    await t.tap(find.text('Get an age card'));
    await until(t, find.textContaining("You're offline"), timeout: const Duration(minutes: 1));
    await shot(t, '20_offline');
    await state.setServer(server);
  });
}
