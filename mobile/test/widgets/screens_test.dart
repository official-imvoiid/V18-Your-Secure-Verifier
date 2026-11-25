import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:v18/app.dart';
import 'package:v18/app_state.dart';
import 'package:v18/flows/flows.dart';
import 'package:v18/storage/card_store.dart';
import 'package:v18/catalog/catalog.dart';
import 'package:v18/ui/screens/aadhaar.dart';
import 'package:v18/ui/screens/country.dart';
import 'package:v18/ui/screens/errors.dart';
import 'package:v18/ui/screens/info_pages.dart';
import 'package:v18/ui/theme.dart';

import '../helpers/fakes.dart';

/// Phone-sized test screen (390 x 844, like the designs).
void phoneSize(WidgetTester tester) {
  tester.view.physicalSize = const Size(1170, 2532);
  tester.view.devicePixelRatio = 3;
  addTearDown(tester.view.reset);
}

Future<AppState> pumpApp(
  WidgetTester tester, {
  FakeV18Server? server,
  FakeDeviceKeyService? keys,
  bool onboarded = true,
  AgeCard? card,
  Stream<Uri>? links,
}) async {
  phoneSize(tester);
  // The Kotlin platform channel (PlatformChannel.kt) answers "unknown" for
  // child accounts on a real phone. Same answer here.
  tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      const MethodChannel('com.v18.app/platform'),
      (call) async => call.method == 'childAccountStatus' ? 'unknown' : null);
  final srv = server ?? FakeV18Server();
  final kv = MemoryKeyValueStore();
  if (onboarded) kv.data['settings'] = '{"onboarded":true,"sharedDevice":false,"server":"$testServer"}';
  final state = fakeAppState(srv, keys ?? FakeDeviceKeyService(), kv: kv);
  if (card != null) await CardStore(kv).saveCard(card);
  await tester.pumpWidget(V18App(state: state, links: links));
  await state.load();
  await tester.pumpAndSettle();
  return state;
}

Widget wrap(AppState state, Widget child) => AppScope(
    state: state, child: MaterialApp(home: child));

AgeCard testCard({DateTime? until, String alias = 'v18_card_test'}) => AgeCard(
      cardId: 'card_test',
      method: 'test_dev',
      validUntil: until ?? DateTime.now().add(const Duration(days: 30)),
      keyAlias: alias,
      server: testServer,
    );

void main() {
  testWidgets('onboarding: three pages, then home with no card', (tester) async {
    await pumpApp(tester, onboarded: false);
    expect(find.text("Prove you're 18+ without saying who you are"), findsOneWidget);
    await tester.tap(find.text('Next'));
    await tester.pumpAndSettle();
    expect(find.text('We never keep your details'), findsOneWidget);
    await tester.tap(find.text('Next'));
    await tester.pumpAndSettle();
    expect(find.text('Two simple steps'), findsOneWidget);
    await tester.tap(find.text('Get started'));
    await tester.pumpAndSettle();
    expect(find.text('No age card yet'), findsOneWidget);
  });

  testWidgets('home without a card, TEST MODE banner, country and India methods', (tester) async {
    await pumpApp(tester);
    expect(find.textContaining('TEST MODE'), findsOneWidget);
    expect(find.text('No age card yet'), findsOneWidget);
    await tester.tap(find.text('Get an age card'));
    await tester.pumpAndSettle();
    expect(find.text('Where is your ID from?'), findsOneWidget);
    await tester.tap(find.text('India').first);
    await tester.pumpAndSettle();
    expect(find.text('Choose a way to prove your age'), findsOneWidget);
    // Exactly what the server's catalog lists for India, best privacy first.
    expect(find.text('Aadhaar QR'), findsOneWidget);
    expect(find.text('Passport (chip)'), findsOneWidget);
    expect(find.text('Most private'), findsOneWidget);
    expect(find.text('Zero-knowledge proof'), findsOneWidget);
    expect(tester.getTopLeft(find.text('Aadhaar QR')).dy,
        lessThan(tester.getTopLeft(find.text('Passport (chip)')).dy));
    expect(find.textContaining('coming soon', findRichText: true), findsNothing);
    await tester.scrollUntilVisible(find.text('Test ID'), 200);
    expect(find.text('Test ID'), findsOneWidget); // dev server only
  });

  testWidgets('no TEST MODE banner and no test card against a production server', (tester) async {
    await pumpApp(tester, server: FakeV18Server(devMode: false));
    expect(find.textContaining('TEST MODE'), findsNothing);
    await tester.tap(find.text('Get an age card'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('India').first);
    await tester.pumpAndSettle();
    await tester.drag(find.byType(Scrollable).last, const Offset(0, -2000));
    await tester.pumpAndSettle();
    expect(find.text('Whichever you pick, V18 never keeps your name, birth date or ID number.'), findsOneWidget);
    expect(find.text('Test ID'), findsNothing);
  });

  testWidgets('countries and methods come only from the catalog; face and unknown methods never show',
      (tester) async {
    await pumpApp(tester);
    await tester.tap(find.text('Get an age card'));
    await tester.pumpAndSettle();
    // The fake catalog has IN, DE and SG; SG's only method (a connector) is not
    // enabled on this server, so the server filtered SG out.
    expect(find.byKey(const Key('country-IN')), findsOneWidget);
    expect(find.byKey(const Key('country-DE')), findsOneWidget);
    expect(find.byKey(const Key('country-SG')), findsNothing);
    expect(find.text('Philippines'), findsNothing);
    await tester.tap(find.byKey(const Key('country-DE')));
    await tester.pumpAndSettle();
    expect(find.text('Passport (chip)'), findsOneWidget);
    expect(find.text('ID card (chip)'), findsOneWidget);
    // The catalog lists face_estimate, but this app has no shippable model
    // (no face model meets PROTOCOL.md 4c.6), so it is not shown.
    expect(find.text('Face estimate'), findsNothing);
  });

  testWidgets('search filters the catalog countries', (tester) async {
    await pumpApp(tester);
    await tester.tap(find.text('Get an age card'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('country-search')), 'germ');
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('country-DE')), findsOneWidget);
    expect(find.byKey(const Key('country-IN')), findsNothing);
  });

  testWidgets('a connector shows only when the server enables it', (tester) async {
    final server = FakeV18Server()..methods['connector:singpass'] = 'ready';
    await pumpApp(tester, server: server);
    await tester.tap(find.text('Get an age card'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('country-SG')));
    await tester.pumpAndSettle();
    expect(find.text('Singpass (Myinfo)'), findsOneWidget);
    expect(find.text('Government and bank logins'), findsOneWidget);
  });

  testWidgets('a phone without NFC says so instead of offering the chip', (tester) async {
    phoneSize(tester);
    final server = FakeV18Server();
    final state = fakeAppState(server, FakeDeviceKeyService(),
        capabilities: const AppCapabilities(
            aadhaarProver: true, nfc: false, digitalCredentials: true, customTabs: true));
    await state.refreshHealth();
    final catalog = await state.loadCatalog();
    await tester.pumpWidget(wrap(state, MethodsScreen(country: catalog.byCode('IN')!)));
    await tester.pumpAndSettle();
    expect(find.text('This phone has no NFC, so it cannot read a chip.'), findsOneWidget);
  });

  testWidgets('home with an active card', (tester) async {
    await pumpApp(tester, card: testCard());
    expect(find.text('18+'), findsOneWidget);
    expect(find.text('Test ID (not real)'), findsOneWidget);
    expect(find.text('Nothing about you is stored'), findsOneWidget);
    expect(find.text('Scan a website or PC code'), findsOneWidget);
  });

  testWidgets('home with an expired card', (tester) async {
    await pumpApp(tester, card: testCard(until: DateTime.now().subtract(const Duration(days: 2))));
    expect(find.text('Your age card has expired'), findsOneWidget);
    expect(find.text('Expired'), findsOneWidget);
    expect(find.text('Renew age card'), findsOneWidget);
  });

  testWidgets('website deep link -> site request -> ticket sent', (tester) async {
    final server = FakeV18Server();
    final keys = FakeDeviceKeyService();
    final links = StreamController<Uri>();
    addTearDown(links.close);
    final state = await pumpApp(tester, server: server, keys: keys, links: links.stream);

    // Make a real card against the fake server first.
    final card = await issueCard(state.services,
        server: testServer,
        method: 'test_dev',
        buildProof: (c, t) async => {'testSubjectId': 't', 'birthDate': '2000-01-01'});
    await state.saveCard(card);
    await tester.pumpAndSettle();

    const session = 'sessionAAAAAAAAAAAAAAAA';
    server.addSession(session, origin: 'https://example-site.test', challenge: 'site-ch-1');
    links.add(Uri.parse('v18://verify?session=$session'
        '&origin=https%3A%2F%2Fexample-site.test&challenge=site-ch-1&minAge=18'
        '&server=http%3A%2F%2Flocalhost%3A8080'));
    await tester.pumpAndSettle();

    expect(find.text('example-site.test'), findsOneWidget);
    expect(find.text('Are you 18+?'), findsOneWidget);
    expect(find.text('THE SITE GETS'), findsOneWidget);
    expect(find.text("THE SITE DOESN'T GET"), findsOneWidget);
    expect(find.text('Your name'), findsOneWidget);
    expect(find.text('The ticket expires in 5 minutes.'), findsOneWidget);
    expect(server.connected, [session]);

    await tester.tap(find.text('Send 18+ ticket'));
    await tester.pumpAndSettle();
    expect(find.text('Ticket sent'), findsOneWidget);
    expect(find.text('Works once'), findsOneWidget);
    expect(server.submittedTickets[session], isNotNull);
    expect(server.verifyTicketSignature(server.submittedTickets[session]!), isTrue);
  });

  testWidgets('"Don\'t send" cancels the pairing session', (tester) async {
    final server = FakeV18Server();
    final links = StreamController<Uri>();
    addTearDown(links.close);
    await pumpApp(tester, server: server, card: testCard(), links: links.stream);
    const session = 'sessionCCCCCCCCCCCCCCCC';
    server.addSession(session, origin: 'https://example-site.test', challenge: 'x');
    links.add(Uri.parse('v18://verify?session=$session&origin=https%3A%2F%2Fexample-site.test'
        '&challenge=x&minAge=18&server=http%3A%2F%2Flocalhost%3A8080'));
    await tester.pumpAndSettle();
    await tester.tap(find.text("Don't send"));
    await tester.pumpAndSettle();
    expect(server.cancelled, [session]);
    expect(find.text('Scan a website or PC code'), findsOneWidget);
  });

  testWidgets('a link to an untrusted server is refused', (tester) async {
    final links = StreamController<Uri>();
    addTearDown(links.close);
    await pumpApp(tester, card: testCard(), links: links.stream);
    links.add(Uri.parse('v18://verify?session=sessionAAAAAAAAAAAAAAAA'
        '&origin=https%3A%2F%2Fexample-site.test&challenge=x&minAge=18&server=https%3A%2F%2Fevil.test'));
    await tester.pumpAndSettle();
    expect(find.text('Untrusted server'), findsOneWidget);
  });

  testWidgets('device link approval', (tester) async {
    final server = FakeV18Server();
    final keys = FakeDeviceKeyService();
    final links = StreamController<Uri>();
    addTearDown(links.close);
    final state = await pumpApp(tester, server: server, keys: keys, links: links.stream);
    final card = await issueCard(state.services,
        server: testServer,
        method: 'test_dev',
        buildProof: (c, t) async => {'testSubjectId': 't', 'birthDate': '2000-01-01'});
    await state.saveCard(card);
    links.add(Uri.parse('v18://link?id=lnk_0123456789abcdefghij&server=http%3A%2F%2Flocalhost%3A8080'));
    await tester.pumpAndSettle();
    expect(find.text('Add an age card to your PC?'), findsOneWidget);
    await tester.tap(find.text('Approve with fingerprint'));
    await tester.pumpAndSettle();
    expect(find.text('Your PC has its own age card'), findsOneWidget);
    expect(server.approvedLinks['lnk_0123456789abcdefghij'], card.cardId);
  });

  testWidgets('settings: shared device mode, learn pages', (tester) async {
    final state = await pumpApp(tester, card: testCard());
    await tester.tap(find.byTooltip('Settings'));
    await tester.pumpAndSettle();
    expect(find.text('Shared device mode'), findsOneWidget);
    expect(find.text('Delete age card'), findsOneWidget);
    await tester.tap(find.text('Shared device mode'));
    await tester.pumpAndSettle();
    expect(find.text('Turn on shared device mode?'), findsOneWidget);
    await tester.tap(find.text('Turn on'));
    await tester.pumpAndSettle();
    expect(state.settings.sharedDevice, isTrue);
    expect(await state.store.loadCard(), isNull);

    await tester.scrollUntilVisible(find.text('How seals work'), 200);
    await tester.tap(find.text('How seals work'));
    await tester.pumpAndSettle();
    expect(find.text('Change one letter, the seal breaks'), findsOneWidget);
  });

  testWidgets('delete card from settings', (tester) async {
    final server = FakeV18Server();
    final keys = FakeDeviceKeyService();
    final state = await pumpApp(tester, server: server, keys: keys);
    final card = await issueCard(state.services,
        server: testServer,
        method: 'test_dev',
        buildProof: (c, t) async => {'testSubjectId': 't', 'birthDate': '2000-01-01'});
    await state.saveCard(card);
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Settings'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Delete age card'));
    await tester.pumpAndSettle();
    expect(find.text('Delete your age card?'), findsOneWidget);
    await tester.tap(find.text('Delete'));
    await tester.pumpAndSettle();
    expect(find.text('No age card yet'), findsOneWidget);
    expect(server.cards[card.cardId]!.active, isFalse);
    expect(state.card, isNull);
  });

  group('error and info screens', () {
    late AppState state;
    setUp(() => state = fakeAppState(FakeV18Server(), FakeDeviceKeyService()));

    Future<void> show(WidgetTester tester, Widget Function(BuildContext) b) async {
      phoneSize(tester);
      await tester.pumpWidget(wrap(state, Builder(builder: b)));
      await tester.pumpAndSettle();
    }

    testWidgets('offline', (t) async {
      await show(t, (c) => offlineErrorScreen(c));
      expect(find.text("You're offline"), findsOneWidget);
      expect(find.text('Try again'), findsOneWidget);
    });
    testWidgets('chip seal invalid', (t) async {
      await show(t, (c) => chipSealErrorScreen(c));
      expect(find.text("We couldn't confirm this ID"), findsOneWidget);
    });
    testWidgets('Aadhaar seal invalid', (t) async {
      await show(t, (c) => aadhaarSealErrorScreen(c));
      expect(find.text("We couldn't confirm this QR"), findsOneWidget);
    });
    testWidgets('under 18 (site and card)', (t) async {
      await show(t, (c) => under18SiteErrorScreen(c, 'example-site.com'));
      expect(find.text('This site is 18+'), findsOneWidget);
      await show(t, (c) => under18CardErrorScreen(c));
      expect(find.text("You're under 18"), findsOneWidget);
    });
    testWidgets('child account, with an honest note', (t) async {
      await show(t, (c) => childAccountErrorScreen(c, 'example-site.com'));
      expect(find.text('This phone has a child account'), findsOneWidget);
      // Only a debug test switch shows this screen, and it says so.
      expect(find.text('TEST'), findsOneWidget);
    });
    testWidgets('expired card', (t) async {
      await show(t, (c) => expiredErrorScreen(c));
      expect(find.text('Your age card has expired'), findsOneWidget);
    });
    testWidgets('privacy info', (t) async {
      await show(t, (c) => const PrivacyInfoScreen());
      expect(find.text('Never stored, anywhere'), findsOneWidget);
    });
    testWidgets('child account info page', (t) async {
      await show(t, (c) => const ChildAccountInfoScreen());
      expect(find.text('What Android does not tell apps (yet)'), findsOneWidget);
    });
    testWidgets('Aadhaar scan screen (no camera in tests)', (t) async {
      await show(t, (c) => const AadhaarScanScreen(useCamera: false));
      expect(find.text('Scan your Aadhaar QR'), findsOneWidget);
      expect(find.text('Import e-Aadhaar PDF or image'), findsOneWidget);
    });
  });

  test('text styles keep a readable colour in both themes (found on the emulator)', () {
    for (final b in Brightness.values) {
      final t = v18Theme(b);
      for (final st in [t.textTheme.headlineLarge, t.textTheme.headlineMedium, t.textTheme.bodyMedium, t.textTheme.bodyLarge]) {
        expect(st?.color, t.colorScheme.onSurface, reason: '$b');
      }
    }
  });
}
