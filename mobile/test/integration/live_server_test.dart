import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:v18/api/v18_api.dart';
import 'package:v18/crypto/b64.dart';
import 'package:v18/crypto/rfc9474.dart';
import 'package:v18/device/platform_checks.dart';
import 'package:v18/flows/flows.dart';
import 'package:v18/protocol/deep_links.dart';
import 'package:v18/protocol/signing_strings.dart';

import '../helpers/fakes.dart';

/// A website challenge in the protocol's format (4b item 15): 32 random bytes as hex.
String siteChallenge() {
  final r = Random.secure();
  return List.generate(32, (_) => r.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
}

/// Runs the app's real flows (pure Dart, real HTTP) against a running V18
/// dev server. Skipped unless V18_LIVE_SERVER is set:
///
///   npm run dev --prefix server
///   V18_LIVE_SERVER=http://localhost:8080 flutter test test/integration
///
/// The device key is a pointycastle P-256 key (not the Android Keystore),
/// so this checks the protocol, not the phone hardware.
void main() {
  final serverUrl = Platform.environment['V18_LIVE_SERVER'];
  final skip = serverUrl == null ? 'Set V18_LIVE_SERVER to run against a live server' : false;

  final client = http.Client();
  final keys = FakeDeviceKeyService();
  final s = V18Services(
    keys: keys,
    checks: PlatformChecks(),
    apiFor: (server) => V18Api(server, client: client),
  );
  final allowlist = ServerAllowlist.forBuild(debug: true);
  final server = allowlist.normalize(serverUrl) ?? 'http://localhost:8080';
  final subject = 'live-test-${Random.secure().nextInt(1 << 32)}';

  Future<Map<String, dynamic>> post(String path, Map<String, Object?> body) async {
    final r = await client.post(Uri.parse('$server/v1$path'),
        headers: {'content-type': 'application/json'}, body: jsonEncode(body));
    expect(r.statusCode, lessThan(300), reason: '$path -> ${r.statusCode} ${r.body}');
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> get(String path) async {
    final r = await client.get(Uri.parse('$server/v1$path'));
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  /// What a website does: make a pairing session, get the v18:// deep link.
  Future<VerifyLink> websiteAsks(String challenge) async {
    final j = await post('/pairing/session', {
      'origin': 'http://localhost:3000',
      'challenge': challenge,
      'minAge': 18,
      'ttlSeconds': 120,
    });
    return parseDeepLink(j['deepLink'] as String, allowlist: allowlist, debug: true) as VerifyLink;
  }

  /// What a website's verify library does with the ticket (PROTOCOL 3.7).
  Future<Map<String, dynamic>> websiteChecks(String ticket, String challenge) async {
    final parts = ticket.split('.');
    expect(parts, hasLength(3));
    final jwks = await V18Api(server, client: client).keys();
    final key = jwks.firstWhere((k) => k.kid == parts[0]);
    final prepared = b64urlDecode(parts[1]);
    final ok = BlindRsaClient(BlindRsaVariant.sha384PssRandomized)
        .verify(key.publicKey, prepared, b64urlDecode(parts[2]));
    expect(ok, isTrue, reason: 'RSA-PSS signature over prepared');
    final payload = jsonDecode(utf8.decode(prepared.sublist(32))) as Map<String, dynamic>;
    expect(payload['v'], 1);
    expect(payload['origin'], 'http://localhost:3000');
    expect(payload['challenge'], challenge);
    expect(key.minAge, greaterThanOrEqualTo(18));
    expect((payload['expiresAt'] as int) - (payload['iat'] as int), lessThanOrEqualTo(300));
    return payload;
  }

  late final dynamic phoneCard;

  test('health: dev mode, Aadhaar nullifier seed', () async {
    final h = await V18Api(server, client: client).health();
    expect(h.devMode, isTrue);
    expect(h.aadhaarNullifierSeed, isNotNull);
  }, skip: skip);

  test('issue a test_dev card (device key proof of possession)', () async {
    phoneCard = await issueCard(s,
        server: server,
        method: 'test_dev',
        buildProof: (c, t) async => {'testSubjectId': subject, 'birthDate': '2000-01-01'});
    expect(phoneCard.cardId as String, startsWith('card_'));
    final st = await get('/card/${phoneCard.cardId}/status');
    expect(st['status'], 'active');
  }, skip: skip);

  test('website pairing: connect, blind-signed ticket, website verifies it', () async {
    final ch = siteChallenge();
    final link = await websiteAsks(ch);
    expect(link.server, server);
    await connectToSession(s, link);
    await sendTicket(s, link, phoneCard);
    final poll = await get('/pairing/${link.sessionId}');
    expect(poll['status'], 'approved');
    final ticket = poll['ticket'] as String;
    await websiteChecks(ticket, ch);
    // Handed out once only.
    final again = await get('/pairing/${link.sessionId}');
    expect(again['ticket'], isNull);
  }, skip: skip);

  test('a second ticket is unlinkable from the first', () async {
    final cha = siteChallenge();
    final chb = siteChallenge();
    final a = await websiteAsks(cha);
    await connectToSession(s, a);
    await sendTicket(s, a, phoneCard);
    final b = await websiteAsks(chb);
    await connectToSession(s, b);
    await sendTicket(s, b, phoneCard);
    final ta = (await get('/pairing/${a.sessionId}'))['ticket'] as String;
    final tb = (await get('/pairing/${b.sessionId}'))['ticket'] as String;
    final pa = await websiteChecks(ta, cha);
    final pb = await websiteChecks(tb, chb);
    expect(pa['ticketId'] == pb['ticketId'], isFalse);
    expect(ta.split('.')[2] == tb.split('.')[2], isFalse);
  }, skip: skip);

  test('device link: a "PC" gets its own card after the phone approves', () async {
    final pc = FakeDeviceKeyService();
    final pcKey = await pc.createKey('pc-key');
    final ch = (await post('/challenge', {}))['challenge'] as String;
    final pop = await pc.sign('pc-key',
        cardIssueSigningString(challenge: ch, deviceKeyThumbprint: pcKey.thumbprint),
        title: '', subtitle: '');
    final start = await post('/card/link/start', {
      'devicePublicKey': pcKey.jwkWithAlg,
      'challenge': ch,
      'deviceSignature': pop.toJson(),
    });
    final link = parseDeepLink(start['deepLink'] as String, allowlist: allowlist)
        as LinkApprovalLink;
    await approveDeviceLink(s, link, phoneCard);
    final poll = await get('/card/link/${link.linkId}');
    expect(poll['status'], 'approved');
    final pcCard = poll['card'] as Map<String, dynamic>;
    expect(pcCard['cardId'], isNot(phoneCard.cardId));
    expect(DateTime.parse(pcCard['validUntil'] as String)
        .isAfter(phoneCard.validUntil as DateTime), isFalse);
  }, skip: skip);

  test('delete the card: revoked on the server, key gone from the phone', () async {
    await deleteCardEverywhere(s, phoneCard);
    final st = await get('/card/${phoneCard.cardId}/status');
    expect(st['status'], 'revoked');
    expect(await keys.hasKey(phoneCard.keyAlias as String), isFalse);
    // The phone cannot even ask any more: its key is gone.
    final link = await websiteAsks(siteChallenge());
    await expectLater(sendTicket(s, link, phoneCard),
        throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.keyInvalidated)));
  }, skip: skip);

  test('the server refuses tickets for a revoked card (key still on the phone)', () async {
    final card = await issueCard(s,
        server: server,
        method: 'test_dev',
        buildProof: (c, t) async => {'testSubjectId': '$subject-2', 'birthDate': '2000-01-01'});
    final api = V18Api(server, client: client);
    final ch = await api.challenge();
    final sig = await keys.sign(card.keyAlias,
        cardDeleteSigningString(cardId: card.cardId, challenge: ch), title: '', subtitle: '');
    await api.deleteCard(cardId: card.cardId, challenge: ch, deviceSignature: sig);
    final link = await websiteAsks(siteChallenge());
    await expectLater(sendTicket(s, link, card),
        throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.cardExpired)));
  }, skip: skip);

  test('under 18 is refused by the server', () async {
    await expectLater(
        issueCard(s,
            server: server,
            method: 'test_dev',
            buildProof: (c, t) async => {'testSubjectId': '$subject-young', 'birthDate': '2015-06-01'}),
        throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.under18)));
  }, skip: skip);

  test('passport_zk answers METHOD_NOT_READY ("coming soon")', () async {
    await expectLater(
        issueCard(s, server: server, method: 'passport_zk', buildProof: (c, t) async => {}),
        throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.methodNotReady)));
  }, skip: skip);

  tearDownAll(client.close);
}
