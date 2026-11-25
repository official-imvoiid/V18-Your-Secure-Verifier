import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:v18/api/v18_api.dart';
import 'package:v18/crypto/b64.dart';
import 'package:v18/crypto/rfc9474.dart';
import 'package:v18/device/platform_checks.dart';
import 'package:v18/flows/flows.dart';
import 'package:v18/protocol/deep_links.dart';
import 'package:v18/storage/card_store.dart';

import '../helpers/fakes.dart';

void main() {
  late FakeV18Server server;
  late FakeDeviceKeyService keys;
  late V18Services s;

  setUp(() {
    server = FakeV18Server(now: DateTime.utc(2026, 11, 10, 12));
    keys = FakeDeviceKeyService();
    s = fakeServices(server, keys);
  });

  Future<AgeCard> makeCard({String birth = '2000-01-01'}) => issueCard(s,
      server: testServer,
      method: 'test_dev',
      buildProof: (c, t) async => {'testSubjectId': 'test-1', 'birthDate': birth});

  VerifyLink site({String session = 'sessionAAAAAAAAAAAAAAAA', int minAge = 18, String server_ = testServer}) =>
      VerifyLink(
        sessionId: session,
        origin: 'https://example-site.test',
        challenge: 'website-challenge-123',
        minAge: minAge,
        server: server_,
      );

  group('card issue (PROTOCOL 3.4, 3.5)', () {
    test('makes a device key, signs the proof of possession, stores only allowed fields', () async {
      final card = await makeCard();
      expect(card.cardId, startsWith('card_'));
      expect(card.method, 'test_dev');
      expect(card.server, testServer);
      expect(keys.keys.containsKey(card.keyAlias), isTrue);
      expect(keys.signed.single, startsWith('v18-card-issue\n'));
      expect(card.toJson().keys.toSet(), AgeCard.storedFields);
    });

    test('under 18 is refused and the new key is deleted', () async {
      await expectLater(makeCard(birth: '2015-01-01'),
          throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.under18)));
      expect(keys.keys, isEmpty);
    });

    test('cancelling the unlock gives "cancelled" and deletes the key', () async {
      keys.cancelNext = true;
      await expectLater(makeCard(),
          throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.cancelled)));
      expect(keys.keys, isEmpty);
    });

    test('passport_zk shows METHOD_NOT_READY as "coming soon"', () async {
      await expectLater(
          issueCard(s, server: testServer, method: 'passport_zk', buildProof: (c, t) async => {}),
          throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.methodNotReady)));
    });

    test('offline', () async {
      server.offline = true;
      await expectLater(makeCard(),
          throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.offline)));
    });
  });

  group('ticket (PROTOCOL 3.6, 3.8)', () {
    test('full flow: blind, sign, finalize, submit; the website can verify it', () async {
      final card = await makeCard();
      final link = site();
      server.addSession(link.sessionId, origin: link.origin, challenge: link.challenge);

      await connectToSession(s, link);
      expect(server.connected, [link.sessionId]);

      final sent = await sendTicket(s, link, card);
      final ticket = server.submittedTickets[link.sessionId]!;
      final parts = ticket.split('.');
      expect(parts, hasLength(3));
      expect(parts[0], server.kid);
      expect(server.verifyTicketSignature(ticket), isTrue);

      final prepared = b64urlDecode(parts[1]);
      final payload = jsonDecode(utf8.decode(prepared.sublist(32))) as Map<String, dynamic>;
      expect(payload.keys.toList(), ['v', 'ticketId', 'origin', 'challenge', 'minAge', 'iat', 'expiresAt']);
      expect(payload['v'], 1);
      expect(payload['origin'], 'https://example-site.test');
      expect(payload['challenge'], 'website-challenge-123');
      expect(payload['minAge'], 18);
      expect((payload['expiresAt'] as int) - (payload['iat'] as int), 300);
      expect(b64urlDecode(payload['ticketId'] as String), hasLength(16));
      expect(sent.expiresAt.millisecondsSinceEpoch ~/ 1000, payload['expiresAt']);

      final ticketSig = keys.signed.last;
      expect(ticketSig, startsWith('v18-ticket-request\n${card.cardId}\n'));
      // The server never saw the ticket message: the blinded message differs.
      expect(ticketSig.contains(parts[1]), isFalse);
    });

    test('two tickets from the same card look unrelated', () async {
      final card = await makeCard();
      server.addSession('sessionAAAAAAAAAAAAAAAA', origin: 'https://example-site.test', challenge: 'website-challenge-123');
      server.addSession('sessionBBBBBBBBBBBBBBBB', origin: 'https://example-site.test', challenge: 'website-challenge-123');
      await sendTicket(s, site(session: 'sessionAAAAAAAAAAAAAAAA'), card);
      await sendTicket(s, site(session: 'sessionBBBBBBBBBBBBBBBB'), card);
      final a = server.submittedTickets['sessionAAAAAAAAAAAAAAAA']!;
      final b = server.submittedTickets['sessionBBBBBBBBBBBBBBBB']!;
      expect(a.split('.')[1] == b.split('.')[1], isFalse);
      expect(a.split('.')[2] == b.split('.')[2], isFalse);
    });

    test('a QR whose origin does not match the session is refused', () async {
      final link = site();
      server.addSession(link.sessionId, origin: 'https://other.test', challenge: link.challenge);
      await expectLater(connectToSession(s, link),
          throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.codeMismatch)));
      expect(server.connected, isEmpty);
    });

    test('an unknown session is "expired"', () async {
      await expectLater(connectToSession(s, site()),
          throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.sessionGone)));
    });

    test('expired card, other server, higher age, child account and phone check are stopped first', () async {
      final card = await makeCard();
      final expired = AgeCard(
          cardId: card.cardId, method: card.method, validUntil: server.now.subtract(const Duration(days: 1)),
          keyAlias: card.keyAlias, server: card.server);
      Future<FailureKind> kindOf(Future<void> f) async {
        try {
          await f;
        } on FlowFailure catch (e) {
          return e.kind;
        }
        return FailureKind.other;
      }

      expect(await kindOf(preflightTicket(s, site(), expired)), FailureKind.cardExpired);
      expect(await kindOf(preflightTicket(s, site(server_: 'http://10.0.2.2:8080'), card)),
          FailureKind.wrongServer);
      expect(await kindOf(preflightTicket(s, site(minAge: 21), card)), FailureKind.siteNeedsHigherAge);

      final checks = PlatformChecks()..simulateChildAccount = true;
      final s2 = fakeServices(server, keys, checks: checks);
      expect(await kindOf(preflightTicket(s2, site(), card)), FailureKind.childAccount);
      expect(server.submittedTickets, isEmpty);
    });

    test('a revoked card gets CARD_REQUIRED, shown as "no longer active"', () async {
      final card = await makeCard();
      server.cards[card.cardId]!.active = false;
      server.addSession('sessionAAAAAAAAAAAAAAAA', origin: 'https://example-site.test', challenge: 'website-challenge-123');
      await expectLater(sendTicket(s, site(), card),
          throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.cardExpired)));
    });

    test('a bad blind signature from the server is caught by finalize', () async {
      expect(FlowFailure.from(BlindRsaException('invalid signature')).kind, FailureKind.server);
    });
  });

  group('device link (PROTOCOL 3.9)', () {
    test('approves with the right signature and never polls the link', () async {
      final card = await makeCard();
      const link = LinkApprovalLink(linkId: 'lnk_0123456789abcdefghij', server: testServer);
      await approveDeviceLink(s, link, card);
      expect(server.approvedLinks[link.linkId], card.cardId);
      expect(keys.signed.last, startsWith('v18-link-approve\n${card.cardId}\n'));
      expect(server.requests.where((r) => r.startsWith('GET /v1/card/link')), isEmpty);
    });
  });

  group('delete card', () {
    test('DELETE with a device signature, then the key is removed', () async {
      final card = await makeCard();
      await deleteCardEverywhere(s, card);
      expect(server.cards[card.cardId]!.active, isFalse);
      expect(keys.keys.containsKey(card.keyAlias), isFalse);
      expect(keys.signed.last, startsWith('v18-card-delete\n${card.cardId}\n'));
    });
  });

  group('server error codes (docs/server/API.md)', () {
    FailureKind kind(int status, String code, {String? reason}) =>
        FlowFailure.from(V18ApiException(status, code, 'x', reason: reason)).kind;

    test('CARD_REQUIRED reasons', () {
      expect(kind(401, 'CARD_REQUIRED', reason: 'card_expired'), FailureKind.cardExpired);
      expect(kind(401, 'CARD_REQUIRED', reason: 'card_revoked'), FailureKind.cardExpired);
      expect(kind(401, 'CARD_REQUIRED', reason: 'bad_signature'), FailureKind.keyInvalidated);
    });
    test('expired sessions and used PC links', () {
      expect(kind(410, 'WRONG_STATE'), FailureKind.sessionGone);
      expect(kind(404, 'SESSION_NOT_FOUND'), FailureKind.sessionGone);
      expect(kind(409, 'ALREADY_SUBMITTED'), FailureKind.sessionGone);
      expect(kind(410, 'LINK_USED'), FailureKind.sessionGone);
    });
    test('age, method and limit codes', () {
      expect(kind(403, 'UNDER_AGE'), FailureKind.under18);
      expect(kind(403, 'MIN_AGE_NOT_CERTIFIED'), FailureKind.siteNeedsHigherAge);
      expect(kind(501, 'METHOD_NOT_READY'), FailureKind.methodNotReady);
      expect(kind(501, 'METHOD_DISABLED'), FailureKind.methodDisabled);
      expect(kind(409, 'NULLIFIER_OVERUSED'), FailureKind.tooManyCards);
    });
    test('a session already "approved" (ticket handed in) is not reused', () async {
      final link = site();
      server.addSession(link.sessionId, origin: link.origin, challenge: link.challenge);
      server.sessions[link.sessionId]!['status'] = 'approved';
      await expectLater(connectToSession(s, link),
          throwsA(isA<FlowFailure>().having((f) => f.kind, 'kind', FailureKind.sessionGone)));
    });
  });

  group('ticket key choice', () {
    final pk = BlindRsaPublicKey((BigInt.one << 2047) + BigInt.one, BigInt.from(65537));
    TicketKey k(String kid, int minAge, int nbf, int exp, {String alg = 'RSABSSA-SHA384-PSS-Randomized'}) =>
        TicketKey(kid: kid, publicKey: pk, alg: alg, minAge: minAge, nbf: nbf, exp: exp);
    final now = DateTime.fromMillisecondsSinceEpoch(1000 * 1000);

    test('picks the newest valid key for the age', () {
      final keys = [k('old', 18, 0, 1100), k('new', 18, 900, 2000), k('next', 18, 1500, 3000)];
      expect(selectTicketKey(keys, siteMinAge: 18, cardMinAge: 18, now: now)!.kid, 'new');
    });
    test('the lowest enough age threshold wins (server rule)', () {
      final keys = [k('21', 21, 900, 2000), k('18', 18, 800, 2000)];
      expect(selectTicketKey(keys, siteMinAge: 18, cardMinAge: 21, now: now)!.kid, '18');
    });
    test('skips wrong algorithm, expired, future and too-high-age keys', () {
      final keys = [
        k('alg', 18, 0, 2000, alg: 'RS256'),
        k('exp', 18, 0, 999),
        k('future', 18, 1001, 2000),
        k('21', 21, 0, 2000),
      ];
      expect(selectTicketKey(keys, siteMinAge: 18, cardMinAge: 18, now: now), isNull);
    });
  });
}
