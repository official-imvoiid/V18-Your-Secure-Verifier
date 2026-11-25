import 'dart:convert';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:v18/crypto/b64.dart';
import 'package:v18/crypto/jwk.dart';
import 'package:v18/protocol/signing_strings.dart';
import 'package:v18/protocol/ticket.dart';

void main() {
  group('signing strings (PROTOCOL 3.4)', () {
    test('issue card', () {
      expect(cardIssueSigningString(challenge: 'c0ffee', deviceKeyThumbprint: 'tp'),
          'v18-card-issue\nc0ffee\ntp');
    });
    test('request ticket', () {
      expect(
          ticketRequestSigningString(
              cardId: 'card_abc', challenge: 'ch', keyId: 'v18-age18-20261109', blindedMessage: 'bm'),
          'v18-ticket-request\ncard_abc\nch\nv18-age18-20261109\nbm');
    });
    test('approve device link', () {
      expect(linkApproveSigningString(cardId: 'card_abc', challenge: 'ch', linkId: 'lnk'),
          'v18-link-approve\ncard_abc\nch\nlnk');
    });
    test('delete card', () {
      expect(cardDeleteSigningString(cardId: 'card_abc', challenge: 'ch'),
          'v18-card-delete\ncard_abc\nch');
    });
    test('no trailing newline, and newlines inside fields are refused', () {
      expect(cardDeleteSigningString(cardId: 'a', challenge: 'b').endsWith('\n'), isFalse);
      expect(() => cardDeleteSigningString(cardId: 'a\nb', challenge: 'c'), throwsArgumentError);
    });
  });

  group('ticket message (PROTOCOL 3.6)', () {
    test('exact JSON text and key order', () {
      final m = TicketMessage(
        ticketId: 'AAECAwQFBgcICQoLDA0ODw',
        origin: 'https://example-site.test',
        challenge: 'site-challenge',
        minAge: 18,
        iat: 1762700000,
        expiresAt: 1762700300,
      );
      expect(
          m.toJson(),
          '{"v":1,"ticketId":"AAECAwQFBgcICQoLDA0ODw","origin":"https://example-site.test",'
          '"challenge":"site-challenge","minAge":18,"iat":1762700000,"expiresAt":1762700300}');
      expect(utf8.decode(m.toBytes()), m.toJson());
    });

    test('create(): 16 random bytes for ticketId, 300 second life', () {
      final m = TicketMessage.create(
        origin: 'https://a.test',
        challenge: 'x',
        minAge: 18,
        now: DateTime.fromMillisecondsSinceEpoch(1762700000123),
        random: Random(1),
      );
      expect(b64urlDecode(m.ticketId).length, 16);
      expect(m.ticketId.contains('='), isFalse);
      expect(m.iat, 1762700000);
      expect(m.expiresAt - m.iat, 300);
    });

    test('a life over 300 seconds is refused', () {
      expect(
          () => TicketMessage(
              ticketId: 't', origin: 'o', challenge: 'c', minAge: 18, iat: 0, expiresAt: 301),
          throwsArgumentError);
    });

    test('ticket string is keyId.base64url(prepared).base64url(sig)', () {
      final s = buildTicketString(
          keyId: 'v18-age18-20261109', prepared: hexToBytes('00ff10'), signature: hexToBytes('abcd'));
      expect(s, 'v18-age18-20261109.AP8Q.q80');
    });
  });

  group('JWK thumbprint (RFC 7638)', () {
    test('RFC 7638 section 3.1 example', () {
      const jwk = {
        'kty': 'RSA',
        'n': '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
        'e': 'AQAB',
        'alg': 'RS256',
        'kid': '2011-04-29',
      };
      expect(jwkThumbprint(jwk), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
    });

    test('EC P-256 key matches the server library (jose calculateJwkThumbprint)', () {
      // Expected value computed with jose (server/node_modules) for this key.
      const jwk = {
        'kty': 'EC',
        'x': 'bBLQGCZCGjIZTwkd6G7daPxPcpcBDoTaFFSslbp5lng',
        'y': '9gNs-xVMVXMxH07ocs5R8FfXPiVNbXzLpd8NrsgIhvo',
        'crv': 'P-256',
      };
      expect(jwkThumbprint(jwk), 'OTw_Ug68x0L4WDBg3cNRUo63jf6rioJ0tPQnYbiR8kU');
      expect(jwkThumbprint({...jwk, 'alg': 'ES256'}), jwkThumbprint(jwk));
    });
  });

  group('base64url', () {
    test('no padding, URL-safe alphabet, decodes with or without padding', () {
      expect(b64urlEncode([0xfb, 0xff]), '-_8');
      expect(b64urlDecode('-_8'), [0xfb, 0xff]);
      expect(b64urlDecode('-_8='), [0xfb, 0xff]);
    });
  });
}
