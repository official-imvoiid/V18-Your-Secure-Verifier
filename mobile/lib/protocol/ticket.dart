import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import '../crypto/b64.dart';

/// Longest ticket life the protocol allows (PROTOCOL 3.6: expiresAt <= iat + 300).
const int maxTicketLifetimeSeconds = 300;

/// The ticket message from PROTOCOL.md section 3.6. Built on the phone and
/// never seen by the V18 server (it only sees the blinded version).
class TicketMessage {
  TicketMessage({
    required this.ticketId,
    required this.origin,
    required this.challenge,
    required this.minAge,
    required this.iat,
    required this.expiresAt,
  }) {
    if (expiresAt < iat || expiresAt - iat > maxTicketLifetimeSeconds) {
      throw ArgumentError('expiresAt must be within 300 seconds of iat');
    }
  }

  /// Makes a fresh message with a random 16-byte ticket ID.
  factory TicketMessage.create({
    required String origin,
    required String challenge,
    required int minAge,
    DateTime? now,
    int lifetimeSeconds = maxTicketLifetimeSeconds,
    Random? random,
  }) {
    final rnd = random ?? Random.secure();
    final id = Uint8List.fromList(List<int>.generate(16, (_) => rnd.nextInt(256)));
    final iat = (now ?? DateTime.now()).millisecondsSinceEpoch ~/ 1000;
    return TicketMessage(
      ticketId: b64urlEncode(id),
      origin: origin,
      challenge: challenge,
      minAge: minAge,
      iat: iat,
      expiresAt: iat + lifetimeSeconds,
    );
  }

  static const int version = 1;
  final String ticketId;
  final String origin;
  final String challenge;
  final int minAge;
  final int iat;
  final int expiresAt;

  /// The exact JSON text, with keys in the protocol's order and no spaces.
  String toJson() => jsonEncode(<String, Object>{
        'v': version,
        'ticketId': ticketId,
        'origin': origin,
        'challenge': challenge,
        'minAge': minAge,
        'iat': iat,
        'expiresAt': expiresAt,
      });

  /// UTF-8 bytes of [toJson]. This is `msg` for RFC 9474 Prepare.
  Uint8List toBytes() => Uint8List.fromList(utf8.encode(toJson()));
}

/// Ticket string: `<keyId>.<base64url(prepared)>.<base64url(signature)>`.
String buildTicketString({
  required String keyId,
  required Uint8List prepared,
  required Uint8List signature,
}) {
  if (keyId.contains('.')) {
    throw ArgumentError('keyId must not contain "."');
  }
  return '$keyId.${b64urlEncode(prepared)}.${b64urlEncode(signature)}';
}
