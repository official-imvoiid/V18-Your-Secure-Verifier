import 'dart:async';

import '../api/v18_api.dart';
import '../device/device_key.dart';
import '../protocol/signing_strings.dart';
import '../storage/card_store.dart';
import 'flows.dart';

/// A started login (PROTOCOL 4d.4): open [authUrl] in a Custom Tab, then wait.
class ConnectStart {
  ConnectStart({required this.connectorId, required this.state, required this.authUrl, required this.alias, required this.expiresAt});
  final String connectorId;
  final String state;
  final Uri authUrl;

  /// The new device key the card will be bound to.
  final String alias;
  final DateTime expiresAt;
}

/// How a login ended.
enum ConnectOutcome { ok, underAge, error, expired }

class ConnectResult {
  ConnectResult(this.outcome, {this.card, this.code});
  final ConnectOutcome outcome;
  final AgeCard? card;
  final String? code;
}

/// Steps 1-2 of PROTOCOL 4d.4: a new device key, the card-issue proof of
/// possession (the server's choice, docs/server/API.md section 16), and
/// POST /v1/connect/:id/start. The provider page must be HTTPS (or the local
/// dev mock provider in debug builds).
Future<ConnectStart> startConnector(V18Services s, {required String server, required String connectorId, required bool debug}) async {
  final api = s.apiFor(server);
  final alias = newDeviceKeyAlias(random: s.random);
  var keyMade = false;
  try {
    final challenge = await api.challenge();
    final key = await s.keys.createKey(alias);
    keyMade = true;
    final sig = await s.keys.sign(
      alias,
      cardIssueSigningString(challenge: challenge, deviceKeyThumbprint: key.thumbprint),
      title: 'Lock your age card',
      subtitle: 'Unlock to start the login',
    );
    final res = await api.connectStart(
        connectorId: connectorId, challenge: challenge, devicePublicKey: key.jwkWithAlg, deviceSignature: sig);
    final state = res['state'];
    final url = Uri.tryParse(res['authUrl']?.toString() ?? '');
    if (state is! String || url == null || !_allowedAuthUrl(url, debug: debug)) {
      throw const FlowFailure(FailureKind.server, 'The V18 server sent a login address that is not safe to open.');
    }
    final expiresIn = (res['expiresIn'] as num?)?.toInt() ?? 600;
    return ConnectStart(
        connectorId: connectorId,
        state: state,
        authUrl: url,
        alias: alias,
        expiresAt: s.now().add(Duration(seconds: expiresIn)));
  } on Object catch (e) {
    if (keyMade) {
      try {
        await s.keys.deleteKey(alias);
      } on Object {
        // Best effort.
      }
    }
    throw FlowFailure.from(e);
  }
}

bool _allowedAuthUrl(Uri u, {required bool debug}) {
  if (u.scheme == 'https' && u.host.isNotEmpty) return true;
  // Local mock providers in debug builds only (PROTOCOL 4d.4 test setup).
  return debug && u.scheme == 'http' && (u.host == 'localhost' || u.host == '10.0.2.2' || u.host == '127.0.0.1');
}

/// Step 4: reads the result from the server. The `v18://connect` link only
/// says "look now"; the app never trusts what the link itself says.
Future<ConnectResult?> checkConnector(V18Services s, {required String server, required ConnectStart start}) async {
  final api = s.apiFor(server);
  Map<String, dynamic> j;
  try {
    j = await api.connectSession(start.state);
  } on V18ApiException catch (e) {
    if (e.status == 404) return ConnectResult(ConnectOutcome.expired);
    throw FlowFailure.from(e);
  }
  switch (j['status']) {
    case 'waiting':
    case 'pending':
      return null;
    case 'ok':
      final c = j['card'];
      if (c is! Map) {
        // Already delivered once (for example to another poll): cannot be used here.
        return ConnectResult(ConnectOutcome.error, code: 'CARD_ALREADY_DELIVERED');
      }
      final card = IssuedCard(c.cast<String, dynamic>());
      return ConnectResult(ConnectOutcome.ok,
          card: AgeCard(
              cardId: card.cardId,
              method: card.method,
              validUntil: card.validUntil,
              keyAlias: start.alias,
              server: server));
    case 'under_age':
      return ConnectResult(ConnectOutcome.underAge, code: j['code']?.toString());
    case 'expired':
      return ConnectResult(ConnectOutcome.expired);
    default:
      return ConnectResult(ConnectOutcome.error, code: j['code']?.toString());
  }
}

/// `v18://connect?status=...&state=...` (PROTOCOL 4d.4 step 4). Only the
/// `state` is used, to know which login to look up.
String? connectReturnState(Uri uri) {
  if (uri.scheme != 'v18' || uri.host != 'connect') return null;
  final st = uri.queryParameters['state'];
  return st != null && RegExp(r'^[A-Za-z0-9_-]{16,128}$').hasMatch(st) ? st : null;
}

/// Deletes the login's device key when no card came of it.
Future<void> abandonConnector(V18Services s, ConnectStart start) async {
  try {
    await s.keys.deleteKey(start.alias);
  } on Object {
    // Best effort.
  }
}
