import 'dart:async';
import 'dart:convert';
import 'dart:io' show SocketException, HandshakeException;
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../crypto/b64.dart';
import '../crypto/rfc9474.dart';

/// The server said no: `{"error": "...", "code": "..."}` with a 4xx/5xx.
class V18ApiException implements Exception {
  V18ApiException(this.status, this.code, this.message, {this.reason});
  final int status;
  final String code;
  final String message;

  /// Extra detail some errors carry, for example CARD_REQUIRED's
  /// `missing_card`, `bad_signature`, `card_revoked`, `card_expired`.
  final String? reason;

  @override
  String toString() => 'V18ApiException($status $code: $message)';
}

/// The phone could not reach the server.
class OfflineException implements Exception {
  const OfflineException([this.detail]);
  final String? detail;
  @override
  String toString() => 'OfflineException($detail)';
}

/// A device signature `{alg, sig}` (PROTOCOL 3.4).
class DeviceSignature {
  const DeviceSignature(this.alg, this.sig);
  final String alg;

  /// base64url of the DER (or raw r||s) ECDSA signature.
  final String sig;

  Map<String, String> toJson() => {'alg': alg, 'sig': sig};
}

class ServerHealth {
  ServerHealth(this.raw);
  final Map<String, dynamic> raw;

  bool get devMode => raw['devMode'] == true;

  /// Published by the server in /v1/health (PROTOCOL.md 4b item 2). Null if the server does not
  /// send it.
  String? get aadhaarNullifierSeed => raw['aadhaarNullifierSeed']?.toString();
}

/// One ticket signing key from GET /v1/keys (PROTOCOL 3.2).
class TicketKey {
  TicketKey({
    required this.kid,
    required this.publicKey,
    required this.alg,
    required this.minAge,
    required this.nbf,
    required this.exp,
  });

  static TicketKey? fromJwk(Map<String, dynamic> j) {
    try {
      if (j['kty'] != 'RSA') return null;
      final n = os2ip(b64urlDecode(j['n'] as String));
      final e = os2ip(b64urlDecode(j['e'] as String));
      return TicketKey(
        kid: j['kid'] as String,
        publicKey: BlindRsaPublicKey(n, e),
        alg: j['alg'] as String? ?? '',
        minAge: (j['v18_min_age'] as num).toInt(),
        nbf: (j['nbf'] as num).toInt(),
        exp: (j['exp'] as num).toInt(),
      );
    } on Object {
      return null;
    }
  }

  final String kid;
  final BlindRsaPublicKey publicKey;
  final String alg;
  final int minAge;
  final int nbf;
  final int exp;
}

/// Picks the ticket key to use: right algorithm, at least 2048 bits, age
/// threshold at least the site's and no more than the card's, valid now.
/// The lowest age threshold that is enough wins (the site learns no more
/// than it asked for); among those, the newest (largest nbf), which is the
/// server's "current" key.
TicketKey? selectTicketKey(
  List<TicketKey> keys, {
  required int siteMinAge,
  required int cardMinAge,
  required DateTime now,
}) {
  final t = now.millisecondsSinceEpoch ~/ 1000;
  final ok = keys.where((k) =>
      k.alg == BlindRsaVariant.sha384PssRandomized.name &&
      k.publicKey.modulusBits >= 2048 &&
      k.minAge >= siteMinAge &&
      k.minAge <= cardMinAge &&
      k.nbf <= t &&
      t < k.exp).toList()
    ..sort((a, b) =>
        a.minAge != b.minAge ? a.minAge.compareTo(b.minAge) : b.nbf.compareTo(a.nbf));
  return ok.isEmpty ? null : ok.first;
}

/// The nullifier key `v18-nullifier-1` (PROTOCOL 4c.2).
class NullifierKey {
  NullifierKey(this.kid, this.publicKey);
  static const String expectedAlg = 'RSABSSA-SHA384-PSSZERO-Deterministic';

  static NullifierKey? fromJwk(Map<String, dynamic> j) {
    try {
      if (j['kty'] != 'RSA') return null;
      final alg = j['alg'];
      if (alg != null && alg != expectedAlg) return null;
      final kid = j['kid'] as String? ?? 'v18-nullifier-1';
      final pk = BlindRsaPublicKey(
          os2ip(b64urlDecode(j['n'] as String)), os2ip(b64urlDecode(j['e'] as String)));
      if (pk.modulusBits < 2048) return null;
      return NullifierKey(kid, pk);
    } on Object {
      return null;
    }
  }

  final String kid;
  final BlindRsaPublicKey publicKey;
}

class IssuedCard {
  IssuedCard(this.raw);
  final Map<String, dynamic> raw;
  String get cardId => raw['cardId'] as String;
  String get method => raw['method'] as String;
  DateTime get validUntil => DateTime.parse(raw['validUntil'] as String);
  int get minAgeCertified => (raw['minAgeCertified'] as num?)?.toInt() ?? 18;
}

class BlindSignResult {
  BlindSignResult(this.blindSignature, this.keyId, this.algorithm);
  final String blindSignature;
  final String keyId;
  final String algorithm;
}

/// Client for the V18 server, protocol version 1.
///
/// PRIVACY: request and response bodies are never logged.
class V18Api {
  V18Api(this.server, {http.Client? client, this.timeout = const Duration(seconds: 15)})
      : _client = client ?? http.Client();

  /// Allowlisted server origin, without /v1.
  final String server;
  final http.Client _client;
  final Duration timeout;

  Uri _u(String path) => Uri.parse('$server/v1$path');

  Future<ServerHealth> health() async =>
      ServerHealth(await _send('GET', '/health'));

  Future<String> challenge() async {
    final j = await _send('POST', '/challenge', body: const {});
    final c = j['challenge'];
    if (c is! String || c.isEmpty) {
      throw V18ApiException(502, 'BAD_RESPONSE', 'No challenge in response');
    }
    return c;
  }

  Future<List<TicketKey>> keys() async {
    final j = await _send('GET', '/keys');
    final list = (j['keys'] as List?) ?? const [];
    return list
        .whereType<Map<String, dynamic>>()
        .map(TicketKey.fromJwk)
        .whereType<TicketKey>()
        .toList();
  }

  Future<IssuedCard> issueCard({
    required String method,
    required String challenge,
    required Map<String, dynamic> devicePublicKey,
    required DeviceSignature deviceSignature,
    required Map<String, Object?> proof,
    List<String>? keyAttestation,
  }) async =>
      IssuedCard(await _send('POST', '/card/issue', body: {
        'method': method,
        'challenge': challenge,
        'devicePublicKey': devicePublicKey,
        'deviceSignature': deviceSignature.toJson(),
        'proof': proof,
        'keyAttestation': ?keyAttestation,
      }));

  /// GET /v1/keys/nullifier (PROTOCOL 4c.2). Accepts one JWK or a JWKS.
  Future<NullifierKey> nullifierKey() async {
    final j = await _send('GET', '/keys/nullifier');
    final list = j['keys'] is List ? (j['keys'] as List) : [j];
    for (final k in list.whereType<Map<String, dynamic>>()) {
      final key = NullifierKey.fromJwk(k);
      if (key != null) return key;
    }
    throw V18ApiException(502, 'BAD_RESPONSE', 'No usable nullifier key');
  }

  /// POST /v1/nullifier/blind-sign. Returns the blind signature (bytes).
  Future<Uint8List> nullifierBlindSign({
    required String challenge,
    required String blindedMessage,
    required Map<String, dynamic> devicePublicKey,
    required DeviceSignature deviceSignature,
    required List<String>? keyAttestation,
  }) async {
    final j = await _send('POST', '/nullifier/blind-sign', body: {
      'challenge': challenge,
      'blindedMessage': blindedMessage,
      'devicePublicKey': devicePublicKey,
      'deviceSignature': deviceSignature.toJson(),
      'keyAttestation': ?keyAttestation,
    });
    final b = j['blindSignature'];
    if (b is! String) throw V18ApiException(502, 'BAD_RESPONSE', 'No blind signature');
    return b64urlDecode(b);
  }

  /// GET /v1/catalog (PROTOCOL 4d.2), filtered by this deployment.
  Future<Map<String, dynamic>> catalog({String? country, String? platform}) {
    final q = <String>[
      if (country != null) 'country=${Uri.encodeQueryComponent(country)}',
      if (platform != null) 'platform=${Uri.encodeQueryComponent(platform)}',
    ];
    return _send('GET', '/catalog${q.isEmpty ? '' : '?${q.join('&')}'}');
  }

  /// POST /v1/connect/:id/start (PROTOCOL 4d.4). Returns `{authUrl, state}`.
  Future<Map<String, dynamic>> connectStart({
    required String connectorId,
    required String challenge,
    required Map<String, dynamic> devicePublicKey,
    required DeviceSignature deviceSignature,
    List<String>? keyAttestation,
  }) =>
      _send('POST', '/connect/${Uri.encodeComponent(connectorId)}/start', body: {
        'challenge': challenge,
        'devicePublicKey': devicePublicKey,
        'deviceSignature': deviceSignature.toJson(),
        'keyAttestation': ?keyAttestation,
      });

  /// GET /v1/connect/session/:state: `{status, card?}` (fallback poll).
  Future<Map<String, dynamic>> connectSession(String state) =>
      _send('GET', '/connect/session/${Uri.encodeComponent(state)}');

  /// POST /v1/wallet/app-request (PROTOCOL 4d.3 `mdoc_app`, docs/server/API.md
  /// section 14). The challenge is NOT used up here; it becomes the request's
  /// nonce, and the same challenge then goes into POST /v1/card/issue.
  /// Returns `{digital: {requests: [...]}, expiresAt}`.
  Future<Map<String, dynamic>> walletAppRequest({required String challenge}) =>
      _send('POST', '/wallet/app-request', body: {'challenge': challenge});

  Future<void> deleteCard({
    required String cardId,
    required String challenge,
    required DeviceSignature deviceSignature,
  }) =>
      _send('DELETE', '/card/${Uri.encodeComponent(cardId)}', body: {
        'challenge': challenge,
        'deviceSignature': deviceSignature.toJson(),
      });

  /// `{status: "active" | "revoked" | "expired", validUntil}`
  Future<Map<String, dynamic>> cardStatus(String cardId) =>
      _send('GET', '/card/${Uri.encodeComponent(cardId)}/status');

  Future<BlindSignResult> blindSign({
    required String cardId,
    required String challenge,
    required String keyId,
    required String blindedMessage,
    required DeviceSignature deviceSignature,
  }) async {
    final j = await _send('POST', '/ticket/blind-sign', body: {
      'cardId': cardId,
      'challenge': challenge,
      'keyId': keyId,
      'blindedMessage': blindedMessage,
      'deviceSignature': deviceSignature.toJson(),
    });
    return BlindSignResult(j['blindSignature'] as String, j['keyId'] as String,
        j['algorithm'] as String? ?? '');
  }

  Future<Map<String, dynamic>> pairingGet(String sessionId) =>
      _send('GET', '/pairing/${Uri.encodeComponent(sessionId)}');

  Future<void> pairingConnect(String sessionId) =>
      _send('POST', '/pairing/${Uri.encodeComponent(sessionId)}/connect', body: const {});

  Future<void> pairingSubmit(String sessionId, String ticket) =>
      _send('POST', '/pairing/${Uri.encodeComponent(sessionId)}/submit',
          body: {'ticket': ticket});

  Future<void> pairingCancel(String sessionId) =>
      _send('POST', '/pairing/${Uri.encodeComponent(sessionId)}/cancel', body: const {});

  Future<void> approveLink({
    required String linkId,
    required String cardId,
    required String challenge,
    required DeviceSignature deviceSignature,
  }) =>
      _send('POST', '/card/link/${Uri.encodeComponent(linkId)}/approve', body: {
        'cardId': cardId,
        'challenge': challenge,
        'deviceSignature': deviceSignature.toJson(),
      });

  Future<Map<String, dynamic>> _send(String method, String path,
      {Map<String, Object?>? body}) async {
    final req = http.Request(method, _u(path));
    req.headers['Accept'] = 'application/json';
    if (body != null) {
      req.headers['Content-Type'] = 'application/json';
      req.body = jsonEncode(body);
    }
    final http.Response res;
    try {
      res = await http.Response.fromStream(
          await _client.send(req).timeout(timeout));
    } on TimeoutException {
      throw const OfflineException('timeout');
    } on SocketException catch (e) {
      throw OfflineException(e.osError?.message);
    } on HandshakeException {
      throw const OfflineException('TLS handshake failed');
    } on http.ClientException catch (e) {
      throw OfflineException(e.message);
    }
    Map<String, dynamic> json = const {};
    if (res.body.isNotEmpty) {
      try {
        final decoded = jsonDecode(res.body);
        if (decoded is Map<String, dynamic>) json = decoded;
      } on FormatException {
        json = const {};
      }
    }
    if (res.statusCode >= 400) {
      throw V18ApiException(
        res.statusCode,
        json['code']?.toString() ?? 'HTTP_${res.statusCode}',
        json['error']?.toString() ?? 'Request failed',
        reason: json['reason']?.toString(),
      );
    }
    return json;
  }

  void close() => _client.close();
}
