import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:pointycastle/asn1.dart' as asn1;
import 'package:pointycastle/export.dart' as pc;
import 'package:v18/aadhaar/anon_aadhaar.dart';
import 'package:v18/aadhaar/artifacts.dart';
import 'package:v18/api/v18_api.dart';
import 'package:dmrtd/dmrtd.dart' show ComProvider;
import 'package:v18/app_state.dart';
import 'package:v18/catalog/catalog.dart';
import 'package:v18/device/wallet.dart';
import 'package:v18/passport/chip_reader.dart';
import 'package:v18/passport/csca.dart';
import 'package:v18/crypto/b64.dart';
import 'package:v18/crypto/jwk.dart';
import 'package:v18/crypto/rfc9474.dart';
import 'package:v18/device/device_key.dart';
import 'package:v18/device/platform_checks.dart';
import 'package:v18/flows/flows.dart';
import 'package:v18/protocol/deep_links.dart';
import 'package:v18/protocol/signing_strings.dart';
import 'package:v18/storage/card_store.dart';

pc.SecureRandom _rng() => pc.FortunaRandom()
  ..seed(pc.KeyParameter(
      Uint8List.fromList(List<int>.generate(32, (_) => Random.secure().nextInt(256)))));

final _p256 = pc.ECDomainParameters('prime256v1');

/// Device keys made with pointycastle (instead of the Android Keystore),
/// signing real ES256 (DER) signatures.
class FakeDeviceKeyService implements DeviceKeyService {
  final Map<String, pc.AsymmetricKeyPair<pc.PublicKey, pc.PrivateKey>> keys = {};
  final List<String> signed = [];
  LockStatus status = LockStatus.ready;

  /// Set to make the next sign() act like the user pressed Cancel.
  bool cancelNext = false;

  /// Aliases made with userAuth: false (the nullifier request key).
  final Set<String> noAuthKeys = {};

  /// Attestation challenges asked for, in order.
  final List<String> attestationChallenges = [];

  @override
  Future<LockStatus> lockStatus() async => status;

  @override
  Future<DeviceKeyInfo> createKey(String alias, {String? attestationChallenge, bool userAuth = true}) async {
    final gen = pc.ECKeyGenerator()
      ..init(pc.ParametersWithRandom(pc.ECKeyGeneratorParameters(_p256), _rng()));
    final pair = gen.generateKeyPair();
    keys[alias] = pair;
    if (!userAuth) noAuthKeys.add(alias);
    final q = (pair.publicKey as pc.ECPublicKey).Q!;
    final x = b64urlEncode(i2osp(q.x!.toBigInteger()!, 32));
    final y = b64urlEncode(i2osp(q.y!.toBigInteger()!, 32));
    if (attestationChallenge != null) attestationChallenges.add(attestationChallenge);
    return DeviceKeyInfo(
      alias: alias,
      publicJwk: {'kty': 'EC', 'crv': 'P-256', 'x': x, 'y': y},
      strongBox: false,
      secureHardware: false,
      // FAKE attestation "chain" for tests: one JSON blob, checked by FakeV18Server.
      attestation: attestationChallenge == null
          ? null
          : [
              Uint8List.fromList(utf8.encode(jsonEncode(
                  {'fake': 'TEST attestation', 'challenge': attestationChallenge, 'x': x, 'y': y})))
            ],
    );
  }

  @override
  Future<DeviceSignature> signNoAuth(String alias, String signingString) async {
    if (!noAuthKeys.contains(alias)) throw const DeviceKeyException('auth_error', 'needs unlock');
    return _sign(alias, signingString);
  }

  @override
  Future<bool> hasKey(String alias) async => keys.containsKey(alias);

  @override
  Future<DeviceSignature> sign(String alias, String signingString,
      {required String title, required String subtitle}) async {
    if (cancelNext) {
      cancelNext = false;
      throw const DeviceKeyException('cancelled');
    }
    return _sign(alias, signingString);
  }

  DeviceSignature _sign(String alias, String signingString) {
    final pair = keys[alias];
    if (pair == null) throw const DeviceKeyException('no_key');
    final signer = pc.ECDSASigner(pc.SHA256Digest(), pc.HMac(pc.SHA256Digest(), 64))
      ..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(pair.privateKey as pc.ECPrivateKey));
    final s = signer.generateSignature(Uint8List.fromList(utf8.encode(signingString)))
        as pc.ECSignature;
    final der = asn1.ASN1Sequence(elements: [asn1.ASN1Integer(s.r), asn1.ASN1Integer(s.s)])
        .encode();
    signed.add(signingString);
    return DeviceSignature('ES256', b64urlEncode(der));
  }

  @override
  Future<void> deleteKey(String alias) async => keys.remove(alias);

  @override
  Future<void> deleteAllKeys() async =>
      keys.removeWhere((k, _) => k.startsWith(deviceKeyAliasPrefix));
}

/// Checks an ES256 DER signature against a public JWK (what the server does).
bool verifyEs256(Map<String, dynamic> jwk, String message, String sigB64) {
  final x = os2ip(b64urlDecode(jwk['x'] as String));
  final y = os2ip(b64urlDecode(jwk['y'] as String));
  final q = _p256.curve.createPoint(x, y);
  final seq = asn1.ASN1Parser(b64urlDecode(sigB64)).nextObject() as asn1.ASN1Sequence;
  final r = (seq.elements![0] as asn1.ASN1Integer).integer!;
  final s = (seq.elements![1] as asn1.ASN1Integer).integer!;
  final v = pc.ECDSASigner(pc.SHA256Digest())
    ..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(pc.ECPublicKey(q, _p256)));
  return v.verifySignature(Uint8List.fromList(utf8.encode(message)), pc.ECSignature(r, s));
}

class FakeCard {
  FakeCard(this.jwk, this.validUntil);
  final Map<String, dynamic> jwk;
  final DateTime validUntil;
  bool active = true;
}

/// An in-memory V18 server that follows PROTOCOL.md section 3 closely
/// enough to test the phone's side, using the RSA test key from
/// test/fixtures/blindrsa_ts_cases.json.
class FakeV18Server {
  FakeV18Server({this.devMode = true, DateTime? now}) : now = now ?? DateTime.now() {
    final jwk = (jsonDecode(File('test/fixtures/blindrsa_ts_cases.json').readAsStringSync())
        as Map<String, dynamic>)['jwk'] as Map<String, dynamic>;
    n = os2ip(b64urlDecode(jwk['n'] as String));
    e = os2ip(b64urlDecode(jwk['e'] as String));
    d = os2ip(b64urlDecode(jwk['d'] as String));
  }

  bool devMode;
  DateTime now;
  late final BigInt n, e, d;
  final String kid = 'v18-age18-20261109';

  final Set<String> challenges = {};
  final Map<String, FakeCard> cards = {};
  final Map<String, Map<String, dynamic>> sessions = {};
  final Map<String, String> submittedTickets = {};
  final List<String> connected = [];
  final List<String> cancelled = [];
  final Map<String, String> approvedLinks = {};
  final List<String> requests = [];
  bool offline = false;
  int _c = 0;

  /// Bodies of POST /v1/card/issue, for checks.
  final List<Map<String, dynamic>> issued = [];

  /// Nullifier per card (for the cap).
  final Map<String, String> nullifierOf = {};
  int maxCardsPerId = 3;

  /// Blinded messages the fake nullifier service signed.
  final List<String> nullifierRequests = [];

  /// Methods reported "ready" in GET /v1/health (the catalog is filtered by them).
  Map<String, String> methods = {
    'test_dev': 'ready',
    'anon_aadhaar': 'ready',
    'emrtd_attested': 'ready',
    'mdoc_app': 'ready',
  };

  /// Catalog countries (PROTOCOL 4d.2), before filtering.
  List<Map<String, dynamic>> catalogCountries = [
    {
      'code': 'IN', 'name': 'India', 'region': 'asia',
      'methods': [
        {'method': 'anon_aadhaar', 'label': 'Aadhaar QR', 'documents': ['Aadhaar letter', 'e-Aadhaar PDF'],
         'needs': ['camera'], 'privacy': 'zero_knowledge', 'platforms': ['android', 'windows']},
        {'method': 'emrtd_attested', 'label': 'Passport (chip)', 'documents': ['Indian e-passport'],
         'docTypes': ['P'], 'needs': ['nfc'], 'privacy': 'on_device', 'platforms': ['android']},
      ]
    },
    {
      'code': 'DE', 'name': 'Germany', 'region': 'europe',
      'methods': [
        {'method': 'emrtd_attested', 'label': 'Passport (chip)', 'documents': ['German passport'],
         'docTypes': ['P'], 'needs': ['nfc'], 'privacy': 'on_device', 'platforms': ['android']},
        {'method': 'emrtd_attested', 'label': 'ID card (chip)', 'documents': ['Personalausweis'],
         'docTypes': ['I'], 'needs': ['nfc'], 'privacy': 'on_device', 'platforms': ['android']},
        {'method': 'face_estimate', 'label': 'Face estimate', 'documents': [],
         'needs': ['camera'], 'privacy': 'estimate', 'platforms': ['android']},
      ]
    },
    {
      'code': 'SG', 'name': 'Singapore', 'region': 'asia',
      'methods': [
        {'method': 'connector:singpass', 'label': 'Singpass (Myinfo)', 'documents': ['Singpass app'],
         'needs': [], 'privacy': 'login', 'platforms': ['android', 'windows']},
      ]
    },
  ];

  /// Fake artifact files (name -> bytes).
  Map<String, Uint8List> artifactFiles = {
    'vkey.json': Uint8List.fromList(utf8.encode('{"protocol":"groth16"}')),
    'aadhaar-verifier.wasm': Uint8List.fromList(List<int>.generate(3000, (i) => i % 251)),
    'circuit_final.zkey': Uint8List.fromList(List<int>.generate(5000, (i) => (i * 7) % 253)),
  };

  /// Connector sessions: state -> {status, card?}.
  final Map<String, Map<String, dynamic>> connectSessions = {};

  /// Checks a FAKE attestation chain made by FakeDeviceKeyService.
  String? _attestationProblem(Object? chain, String challenge, Map<String, dynamic> jwk) {
    if (chain is! List || chain.isEmpty) return 'no_attestation';
    final Map<String, dynamic> leaf;
    try {
      leaf = jsonDecode(utf8.decode(base64.decode(chain.first as String))) as Map<String, dynamic>;
    } on Object {
      return 'malformed';
    }
    if (leaf['challenge'] != challenge) return 'challenge_mismatch';
    if (leaf['x'] != jwk['x'] || leaf['y'] != jwk['y']) return 'key_mismatch';
    return null;
  }

  /// Adds a website pairing session.
  void addSession(String id, {required String origin, required String challenge}) =>
      sessions[id] = {'status': 'waiting', 'origin': origin, 'challenge': challenge};

  http.Client client() => MockClient(_handle);

  http.Response _json(int status, Object body) => http.Response(jsonEncode(body), status,
      headers: {'content-type': 'application/json'});
  http.Response _err(int status, String code, String msg) =>
      _json(status, {'error': msg, 'code': code});

  bool _takeChallenge(Object? c) => c is String && challenges.remove(c);

  Future<http.Response> _handle(http.Request req) async {
    if (offline) throw http.ClientException('Connection refused');
    final path = req.url.path;
    requests.add('${req.method} $path');
    final body = req.body.isEmpty ? <String, dynamic>{} : jsonDecode(req.body) as Map<String, dynamic>;
    final seg = path.split('/').where((s) => s.isNotEmpty).toList(); // [v1, ...]

    if (req.method == 'GET' && path == '/v1/health') {
      return _json(200, {
        'status': 'ok',
        'devMode': devMode,
        'methods': methods,
        'aadhaarNullifierSeed': '180018001800180018',
        'nullifierKeyId': 'v18-nullifier-1',
      });
    }
    if (req.method == 'GET' && path == '/v1/catalog') {
      final country = req.url.queryParameters['country']?.toUpperCase();
      final platform = req.url.queryParameters['platform'];
      final out = <Map<String, dynamic>>[];
      for (final c in catalogCountries) {
        if (country != null && c['code'] != country) continue;
        final ms = (c['methods'] as List).cast<Map<String, dynamic>>().where((m) {
          final id = m['method'] as String;
          if (methods[id] != 'ready') return false;
          if (platform != null && !(m['platforms'] as List).contains(platform)) return false;
          return true;
        }).toList();
        if (ms.isNotEmpty) out.add({...c, 'methods': ms});
      }
      return _json(200, {'version': 1, 'countries': out});
    }
    if (req.method == 'GET' && path == '/v1/artifacts/manifest') {
      return _json(200, [
        for (final e in artifactFiles.entries)
          {
            'name': e.key,
            'sha256': bytesToHex(pc.SHA256Digest().process(e.value)),
            'bytes': e.value.length,
            'url': 'http://localhost:8080/v1/artifacts/${e.key}',
            'role': switch (e.key) {
              'vkey.json' => 'verification_key',
              'aadhaar-verifier.wasm' => 'witness_wasm',
              _ => 'proving_key',
            },
          }
      ]);
    }
    if (req.method == 'GET' && seg.length == 3 && seg[1] == 'artifacts') {
      final f = artifactFiles[seg[2]];
      if (f == null) return _err(404, 'ARTIFACT_NOT_FOUND', 'no file');
      return http.Response.bytes(f, 200);
    }
    if (req.method == 'GET' && path == '/v1/keys/nullifier') {
      return _json(200, {
        'keys': [
          {
            'kty': 'RSA', 'kid': 'v18-nullifier-1', 'use': 'sig',
            'alg': 'RSABSSA-SHA384-PSSZERO-Deterministic',
            'n': b64urlEncode(i2osp(n, 256)), 'e': b64urlEncode(i2osp(e, 3)),
          }
        ]
      });
    }
    if (req.method == 'POST' && path == '/v1/nullifier/blind-sign') {
      final ch = body['challenge'];
      if (!_takeChallenge(ch)) return _err(401, 'CHALLENGE_INVALID', 'challenge');
      final jwk = (body['devicePublicKey'] as Map).cast<String, dynamic>();
      final tp = jwkThumbprint(jwk);
      final blinded = body['blindedMessage'] as String;
      final sig = (body['deviceSignature'] as Map)['sig'] as String;
      if (!verifyEs256(jwk, nullifierSigningString(challenge: ch as String, deviceKeyThumbprint: tp, blindedMessage: blinded), sig)) {
        return _err(401, 'BAD_DEVICE_SIGNATURE', 'sig');
      }
      final problem = _attestationProblem(body['keyAttestation'], ch, jwk);
      if (problem != null) return _json(400, {'error': 'attestation', 'code': 'ATTESTATION_INVALID', 'reason': problem});
      nullifierRequests.add(blinded);
      final z = os2ip(b64urlDecode(blinded));
      return _json(200, {
        'blindSignature': b64urlEncode(i2osp(z.modPow(d, n), 256)),
        'keyId': 'v18-nullifier-1',
        'algorithm': 'RSABSSA-SHA384-PSSZERO-Deterministic',
      });
    }
    if (req.method == 'POST' && path == '/v1/wallet/app-request') {
      final ch = body['challenge'];
      if (ch is! String || !challenges.contains(ch)) return _err(401, 'CHALLENGE_INVALID', 'challenge');
      return _json(200, {
        'digital': {
          'requests': [
            {'protocol': 'openid4vp-v1-unsigned', 'data': {'nonce': ch, 'response_mode': 'dc_api.jwt'}}
          ]
        },
        'expiresAt': now.add(const Duration(minutes: 5)).toIso8601String(),
      });
    }
    if (req.method == 'POST' && seg.length == 4 && seg[1] == 'connect' && seg[3] == 'start') {
      final id = seg[2];
      if (methods['connector:$id'] != 'ready') return _err(404, 'CONNECTOR_NOT_ENABLED', 'off');
      final ch = body['challenge'];
      if (!_takeChallenge(ch)) return _err(401, 'CHALLENGE_INVALID', 'challenge');
      final jwk = (body['devicePublicKey'] as Map).cast<String, dynamic>();
      final tp = jwkThumbprint(jwk);
      if (!verifyEs256(jwk, cardIssueSigningString(challenge: ch as String, deviceKeyThumbprint: tp),
          (body['deviceSignature'] as Map)['sig'] as String)) {
        return _err(401, 'BAD_DEVICE_SIGNATURE', 'sig');
      }
      final state = 'st${_c++}'.padRight(43, 'x');
      connectSessions[state] = {'status': 'waiting', 'jwk': jwk};
      return _json(201, {'authUrl': 'https://provider.test/auth?state=$state', 'state': state, 'expiresIn': 600});
    }
    if (req.method == 'GET' && seg.length == 4 && seg[1] == 'connect' && seg[2] == 'session') {
      final st = connectSessions[seg[3]];
      if (st == null) return _json(404, {'status': 'expired', 'code': 'NOT_FOUND', 'error': 'gone'});
      final out = Map<String, dynamic>.from(st)..remove('jwk');
      if (st['card'] != null) st.remove('card');
      return _json(200, out);
    }
    if (req.method == 'POST' && path == '/v1/challenge') {
      final c = 'c${_c++}'.padRight(64, '0');
      challenges.add(c);
      return _json(200, {'challenge': c, 'expiresAt': now.add(const Duration(minutes: 5)).toIso8601String()});
    }
    if (req.method == 'GET' && path == '/v1/keys') {
      final t = now.millisecondsSinceEpoch ~/ 1000;
      return _json(200, {
        'keys': [
          {
            'kid': kid,
            'kty': 'RSA',
            'n': b64urlEncode(i2osp(n, 256)),
            'e': b64urlEncode(i2osp(e, 3)),
            'use': 'sig',
            'alg': 'RSABSSA-SHA384-PSS-Randomized',
            'v18_min_age': 18,
            'nbf': t - 3600,
            'exp': t + 6 * 86400,
          }
        ]
      });
    }
    if (req.method == 'POST' && path == '/v1/card/issue') {
      if (!_takeChallenge(body['challenge'])) return _err(401, 'CHALLENGE_INVALID', 'challenge');
      final method = body['method'];
      if (method == 'passport_zk') return _err(501, 'METHOD_NOT_READY', 'not ready');
      if (method == 'test_dev' && !devMode) return _err(501, 'METHOD_DISABLED', 'disabled');
      final jwk = (body['devicePublicKey'] as Map).cast<String, dynamic>();
      if (jwk['alg'] != 'ES256') return _err(400, 'BAD_DEVICE_KEY', 'alg');
      final tp = jwkThumbprint(jwk);
      final sig = (body['deviceSignature'] as Map)['sig'] as String;
      if (!verifyEs256(jwk, cardIssueSigningString(challenge: body['challenge'] as String, deviceKeyThumbprint: tp), sig)) {
        return _err(401, 'BAD_DEVICE_SIGNATURE', 'sig');
      }
      final proof = (body['proof'] as Map).cast<String, dynamic>();
      issued.add(body);
      String? nullifier;
      if (method == 'test_dev') {
        final birth = DateTime.parse(proof['birthDate'] as String);
        if (now.difference(birth).inDays < 18 * 365.25) return _err(403, 'UNDER_AGE', 'under 18');
      } else if (method == 'emrtd_attested' || method == 'passport_attested') {
        final problem = _attestationProblem(body['keyAttestation'], body['challenge'] as String, jwk);
        if (problem != null) {
          return _json(400, {'error': 'attestation', 'code': 'ATTESTATION_INVALID', 'reason': problem});
        }
        const allowed = {'over18', 'docExpiry', 'issuingState', 'docType', 'passiveAuth', 'chipAuth', 'nullifier', 'nullifierKeyId'};
        if (proof.keys.any((k) => !allowed.contains(k))) {
          return _json(400, {'error': 'field', 'code': 'PROOF_INVALID', 'reason': 'unexpected_field'});
        }
        if (proof['over18'] != true || proof['passiveAuth'] != 'ok') return _err(400, 'PROOF_INVALID', 'bad');
        nullifier = proof['nullifier'] as String;
      } else if (method == 'anon_aadhaar') {
        final p = (proof['proof'] as Map).cast<String, dynamic>();
        if (p['ageAbove18'] != '1') return _err(403, 'UNDER_AGE', 'under 18');
        nullifier = p['nullifier'] as String;
      } else if (method == 'mdoc_app') {
        if (proof['protocol'] != 'openid4vp-v1-unsigned') return _err(400, 'WALLET_INVALID', 'protocol');
        nullifier = 'wallet';
      }
      if (nullifier != null &&
          nullifierOf.entries.where((e) => e.value == nullifier && cards[e.key]?.active == true).length >=
              maxCardsPerId) {
        return _err(409, 'NULLIFIER_OVERUSED', 'too many');
      }
      final id = 'card_${b64urlEncode(List<int>.generate(16, (i) => i + _c))}';
      if (nullifier != null) nullifierOf[id] = nullifier;
      final until = now.add(const Duration(days: 30));
      cards[id] = FakeCard({'kty': 'EC', 'crv': 'P-256', 'x': jwk['x'], 'y': jwk['y']}, until);
      return _json(201, {
        'cardId': id,
        'method': method,
        'assuranceLevel': method == 'test_dev' ? 'test' : 'substantial',
        'minAgeCertified': 18,
        'validUntil': until.toUtc().toIso8601String(),
      });
    }
    if (req.method == 'POST' && path == '/v1/ticket/blind-sign') {
      if (!_takeChallenge(body['challenge'])) return _err(400, 'BAD_CHALLENGE', 'challenge');
      final card = cards[body['cardId']];
      if (card == null || !card.active) return _err(401, 'CARD_REQUIRED', 'card');
      final s = signingStringForTicket(body);
      if (!verifyEs256(card.jwk, s, (body['deviceSignature'] as Map)['sig'] as String)) {
        return _err(401, 'CARD_REQUIRED', 'sig');
      }
      if (body['keyId'] != kid) return _err(400, 'BAD_KEY', 'key');
      final z = os2ip(b64urlDecode(body['blindedMessage'] as String));
      final sig = i2osp(z.modPow(d, n), 256);
      return _json(200, {'blindSignature': b64urlEncode(sig), 'keyId': kid, 'algorithm': 'RSABSSA-SHA384-PSS-Randomized'});
    }
    if (seg.length >= 3 && seg[1] == 'pairing') {
      final id = seg[2];
      final s = sessions[id];
      if (s == null) return _err(404, 'NOT_FOUND', 'session not found');
      if (req.method == 'GET' && seg.length == 3) return _json(200, s);
      switch (seg.length == 4 ? seg[3] : '') {
        case 'connect':
          connected.add(id);
          s['status'] = 'connected';
          return _json(200, {'ok': true});
        case 'submit':
          if (submittedTickets.containsKey(id)) return _err(409, 'ALREADY', 'once only');
          submittedTickets[id] = body['ticket'] as String;
          return _json(200, {'ok': true});
        case 'cancel':
          cancelled.add(id);
          return _json(200, {'ok': true});
      }
    }
    if (seg.length == 5 && seg[1] == 'card' && seg[2] == 'link' && seg[4] == 'approve' && req.method == 'POST') {
      if (!_takeChallenge(body['challenge'])) return _err(400, 'BAD_CHALLENGE', 'challenge');
      final card = cards[body['cardId']];
      if (card == null) return _err(401, 'CARD_REQUIRED', 'card');
      final s = linkApproveSigningString(cardId: body['cardId'] as String, challenge: body['challenge'] as String, linkId: seg[3]);
      if (!verifyEs256(card.jwk, s, (body['deviceSignature'] as Map)['sig'] as String)) {
        return _err(401, 'BAD_DEVICE_SIGNATURE', 'sig');
      }
      approvedLinks[seg[3]] = body['cardId'] as String;
      return _json(200, {'status': 'approved'});
    }
    if (seg.length == 3 && seg[1] == 'card' && req.method == 'DELETE') {
      if (!_takeChallenge(body['challenge'])) return _err(400, 'BAD_CHALLENGE', 'challenge');
      final card = cards[seg[2]];
      if (card == null) return _err(404, 'CARD_NOT_FOUND', 'card');
      final s = cardDeleteSigningString(cardId: seg[2], challenge: body['challenge'] as String);
      if (!verifyEs256(card.jwk, s, (body['deviceSignature'] as Map)['sig'] as String)) {
        return _err(401, 'BAD_DEVICE_SIGNATURE', 'sig');
      }
      card.active = false;
      return _json(200, {'status': 'revoked'});
    }
    return _err(404, 'NOT_FOUND', 'no route');
  }

  String signingStringForTicket(Map<String, dynamic> b) => ticketRequestSigningString(
        cardId: b['cardId'] as String,
        challenge: b['challenge'] as String,
        keyId: b['keyId'] as String,
        blindedMessage: b['blindedMessage'] as String,
      );

  /// What a website's verify library does (PROTOCOL 3.7, signature part).
  bool verifyTicketSignature(String ticket) {
    final parts = ticket.split('.');
    final prepared = b64urlDecode(parts[1]);
    final sig = b64urlDecode(parts[2]);
    return BlindRsaClient(BlindRsaVariant.sha384PssRandomized)
        .verify(BlindRsaPublicKey(n, e), prepared, sig);
  }
}

const testServer = 'http://localhost:8080';

V18Services fakeServices(FakeV18Server server, FakeDeviceKeyService keys, {PlatformChecks? checks}) =>
    V18Services(
      keys: keys,
      checks: checks ?? PlatformChecks(),
      apiFor: (s) => V18Api(s, client: server.client()),
      now: () => server.now,
    );

/// FAKE prover for widget tests: no proof maths, it only returns the public
/// values a real proof would have. The real prover is tested on the PC
/// (test/aadhaar/prover_host_test.dart) and on the emulator (integration_test/).
class FakeAnonAadhaarProver implements AnonAadhaarProver {
  int calls = 0;
  AadhaarArtifactPaths? lastPaths;

  @override
  bool get available => true;

  @override
  Future<AnonAadhaarProof> prove(AnonAadhaarInputs inputs, AadhaarArtifactPaths files,
      {void Function(ProverStage stage)? onStage}) async {
    calls++;
    lastPaths = files;
    final c = inputs.circuitInputs;
    onStage?.call(ProverStage.witness);
    onStage?.call(ProverStage.proving);
    final named = {
      'pubkeyHash': '15134874015316324267425466444584014077184337590635665158241104437045239495873',
      'nullifier': '42',
      'timestamp': '1700000000',
      'ageAbove18': '1',
      'gender': '0',
      'pincode': '0',
      'state': '0',
      'nullifierSeed': c['nullifierSeed'] as String,
      'signalHash': c['signalHash'] as String,
    };
    inputs.wipe();
    return AnonAadhaarProof.fromProver({
      'proof': {'pi_a': ['1', '2', '1'], 'pi_b': [['1', '2'], ['3', '4'], ['1', '0']], 'pi_c': ['5', '6', '1'],
        'protocol': 'groth16', 'curve': 'bn128'},
      'named': named,
      'timingsMs': {'total': 1234},
    });
  }
}

/// FAKE wallet app for widget tests (Android Credential Manager is not there).
class FakeWallet implements DigitalCredentials {
  Map<String, dynamic>? lastRequest;
  String? failWith;

  @override
  Future<Map<String, dynamic>> get(Map<String, dynamic> digital) async {
    lastRequest = digital;
    if (failWith != null) throw WalletException(failWith!);
    return {'protocol': 'openid4vp-v1-unsigned', 'data': {'response': 'FAKE encrypted answer'}};
  }

  @override
  Future<String?> appOrigin() async => 'android:apk-key-hash:FAKE';
}

const AppCapabilities allCaps =
    AppCapabilities(aadhaarProver: true, nfc: true, digitalCredentials: true, customTabs: true);

/// The V18 TEST CSCA from test/fixtures/emrtd (made by tool/make_emrtd_fixtures.py).
CscaTrust testCscaTrust() =>
    CscaTrust([X509.fromBytes(File('test/fixtures/emrtd/test_csca.der').readAsBytesSync())]);

AppState fakeAppState(FakeV18Server server, FakeDeviceKeyService keys,
    {MemoryKeyValueStore? kv,
    PlatformChecks? checks,
    AnonAadhaarProver? prover,
    AppCapabilities capabilities = allCaps,
    ComProvider Function()? chip,
    FakeWallet? wallet}) =>
    AppState(
      store: CardStore(kv ?? MemoryKeyValueStore()),
      services: fakeServices(server, keys, checks: checks),
      allowlist: ServerAllowlist.forBuild(debug: true),
      prover: prover ?? FakeAnonAadhaarProver(),
      artifacts: ArtifactStore(
          dir: () async => Directory.systemTemp.createTempSync('v18_artifacts'),
          client: server.client()),
      capabilities: capabilities,
      chipReaderFactory: chip == null
          ? null
          : (app) => ChipReader(
              provider: chip, trust: () async => testCscaTrust(), nfcEnabled: () async => true),
      wallet: wallet ?? FakeWallet(),
    );
