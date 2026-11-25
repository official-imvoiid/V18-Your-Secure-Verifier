import 'dart:convert';
import 'dart:math';

import 'package:flutter/services.dart';

import '../api/v18_api.dart';
import '../crypto/b64.dart';
import '../crypto/jwk.dart';

/// Prefix of every V18 device key alias in the Android Keystore.
const String deviceKeyAliasPrefix = 'v18_card_';

String newDeviceKeyAlias({Random? random}) {
  final r = random ?? Random.secure();
  final bytes = List<int>.generate(12, (_) => r.nextInt(256));
  return '$deviceKeyAliasPrefix${b64urlEncode(bytes)}';
}

class DeviceKeyException implements Exception {
  const DeviceKeyException(this.code, [this.message]);

  /// cancelled, no_lock, key_invalidated, locked_out, no_key, auth_error,
  /// no_biometric_hardware, error
  final String code;
  final String? message;

  bool get cancelled => code == 'cancelled';

  @override
  String toString() => 'DeviceKeyException($code${message == null ? '' : ': $message'})';
}

/// A device key that was made in secure hardware.
class DeviceKeyInfo {
  DeviceKeyInfo({
    required this.alias,
    required this.publicJwk,
    required this.strongBox,
    required this.secureHardware,
    this.attestation,
  });

  final String alias;

  /// {kty: EC, crv: P-256, x, y}
  final Map<String, dynamic> publicJwk;

  /// Made inside StrongBox (a separate security chip).
  final bool strongBox;

  /// Made inside secure hardware (TEE or StrongBox).
  final bool secureHardware;

  /// Android key attestation chain, DER, leaf first (PROTOCOL 4c.3). Only
  /// when the key was made with an attestation challenge.
  final List<Uint8List>? attestation;

  /// `keyAttestation` as sent to the server: standard base64 DER, leaf first.
  List<String>? get keyAttestation => attestation?.map(base64.encode).toList();

  String get thumbprint => jwkThumbprint(publicJwk);

  /// The JWK sent as `devicePublicKey` (PROTOCOL 3.5).
  Map<String, dynamic> get jwkWithAlg => deviceJwkWithAlg(publicJwk, 'ES256');
}

enum LockStatus { ready, noneEnrolled, noHardware, unavailable }

/// Device keys: EC P-256 in the Android Keystore, each use unlocked by the
/// user (fingerprint, face unlock or screen lock) through BiometricPrompt with
/// a CryptoObject. Signature: ES256, DER encoded.
abstract class DeviceKeyService {
  Future<LockStatus> lockStatus();
  /// Makes a new key. With [attestationChallenge] the Keystore attests it
  /// (the challenge's UTF-8 bytes go into the attestation certificate).
  /// [userAuth] false makes a key that signs without an unlock: only for the
  /// short-lived nullifier request key.
  Future<DeviceKeyInfo> createKey(String alias, {String? attestationChallenge, bool userAuth = true});
  Future<bool> hasKey(String alias);

  /// Signs with a key made with `userAuth: false`.
  Future<DeviceSignature> signNoAuth(String alias, String signingString);

  /// Shows the system unlock prompt, then signs the UTF-8 bytes of
  /// [signingString] with the key.
  Future<DeviceSignature> sign(
    String alias,
    String signingString, {
    required String title,
    required String subtitle,
  });

  Future<void> deleteKey(String alias);

  /// Deletes every V18 device key on this phone.
  Future<void> deleteAllKeys();
}

class AndroidDeviceKeyService implements DeviceKeyService {
  AndroidDeviceKeyService({MethodChannel? channel})
      : _ch = channel ?? const MethodChannel('com.v18.app/device_key');

  final MethodChannel _ch;

  Future<T?> _call<T>(String method, [Map<String, Object?>? args]) async {
    try {
      return await _ch.invokeMethod<T>(method, args);
    } on PlatformException catch (e) {
      throw DeviceKeyException(e.code, e.message);
    } on MissingPluginException {
      throw const DeviceKeyException('error', 'Device key channel missing');
    }
  }

  @override
  Future<LockStatus> lockStatus() async {
    final s = await _call<String>('lockStatus');
    return switch (s) {
      'ready' => LockStatus.ready,
      'none_enrolled' => LockStatus.noneEnrolled,
      'no_hardware' => LockStatus.noHardware,
      _ => LockStatus.unavailable,
    };
  }

  @override
  Future<DeviceKeyInfo> createKey(String alias, {String? attestationChallenge, bool userAuth = true}) async {
    final m = (await _call<Map<Object?, Object?>>('createKey', {
      'alias': alias,
      'userAuth': userAuth,
      if (attestationChallenge != null)
        'attestationChallenge': Uint8List.fromList(utf8.encode(attestationChallenge)),
    }))!;
    final x = m['x']! as Uint8List;
    final y = m['y']! as Uint8List;
    if (x.length != 32 || y.length != 32) {
      throw const DeviceKeyException('error', 'Bad EC point size');
    }
    return DeviceKeyInfo(
      alias: alias,
      publicJwk: {'kty': 'EC', 'crv': 'P-256', 'x': b64urlEncode(x), 'y': b64urlEncode(y)},
      strongBox: m['strongBox'] == true,
      secureHardware: m['secureHardware'] == true,
      attestation: (m['attestation'] as List?)?.map((c) => c as Uint8List).toList(),
    );
  }

  @override
  Future<DeviceSignature> signNoAuth(String alias, String signingString) async {
    final der = await _call<Uint8List>('signNoAuth', {
      'alias': alias,
      'message': Uint8List.fromList(utf8.encode(signingString)),
    });
    if (der == null || der.isEmpty) {
      throw const DeviceKeyException('error', 'Empty signature');
    }
    return DeviceSignature('ES256', b64urlEncode(der));
  }

  @override
  Future<bool> hasKey(String alias) async =>
      (await _call<bool>('hasKey', {'alias': alias})) ?? false;

  @override
  Future<DeviceSignature> sign(String alias, String signingString,
      {required String title, required String subtitle}) async {
    final der = await _call<Uint8List>('sign', {
      'alias': alias,
      'message': Uint8List.fromList(utf8.encode(signingString)),
      'title': title,
      'subtitle': subtitle,
    });
    if (der == null || der.isEmpty) {
      throw const DeviceKeyException('error', 'Empty signature');
    }
    return DeviceSignature('ES256', b64urlEncode(der));
  }

  @override
  Future<void> deleteKey(String alias) => _call<void>('deleteKey', {'alias': alias});

  @override
  Future<void> deleteAllKeys() =>
      _call<void>('deleteAllKeys', {'prefix': deviceKeyAliasPrefix});
}
