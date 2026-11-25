import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// The age card as stored on the phone. PROTOCOL 3.10 allows ONLY: card ID,
/// method, validUntil, the device key's alias and the server URL. Nothing
/// about the person is stored.
class AgeCard {
  const AgeCard({
    required this.cardId,
    required this.method,
    required this.validUntil,
    required this.keyAlias,
    required this.server,
  });

  factory AgeCard.fromJson(Map<String, dynamic> j) => AgeCard(
        cardId: j['cardId'] as String,
        method: j['method'] as String,
        validUntil: DateTime.parse(j['validUntil'] as String),
        keyAlias: j['keyAlias'] as String,
        server: j['server'] as String,
      );

  final String cardId;
  final String method;
  final DateTime validUntil;
  final String keyAlias;
  final String server;

  /// Every card V18 issues today certifies 18+ (PROTOCOL 3.5).
  int get minAgeCertified => 18;

  bool isExpired(DateTime now) => !now.isBefore(validUntil);

  Map<String, String> toJson() => {
        'cardId': cardId,
        'method': method,
        'validUntil': validUntil.toUtc().toIso8601String(),
        'keyAlias': keyAlias,
        'server': server,
      };

  /// The exact set of stored field names, checked by a unit test.
  static const storedFields = {'cardId', 'method', 'validUntil', 'keyAlias', 'server'};
}

/// App settings (also allowed by PROTOCOL 3.10).
class AppSettings {
  const AppSettings({
    this.onboarded = false,
    this.sharedDevice = false,
    this.server,
  });

  factory AppSettings.fromJson(Map<String, dynamic> j) => AppSettings(
        onboarded: j['onboarded'] == true,
        sharedDevice: j['sharedDevice'] == true,
        server: j['server'] as String?,
      );

  final bool onboarded;
  final bool sharedDevice;

  /// Chosen server (from the allowlist). Null means the build default.
  final String? server;

  AppSettings copyWith({bool? onboarded, bool? sharedDevice, String? server}) =>
      AppSettings(
        onboarded: onboarded ?? this.onboarded,
        sharedDevice: sharedDevice ?? this.sharedDevice,
        server: server ?? this.server,
      );

  Map<String, Object?> toJson() =>
      {'onboarded': onboarded, 'sharedDevice': sharedDevice, 'server': server};
}

/// Small key-value store. Real app: encrypted (Keystore-backed AES-GCM).
abstract class KeyValueStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// Encrypted with a key wrapped by the Android Keystore (RSA-OAEP key
/// wrapping, AES-GCM data: flutter_secure_storage's standard mode). No unlock
/// prompt is needed to read it: the stored fields are not secret (PROTOCOL
/// 3.10), and every card USE is still locked by the device key's own unlock.
/// (AES key wrapping would switch the library to its biometric mode, which
/// asked for an unlock every time the app started: found on the emulator.)
class SecureKeyValueStore implements KeyValueStore {
  SecureKeyValueStore()
      : _s = const FlutterSecureStorage(
          aOptions: AndroidOptions(
            storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
            storageNamespace: 'v18',
          ),
        );

  final FlutterSecureStorage _s;

  @override
  Future<String?> read(String key) => _s.read(key: key);
  @override
  Future<void> write(String key, String value) => _s.write(key: key, value: value);
  @override
  Future<void> delete(String key) => _s.delete(key: key);
}

class MemoryKeyValueStore implements KeyValueStore {
  final Map<String, String> data = {};
  @override
  Future<String?> read(String key) async => data[key];
  @override
  Future<void> write(String key, String value) async => data[key] = value;
  @override
  Future<void> delete(String key) async => data.remove(key);
}

class CardStore {
  CardStore(this._kv);
  final KeyValueStore _kv;

  static const _cardKey = 'card';
  static const _settingsKey = 'settings';

  Future<AgeCard?> loadCard() async {
    final s = await _kv.read(_cardKey);
    if (s == null) return null;
    try {
      return AgeCard.fromJson(jsonDecode(s) as Map<String, dynamic>);
    } on Object {
      await _kv.delete(_cardKey);
      return null;
    }
  }

  Future<void> saveCard(AgeCard card) => _kv.write(_cardKey, jsonEncode(card.toJson()));

  Future<void> deleteCard() => _kv.delete(_cardKey);

  Future<AppSettings> loadSettings() async {
    final s = await _kv.read(_settingsKey);
    if (s == null) return const AppSettings();
    try {
      return AppSettings.fromJson(jsonDecode(s) as Map<String, dynamic>);
    } on Object {
      return const AppSettings();
    }
  }

  Future<void> saveSettings(AppSettings settings) =>
      _kv.write(_settingsKey, jsonEncode(settings.toJson()));
}
