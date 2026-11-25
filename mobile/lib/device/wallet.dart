import 'dart:convert';

import 'package:flutter/services.dart';

class WalletException implements Exception {
  const WalletException(this.code, [this.message]);

  /// cancelled, no_credential, wallet_error, wrong_type, error
  final String code;
  final String? message;
  @override
  String toString() => 'WalletException($code)';
}

/// Android Credential Manager digital credentials (PROTOCOL 4d.3 `mdoc_app`):
/// asks another wallet on this phone for ONLY `age_over_18`.
abstract class DigitalCredentials {
  /// Passes the server's `digital` request to Credential Manager untouched and
  /// returns the wallet's `DigitalCredential` as `{protocol, data}`.
  Future<Map<String, dynamic>> get(Map<String, dynamic> digital);

  /// `android:apk-key-hash:<base64url SHA-256 of the signing certificate>`.
  Future<String?> appOrigin();
}

class AndroidDigitalCredentials implements DigitalCredentials {
  AndroidDigitalCredentials({MethodChannel? channel}) : _ch = channel ?? const MethodChannel('com.v18.app/wallet');
  final MethodChannel _ch;

  @override
  Future<Map<String, dynamic>> get(Map<String, dynamic> digital) async {
    final String? json;
    try {
      json = await _ch.invokeMethod<String>('getDigitalCredential', {'requestJson': jsonEncode(digital)});
    } on PlatformException catch (e) {
      throw WalletException(e.code, e.message);
    } on MissingPluginException {
      throw const WalletException('error', 'Wallet channel missing');
    }
    if (json == null) throw const WalletException('wallet_error', 'Empty answer');
    final decoded = jsonDecode(json);
    if (decoded is! Map<String, dynamic> || decoded['protocol'] is! String || decoded['data'] == null) {
      throw const WalletException('wallet_error', 'Not a digital credential');
    }
    return {'protocol': decoded['protocol'], 'data': decoded['data']};
  }

  @override
  Future<String?> appOrigin() async {
    try {
      return await _ch.invokeMethod<String>('appOrigin');
    } on Object {
      return null;
    }
  }
}
