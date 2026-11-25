import 'dart:convert';
import 'dart:io' show ZLibCodec, GZipCodec;
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'uidai_keys.dart';

class AadhaarQrException implements Exception {
  const AadhaarQrException(this.message);

  /// Plain-English message, safe to show.
  final String message;

  @override
  String toString() => 'AadhaarQrException($message)';
}

/// A decoded Aadhaar Secure QR (UIDAI "Secure QR code" format, V2 and later).
///
/// PRIVACY: this object holds personal data (name, date of birth, photo...)
/// in memory only, for as long as the proof takes. Nothing here is logged,
/// saved or sent. Call [wipe] as soon as the proof inputs are made.
class AadhaarSecureQr {
  AadhaarSecureQr._(this._signedData, this._signature, this._fields);

  /// Decodes the QR text: a big decimal number -> bytes -> zlib/gzip inflate
  /// -> fields split by 0xFF, with the last 256 bytes being the RSA signature.
  /// This follows @anon-aadhaar/core generateArgs().
  factory AadhaarSecureQr.decode(String qrText) {
    final text = qrText.trim();
    if (text.isEmpty ||
        text.length > 12000 ||
        !RegExp(r'^[0-9]+$').hasMatch(text)) {
      throw const AadhaarQrException(
          "This isn't an Aadhaar Secure QR. Use the big QR on the Aadhaar letter, card or e-Aadhaar PDF.");
    }
    final compressed = _bigIntToBytes(BigInt.parse(text));
    final Uint8List raw;
    try {
      raw = _inflate(compressed);
    } on Object {
      throw const AadhaarQrException(
          "This QR couldn't be read as an Aadhaar Secure QR.");
    }
    if (raw.length < 256 + 32) {
      throw const AadhaarQrException('This QR is too short to be an Aadhaar Secure QR.');
    }
    final signed = Uint8List.sublistView(raw, 0, raw.length - 256);
    final signature = Uint8List.sublistView(raw, raw.length - 256);
    final fields = <Uint8List>[];
    var start = 0;
    for (var i = 0; i < signed.length && fields.length < 18; i++) {
      if (signed[i] == 0xFF) {
        fields.add(Uint8List.sublistView(signed, start, i));
        start = i + 1;
      }
    }
    if (fields.length < 5) {
      throw const AadhaarQrException("This QR doesn't have the Aadhaar fields.");
    }
    return AadhaarSecureQr._(
        Uint8List.fromList(signed), Uint8List.fromList(signature), fields);
  }

  Uint8List _signedData;
  Uint8List _signature;
  List<Uint8List> _fields;

  /// The part of the QR covered by UIDAI's signature.
  Uint8List get signedData => _signedData;

  /// UIDAI's RSA-2048 signature (SHA-256, PKCS#1 v1.5).
  Uint8List get signature => _signature;

  /// "V2", "V3"... or null for the old format without a version field.
  String? get version {
    final v = ascii.decode(_fields[0], allowInvalid: true);
    return RegExp(r'^V\d$').hasMatch(v) ? v : null;
  }

  int get _offset => version == null ? 0 : 1;

  /// Anon Aadhaar's circuit reads the V2 layout.
  bool get isV2Layout => version == 'V2';

  String _field(int index) =>
      latin1.decode(_fields[_offset + index], allowInvalid: true);

  /// Date of birth as written in the QR (DD-MM-YYYY, YYYY-MM-DD or YYYY).
  /// Used only to tell the user early that they are under 18.
  String get _dobText => _field(3);

  /// Checks UIDAI's signature on this phone. Returns the key that matched,
  /// or null if no trusted key matches (fake or changed QR).
  AadhaarSigningKey? verifySeal(List<AadhaarSigningKey> trustedKeys) {
    for (final key in trustedKeys) {
      final signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201');
      signer.init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(key.rsaKey));
      try {
        if (signer.verifySignature(_signedData, pc.RSASignature(_signature))) {
          return key;
        }
      } on Object {
        // Try the next key.
      }
    }
    return null;
  }

  /// Age in whole years on [today], from the date of birth in the QR.
  /// If only the year is known, it assumes the latest possible birthday
  /// (31 December), so nobody under 18 is counted as 18.
  int ageOn(DateTime today) {
    final dob = _parseDob(_dobText);
    if (dob == null) {
      throw const AadhaarQrException("The date of birth in this QR couldn't be read.");
    }
    var age = today.year - dob.year;
    if (today.month < dob.month ||
        (today.month == dob.month && today.day < dob.day)) {
      age--;
    }
    return age;
  }

  /// Overwrites the personal data in memory. Best effort: Dart may have made
  /// copies we cannot reach, but this drops our own references.
  void wipe() {
    _signedData.fillRange(0, _signedData.length, 0);
    _signature.fillRange(0, _signature.length, 0);
    for (final f in _fields) {
      f.fillRange(0, f.length, 0);
    }
    _signedData = Uint8List(0);
    _signature = Uint8List(0);
    _fields = const [];
  }

  static DateTime? _parseDob(String s) {
    final t = s.trim();
    var m = RegExp(r'^(\d{2})[-/](\d{2})[-/](\d{4})$').firstMatch(t);
    if (m != null) {
      return DateTime(int.parse(m[3]!), int.parse(m[2]!), int.parse(m[1]!));
    }
    m = RegExp(r'^(\d{4})[-/](\d{2})[-/](\d{2})$').firstMatch(t);
    if (m != null) {
      return DateTime(int.parse(m[1]!), int.parse(m[2]!), int.parse(m[3]!));
    }
    m = RegExp(r'^(\d{4})$').firstMatch(t);
    if (m != null) return DateTime(int.parse(m[1]!), 12, 31);
    return null;
  }

  static Uint8List _bigIntToBytes(BigInt v) {
    final len = (v.bitLength + 7) ~/ 8;
    final out = Uint8List(len == 0 ? 1 : len);
    var x = v;
    for (var i = out.length - 1; i >= 0; i--) {
      out[i] = (x & BigInt.from(0xFF)).toInt();
      x = x >> 8;
    }
    return out;
  }

  static Uint8List _inflate(Uint8List data) {
    if (data.length > 2 && data[0] == 0x1F && data[1] == 0x8B) {
      return Uint8List.fromList(GZipCodec().decode(data));
    }
    return Uint8List.fromList(ZLibCodec().decode(data));
  }
}
