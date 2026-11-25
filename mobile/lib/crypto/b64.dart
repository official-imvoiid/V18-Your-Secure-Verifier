import 'dart:math';
import 'dart:convert';
import 'dart:typed_data';

/// base64url without padding, as PROTOCOL.md requires for every binary value.
String b64urlEncode(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// Decodes base64url with or without padding. Also accepts standard base64
/// characters, because some servers send them.
Uint8List b64urlDecode(String text) {
  var s = text.trim().replaceAll('+', '-').replaceAll('/', '_');
  s = s.replaceAll('=', '');
  final pad = (4 - s.length % 4) % 4;
  if (pad == 3) {
    throw const FormatException('Invalid base64url length');
  }
  return Uint8List.fromList(base64Url.decode(s + '=' * pad));
}

Uint8List hexToBytes(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s'), '');
  if (clean.length.isOdd) {
    throw const FormatException('Odd hex length');
  }
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String bytesToHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Constant-time-ish byte comparison (length leak only).
bool bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// [n] bytes from the platform's secure random generator.
Uint8List randomBytes(int n, [Random? random]) {
  final r = random ?? Random.secure();
  return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
}
