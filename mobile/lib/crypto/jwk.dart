import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'b64.dart';

/// RFC 7638 JWK thumbprint (SHA-256, base64url) of a public key JWK.
///
/// Only the required members are hashed, in lexicographic order, with no
/// whitespace: EC -> crv, kty, x, y. RSA -> e, kty, n.
String jwkThumbprint(Map<String, dynamic> jwk) {
  final kty = jwk['kty'];
  final String canonical;
  if (kty == 'EC') {
    canonical = '{"crv":${jsonEncode(jwk['crv'])},"kty":"EC",'
        '"x":${jsonEncode(jwk['x'])},"y":${jsonEncode(jwk['y'])}}';
  } else if (kty == 'RSA') {
    canonical = '{"e":${jsonEncode(jwk['e'])},"kty":"RSA",'
        '"n":${jsonEncode(jwk['n'])}}';
  } else {
    throw ArgumentError('Unsupported JWK kty: $kty');
  }
  final digest =
      pc.SHA256Digest().process(Uint8List.fromList(utf8.encode(canonical)));
  return b64urlEncode(digest);
}

/// The device public key JWK that is sent to the server (PROTOCOL 3.5):
/// the key members plus "alg".
Map<String, dynamic> deviceJwkWithAlg(Map<String, dynamic> jwk, String alg) =>
    {...jwk, 'alg': alg};
