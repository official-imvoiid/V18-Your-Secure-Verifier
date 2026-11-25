import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import '../crypto/b64.dart';
import 'artifacts.dart';
import 'secure_qr.dart';

/// BN254 scalar field size used by Anon Aadhaar's Circom circuit.
final BigInt circomFieldP = BigInt.parse(
    '21888242871839275222246405745257275088548364400416034343698204186575808495617');

/// Dev default nullifier seed of the V18 server (server/src/config.ts).
/// Used only when the server is in dev mode and does not send its own seed.
const String devAadhaarNullifierSeed = '180018001800180018';

/// Signal for the Anon Aadhaar proof (PROTOCOL 3.5):
/// `challenge + "|" + deviceKeyThumbprint`.
String anonAadhaarSignalString(String challenge, String deviceKeyThumbprint) =>
    '$challenge|$deviceKeyThumbprint';

/// @anon-aadhaar/core's `hash()` needs a number of at most 32 bytes, and the
/// protocol's signal string is longer than that and not a number. Closest
/// reading (adopted by the server):
/// signal = "0x" + hex(SHA-256(UTF-8(signal string))).
String anonAadhaarSignal(String challenge, String deviceKeyThumbprint) {
  final digest = pc.SHA256Digest().process(Uint8List.fromList(
      utf8.encode(anonAadhaarSignalString(challenge, deviceKeyThumbprint))));
  return '0x${bytesToHex(digest)}';
}

/// Port of @anon-aadhaar/core `hash()`: keccak256 of the value as a 32-byte
/// big-endian number, shifted right by 3 bits so it fits the SNARK field.
BigInt anonAadhaarHash(BigInt value) {
  if (value.isNegative || value.bitLength > 256) {
    throw ArgumentError('value must fit in 32 bytes');
  }
  final bytes = Uint8List(32);
  var v = value;
  for (var i = 31; i >= 0; i--) {
    bytes[i] = (v & BigInt.from(0xFF)).toInt();
    v = v >> 8;
  }
  final digest = pc.KeccakDigest(256).process(bytes);
  var h = BigInt.zero;
  for (final b in digest) {
    h = (h << 8) | BigInt.from(b);
  }
  return h >> 3;
}

/// zk-email `sha256Pad(message, maxShaBytes)`: SHA-256 padding, then zeros
/// up to [maxShaBytes]. Returns the padded bytes and the SHA-padded length.
(Uint8List, int) sha256Pad(Uint8List message, int maxShaBytes) {
  final bitLen = message.length * 8;
  final out = BytesBuilder()
    ..add(message)
    ..addByte(0x80);
  while ((out.length + 8) % 64 != 0) {
    out.addByte(0);
  }
  final lenBytes = Uint8List(8);
  var l = bitLen;
  for (var i = 7; i >= 0; i--) {
    lenBytes[i] = l & 0xFF;
    l >>= 8;
  }
  out.add(lenBytes);
  final messageLen = out.length;
  if (messageLen > maxShaBytes) {
    throw ArgumentError('Message is longer than $maxShaBytes bytes after padding');
  }
  final padded = Uint8List(maxShaBytes)..setRange(0, messageLen, out.toBytes());
  return (padded, messageLen);
}

/// @anon-aadhaar/core `splitToWords(n, wordsize, count)`, little-end first.
List<String> splitToWords(BigInt number, int wordSize, int count) {
  final mask = (BigInt.one << wordSize) - BigInt.one;
  var t = number;
  final words = <String>[];
  for (var i = 0; i < count; i++) {
    words.add((t & mask).toString());
    t = t >> wordSize;
  }
  if (t != BigInt.zero) {
    throw ArgumentError('Number does not fit in ${wordSize * count} bits');
  }
  return words;
}

/// The witness inputs of the Anon Aadhaar circuit, built exactly like
/// @anon-aadhaar/core `generateArgs()`, revealing ONLY "age above 18".
///
/// PRIVACY: qrDataPadded holds the personal data. This object lives in
/// memory until the prover finishes, and is never logged, saved or sent.
class AnonAadhaarInputs {
  AnonAadhaarInputs._(this.circuitInputs);

  factory AnonAadhaarInputs.build({
    required AadhaarSecureQr qr,
    required BigInt uidaiModulus,
    required String nullifierSeed,
    required String signal,
  }) {
    final seed = BigInt.parse(nullifierSeed);
    if (seed.isNegative || seed > circomFieldP) {
      throw ArgumentError('Nullifier seed is larger than the field size');
    }
    final (padded, messageLen) = sha256Pad(qr.signedData, 512 * 3);
    final delimiterIndices = <String>[];
    for (var i = 0; i < padded.length && delimiterIndices.length < 18; i++) {
      if (padded[i] == 255) delimiterIndices.add('$i');
    }
    var sig = BigInt.zero;
    for (final b in qr.signature) {
      sig = (sig << 8) | BigInt.from(b);
    }
    final signalValue = BigInt.parse(signal.substring(2), radix: 16);
    return AnonAadhaarInputs._({
      'qrDataPadded': padded.map((b) => '$b').toList(),
      'qrDataPaddedLength': '$messageLen',
      'delimiterIndices': delimiterIndices,
      'signature': splitToWords(sig, 121, 17),
      'pubKey': splitToWords(uidaiModulus, 121, 17),
      'nullifierSeed': seed.toString(),
      'signalHash': anonAadhaarHash(signalValue).toString(),
      'revealAgeAbove18': '1',
      'revealGender': '0',
      'revealPinCode': '0',
      'revealState': '0',
    });
  }

  /// Circom input JSON for `aadhaar-verifier.wasm` / `circuit_final.zkey`.
  final Map<String, Object> circuitInputs;

  void wipe() => circuitInputs.clear();
}

class ProverFailed implements Exception {
  const ProverFailed(this.message);
  final String message;
  @override
  String toString() => 'ProverFailed($message)';
}

/// Where the prover is, for the progress screen.
enum ProverStage {
  idle('Getting ready'),
  loadingWitnessProgram('Loading the proof program'),
  witness('Working through the QR inside the proof'),
  loadingProvingKey('Loading the proving key'),
  proving('Making the proof'),
  checking('Checking the proof'),
  done('Proof made'),
  failed('Stopped');

  const ProverStage(this.label);
  final String label;

  static ProverStage fromCode(int c) => switch (c) {
        1 => loadingWitnessProgram,
        2 => witness,
        3 => loadingProvingKey,
        4 => proving,
        5 => checking,
        6 => done,
        9 => failed,
        _ => idle,
      };
}

/// The Anon Aadhaar proof object sent as `proof` in POST /v1/card/issue
/// (method `anon_aadhaar`), in @anon-aadhaar/core's AnonAadhaarCore shape.
class AnonAadhaarProof {
  AnonAadhaarProof({required this.groth16Proof, required this.signals, required this.timingsMs, this.id});

  factory AnonAadhaarProof.fromProver(Map<String, dynamic> j) {
    final named = (j['named'] as Map?)?.cast<String, dynamic>() ?? const {};
    for (final k in _signalNames) {
      if (named[k] is! String) throw const ProverFailed('The proof is missing its public values.');
    }
    if (named['ageAbove18'] != '1' || named['gender'] != '0' || named['pincode'] != '0' || named['state'] != '0') {
      throw const ProverFailed('The proof would reveal more than "18+", so it was not sent.');
    }
    return AnonAadhaarProof(
      groth16Proof: (j['proof'] as Map).cast<String, Object?>(),
      signals: {for (final k in _signalNames) k: named[k] as String},
      timingsMs: ((j['timingsMs'] as Map?) ?? const {}).map((k, v) => MapEntry('$k', (v as num).toInt())),
    );
  }

  static const _signalNames = [
    'pubkeyHash', 'nullifier', 'timestamp', 'ageAbove18', 'gender', 'pincode', 'state',
    'nullifierSeed', 'signalHash'
  ];

  final Map<String, Object?> groth16Proof;
  final Map<String, String> signals;
  final Map<String, int> timingsMs;
  final String? id;

  Duration get total => Duration(milliseconds: timingsMs['total'] ?? 0);

  Map<String, Object?> toJson(String id) => {
        'type': 'anon-aadhaar',
        'id': id,
        'claim': {'ageAbove18': true},
        'proof': {
          'groth16Proof': groth16Proof,
          for (final k in _signalNames) k: signals[k],
        },
      };
}

/// Makes the Anon Aadhaar Groth16 proof from [AnonAadhaarInputs] and the
/// downloaded circuit files.
abstract class AnonAadhaarProver {
  /// False when this phone cannot run the prover (the native library did not load).
  bool get available;

  Future<AnonAadhaarProof> prove(
    AnonAadhaarInputs inputs,
    AadhaarArtifactPaths files, {
    void Function(ProverStage stage)? onStage,
  });
}
