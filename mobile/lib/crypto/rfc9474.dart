// =============================================================================
// NEEDS SECURITY REVIEW
//
// RFC 9474 (RSA Blind Signatures) client steps: Prepare, Blind, Finalize, and
// the RSASSA-PSS verification used by Finalize.
//
// Why this file exists: there is no vetted RFC 9474 client library for Dart.
// PROTOCOL.md section 2 says to implement it exactly per the RFC, using vetted
// building blocks, and to pass every RFC 9474 Appendix A test vector.
//
// Building blocks used (not home-made):
//   * SHA-384:            package:pointycastle SHA384Digest
//   * RSASSA-PSS-VERIFY:  package:pointycastle PSSSigner + RSAEngine
//   * Big integers:       Dart SDK BigInt (modPow, modInverse, gcd)
//   * Randomness:         dart:math Random.secure() (the OS CSPRNG)
//
// Written here, following RFC 8017 and RFC 9474 text line by line:
//   * EMSA-PSS-ENCODE (RFC 8017 section 9.1.1) and MGF1 (RFC 8017 B.2.1)
//   * OS2IP / I2OSP, random_integer_uniform (rejection sampling)
//
// Notes for the reviewer:
//   1. RFC 9474 section 4.2 step 1 writes EMSA-PSS-ENCODE(msg, bit_len(n)).
//      RFC 8017 signing and verification use emBits = modBits - 1, and so do
//      the Appendix A vectors and @cloudflare/blindrsa-ts. We use
//      modBits - 1. The Appendix A tests in test/crypto/ confirm this.
//   2. Dart's BigInt.modPow is not constant time. The blinding factor r is a
//      client secret; a timing side channel on the phone itself is outside
//      our threat model, but please double-check.
//   3. Finalize verifies the unblinded signature with pointycastle's
//      independent PSS verifier, so a bug in our encoder cannot produce a
//      ticket that passes on the phone but fails on websites.
// =============================================================================

import 'dart:math';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart' as pc;

/// The four RFC 9474 variants. V18 uses only [sha384PssRandomized].
enum BlindRsaVariant {
  sha384PssRandomized('RSABSSA-SHA384-PSS-Randomized', 48, true),
  sha384PssZeroRandomized('RSABSSA-SHA384-PSSZERO-Randomized', 0, true),
  sha384PssDeterministic('RSABSSA-SHA384-PSS-Deterministic', 48, false),
  sha384PssZeroDeterministic('RSABSSA-SHA384-PSSZERO-Deterministic', 0, false);

  const BlindRsaVariant(this.name, this.saltLength, this.randomized);

  /// The name used in JWKS `alg` and the blind-sign response `algorithm`.
  final String name;

  /// sLen in bytes (48 for PSS, 0 for PSSZERO).
  final int saltLength;

  /// Whether Prepare adds a 32-byte random prefix.
  final bool randomized;

  /// SHA-384 output length.
  static const int hashLength = 48;

  /// Length of the random prefix added by PrepareRandomize.
  static const int prefixLength = 32;
}

class BlindRsaException implements Exception {
  BlindRsaException(this.kind, [this.detail]);

  /// One of the RFC 9474 error names, for example "invalid input",
  /// "blinding error", "invalid signature", "unexpected input size",
  /// "message too long", "encoding error".
  final String kind;
  final String? detail;

  @override
  String toString() =>
      'BlindRsaException($kind${detail == null ? '' : ': $detail'})';
}

/// RSA public key (n, e) of the ticket signing key.
class BlindRsaPublicKey {
  BlindRsaPublicKey(this.n, this.e) {
    if (n <= BigInt.one || e <= BigInt.one) {
      throw BlindRsaException('invalid input', 'bad RSA public key');
    }
  }

  final BigInt n;
  final BigInt e;

  int get modulusBits => n.bitLength;

  /// modulus_len in RFC 9474: the length in bytes of n.
  int get modulusLength => (n.bitLength + 7) ~/ 8;
}

/// Output of Blind: the bytes for the server, and the inverse kept on the phone.
class BlindingResult {
  BlindingResult(this.blindedMessage, this.inverse);

  /// blinded_msg, exactly modulus_len bytes.
  final Uint8List blindedMessage;

  /// inv, the inverse of the blinding factor r modulo n. Secret.
  final BigInt inverse;
}

/// The client half of RFC 9474.
class BlindRsaClient {
  BlindRsaClient(this.variant, {Random? random})
      : _random = random ?? Random.secure();

  final BlindRsaVariant variant;
  final Random _random;

  /// RFC 9474 section 4.1. PrepareRandomize or PrepareIdentity.
  Uint8List prepare(Uint8List msg) {
    if (!variant.randomized) return Uint8List.fromList(msg);
    return prepareWithPrefix(msg, _randomBytes(BlindRsaVariant.prefixLength));
  }

  /// PrepareRandomize with a given prefix. Visible for the Appendix A tests.
  @visibleForTesting
  Uint8List prepareWithPrefix(Uint8List msg, Uint8List msgPrefix) {
    if (!variant.randomized) {
      throw StateError('This variant does not add a prefix');
    }
    if (msgPrefix.length != BlindRsaVariant.prefixLength) {
      throw ArgumentError('msg_prefix must be 32 bytes');
    }
    return Uint8List.fromList([...msgPrefix, ...msg]);
  }

  /// RFC 9474 section 4.2. [preparedMsg] is the output of [prepare].
  BlindingResult blind(BlindRsaPublicKey pk, Uint8List preparedMsg) {
    // "blinding error" SHOULD be retried; it has negligible probability.
    for (var attempt = 0; attempt < 8; attempt++) {
      final salt = _randomBytes(variant.saltLength);
      final r = _randomIntegerUniform(BigInt.one, pk.n);
      try {
        return blindWith(pk, preparedMsg, salt: salt, r: r);
      } on BlindRsaException catch (e) {
        if (e.kind != 'blinding error') rethrow;
      }
    }
    throw BlindRsaException('blinding error', 'gave up after 8 attempts');
  }

  /// Blind with a fixed salt and r. Visible for the Appendix A tests only.
  @visibleForTesting
  BlindingResult blindWith(
    BlindRsaPublicKey pk,
    Uint8List preparedMsg, {
    required Uint8List salt,
    required BigInt r,
  }) {
    // 1-2. encoded_msg = EMSA-PSS-ENCODE(msg, modBits - 1) (see note 1 above)
    final encoded = emsaPssEncode(preparedMsg, pk.modulusBits - 1, salt);
    // 3. m = bytes_to_int(encoded_msg)
    final m = os2ip(encoded);
    // 4-5. is_coprime(m, n)
    if (m.gcd(pk.n) != BigInt.one) {
      throw BlindRsaException('invalid input', 'message not co-prime with n');
    }
    // 6. r = random_integer_uniform(1, n)  (given by the caller)
    if (r < BigInt.one || r >= pk.n) {
      throw BlindRsaException('blinding error', 'r out of range');
    }
    // 7-8. inv = inverse_mod(r, n)
    final BigInt inv;
    try {
      inv = r.modInverse(pk.n);
    } on Exception {
      throw BlindRsaException('blinding error', 'r has no inverse');
    }
    // 9. x = RSAVP1(pk, r) = r^e mod n
    final x = r.modPow(pk.e, pk.n);
    // 10. z = (m * x) mod n
    final z = (m * x) % pk.n;
    // 11. blinded_msg = int_to_bytes(z, modulus_len)
    return BlindingResult(i2osp(z, pk.modulusLength), inv);
  }

  /// RFC 9474 section 4.4. Returns sig (modulus_len bytes) or throws.
  Uint8List finalize(
    BlindRsaPublicKey pk,
    Uint8List preparedMsg,
    Uint8List blindSig,
    BigInt inv,
  ) {
    // 1. length check
    if (blindSig.length != pk.modulusLength) {
      throw BlindRsaException('unexpected input size',
          'blind_sig is ${blindSig.length} bytes, expected ${pk.modulusLength}');
    }
    // 2. z = bytes_to_int(blind_sig)
    final z = os2ip(blindSig);
    if (z >= pk.n) {
      throw BlindRsaException('invalid signature', 'blind_sig >= n');
    }
    // 3. s = (z * inv) mod n
    final s = (z * inv) % pk.n;
    // 4. sig = int_to_bytes(s, modulus_len)
    final sig = i2osp(s, pk.modulusLength);
    // 5-6. RSASSA-PSS-VERIFY(pk, msg, sig)
    if (!verify(pk, preparedMsg, sig)) {
      throw BlindRsaException('invalid signature');
    }
    return sig;
  }

  /// RSASSA-PSS-VERIFY (RFC 8017 section 8.1.2) with SHA-384, MGF1-SHA-384
  /// and this variant's salt length, done by pointycastle.
  bool verify(BlindRsaPublicKey pk, Uint8List preparedMsg, Uint8List sig) {
    if (sig.length != pk.modulusLength) return false;
    final signer = pc.PSSSigner(
        pc.RSAEngine(), pc.SHA384Digest(), pc.SHA384Digest());
    signer.init(
      false,
      pc.ParametersWithSaltConfiguration(
        pc.PublicKeyParameter<pc.RSAPublicKey>(pc.RSAPublicKey(pk.n, pk.e)),
        _unusedRandom(),
        variant.saltLength,
      ),
    );
    try {
      return signer.verifySignature(preparedMsg, pc.PSSSignature(sig));
    } on Object {
      return false;
    }
  }

  /// EMSA-PSS-ENCODE, RFC 8017 section 9.1.1, with SHA-384 and MGF1-SHA-384.
  @visibleForTesting
  Uint8List emsaPssEncode(Uint8List message, int emBits, Uint8List salt) {
    const hLen = BlindRsaVariant.hashLength;
    final sLen = variant.saltLength;
    if (salt.length != sLen) {
      throw ArgumentError('salt must be $sLen bytes');
    }
    final emLen = (emBits + 7) ~/ 8;
    // 1-2. mHash = Hash(M). (SHA-384 input limit is far above any ticket.)
    final mHash = sha384(message);
    // 3. emLen < hLen + sLen + 2 -> "encoding error"
    if (emLen < hLen + sLen + 2) {
      throw BlindRsaException('encoding error', 'modulus too small');
    }
    // 4-5. M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    final mPrime = Uint8List(8 + hLen + sLen)
      ..setRange(8, 8 + hLen, mHash)
      ..setRange(8 + hLen, 8 + hLen + sLen, salt);
    // 6. H = Hash(M')
    final h = sha384(mPrime);
    // 7-8. DB = PS || 0x01 || salt, PS = zeros(emLen - sLen - hLen - 2)
    final dbLen = emLen - hLen - 1;
    final db = Uint8List(dbLen);
    db[dbLen - sLen - 1] = 0x01;
    db.setRange(dbLen - sLen, dbLen, salt);
    // 9. dbMask = MGF(H, emLen - hLen - 1)
    final dbMask = mgf1Sha384(h, dbLen);
    // 10. maskedDB = DB xor dbMask
    for (var i = 0; i < dbLen; i++) {
      db[i] ^= dbMask[i];
    }
    // 11. Set the leftmost 8*emLen - emBits bits of maskedDB to zero.
    final zeroBits = 8 * emLen - emBits;
    if (zeroBits > 0) {
      db[0] &= 0xFF >> zeroBits;
    }
    // 12. EM = maskedDB || H || 0xbc
    return Uint8List(emLen)
      ..setRange(0, dbLen, db)
      ..setRange(dbLen, dbLen + hLen, h)
      ..[emLen - 1] = 0xbc;
  }

  /// random_integer_uniform(min, max): uniform in [min, max) by rejection
  /// sampling, as RFC 9474 section 4.2 asks.
  BigInt _randomIntegerUniform(BigInt min, BigInt max) {
    final bits = max.bitLength;
    final byteLen = (bits + 7) ~/ 8;
    final topMask = 0xFF >> (8 * byteLen - bits);
    while (true) {
      final bytes = _randomBytes(byteLen);
      bytes[0] &= topMask;
      final candidate = os2ip(bytes);
      if (candidate >= min && candidate < max) return candidate;
    }
  }

  Uint8List _randomBytes(int length) {
    final out = Uint8List(length);
    for (var i = 0; i < length; i++) {
      out[i] = _random.nextInt(256);
    }
    return out;
  }

  // PSS verification does not use randomness, but pointycastle's parameter
  // type needs a SecureRandom. Seeded from the OS CSPRNG anyway.
  pc.SecureRandom _unusedRandom() {
    final r = pc.FortunaRandom();
    final seed = Random.secure();
    r.seed(pc.KeyParameter(
        Uint8List.fromList(List<int>.generate(32, (_) => seed.nextInt(256)))));
    return r;
  }
}

/// SHA-384 via pointycastle.
Uint8List sha384(Uint8List data) => pc.SHA384Digest().process(data);

/// MGF1 with SHA-384, RFC 8017 appendix B.2.1.
Uint8List mgf1Sha384(Uint8List seed, int maskLen) {
  const hLen = BlindRsaVariant.hashLength;
  final out = BytesBuilder(copy: false);
  var counter = 0;
  while (out.length < maskLen) {
    final c = Uint8List(4)
      ..[0] = (counter >> 24) & 0xFF
      ..[1] = (counter >> 16) & 0xFF
      ..[2] = (counter >> 8) & 0xFF
      ..[3] = counter & 0xFF;
    out.add(sha384(Uint8List.fromList([...seed, ...c])));
    counter++;
  }
  assert(counter <= (maskLen + hLen - 1) ~/ hLen);
  return Uint8List.sublistView(out.toBytes(), 0, maskLen);
}

/// OS2IP: big-endian bytes to a non-negative integer.
BigInt os2ip(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

/// I2OSP: non-negative integer to exactly [length] big-endian bytes.
Uint8List i2osp(BigInt x, int length) {
  if (x.isNegative || x.bitLength > length * 8) {
    throw BlindRsaException('encoding error', 'integer too large');
  }
  final out = Uint8List(length);
  var v = x;
  final mask = BigInt.from(0xFF);
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (v & mask).toInt();
    v = v >> 8;
  }
  return out;
}
