import 'dart:math';
import 'dart:typed_data';

import 'package:dmrtd/dmrtd.dart';
// CanKey is not exported by dmrtd's main library.
// ignore: implementation_imports
import 'package:dmrtd/src/proto/can_key.dart';

import 'active_auth.dart';
import 'csca.dart';
import 'mrz_reader.dart';
import 'passive_auth.dart';

/// How the phone unlocks the chip.
sealed class ChipAccess {
  const ChipAccess();
}

/// The MRZ lines (passports, and ID cards when typed in): BAC, or PACE with the MRZ.
class MrzAccess extends ChipAccess {
  const MrzAccess(this.key);
  final MrzKey key;
}

/// The 6-digit Card Access Number printed on ID cards and residence permits: PACE.
class CanAccess extends ChipAccess {
  const CanAccess(this.can);
  final String can;
}

/// What the phone learned from the chip.
///
/// PRIVACY: [nullifierMessage] holds the document number. It lives in memory
/// only until the nullifier request is made, then [wipe] clears it. The name
/// and date of birth are never kept: only "18 or older" and the expiry date.
class ChipCheckResult {
  ChipCheckResult({
    required this.accessProtocol,
    required this.passiveAuth,
    required this.activeAuth,
    required this.docType,
    required this.issuingState,
    required this.docExpiry,
    required this.over18,
    required String nullifierMessage,
  }) {
    _nullifierMessage = nullifierMessage;
  }

  /// "PACE" or "BAC".
  final String accessProtocol;
  final PassiveAuthResult passiveAuth;
  final ActiveAuthResult activeAuth;

  /// First MRZ letter: P (passport), I (ID card), A or C (residence permits and other).
  final String docType;

  /// 3-letter MRZ code, with `<` filler (for example "IND", "D<<").
  final String issuingState;
  final DateTime docExpiry;
  final bool over18;

  String? _nullifierMessage;

  /// `v18-doc-v1|<issuing state>|<document number>` (PROTOCOL 4c.2).
  String get nullifierMessage {
    final m = _nullifierMessage;
    if (m == null) throw StateError('The chip result was already wiped');
    return m;
  }

  void wipe() => _nullifierMessage = null;

  /// The value for the card request's `chipAuth` (PROTOCOL 4c.4).
  /// dmrtd has no Chip Authentication, so only Active Authentication counts.
  String get chipAuthWire => activeAuth == ActiveAuthResult.passed ? 'active_auth' : 'none';

  bool get expired {
    final now = DateTime.now();
    return DateTime(now.year, now.month, now.day).isAfter(docExpiry);
  }

  /// The `proof` for POST /v1/card/issue, method `emrtd_attested` (PROTOCOL 4c.4, 4d.3).
  /// Only these fields: no name, no date of birth, no document number.
  Map<String, Object?> proof({required String nullifier, required String nullifierKeyId}) => {
        'over18': over18,
        'docExpiry': _ymd(docExpiry),
        'issuingState': issuingState,
        'docType': docType,
        'passiveAuth': passiveAuth.passed ? 'ok' : 'failed',
        'chipAuth': chipAuthWire,
        'nullifier': nullifier,
        'nullifierKeyId': nullifierKeyId,
      };

  static String _ymd(DateTime d) =>
      '${d.year.toString().padLeft(4, '0')}-${d.month.toString().padLeft(2, '0')}-${d.day.toString().padLeft(2, '0')}';
}

class ChipReadException implements Exception {
  const ChipReadException(this.message, {this.sealProblem = false});
  final String message;

  /// True when the chip was read but its seal did not check out.
  final bool sealProblem;
  @override
  String toString() => 'ChipReadException($message)';
}

/// The nullifier message of PROTOCOL 4c.2 for a document.
String docNullifierMessage(String issuingState, String documentNumber) =>
    'v18-doc-v1|$issuingState|${documentNumber.toUpperCase().replaceAll('<', '')}';

/// "18 or older" on [today] for someone born on [dob].
bool isAtLeast18(DateTime dob, DateTime today) {
  final eighteenth = DateTime(dob.year + 18, dob.month, dob.day);
  return !DateTime(today.year, today.month, today.day).isBefore(eighteenth);
}

/// Reads a passport, ID card or residence permit chip with dmrtd (ICAO 9303),
/// then checks it on the phone: passive authentication up to a CSCA from the
/// bundled master list, and Active Authentication when the chip has it.
///
/// [provider] is the NFC connection; tests and the emulator pass the TEST chip
/// simulator instead (test/helpers/test_chip.dart).
class ChipReader {
  ChipReader({
    ComProvider Function()? provider,
    required this.trust,
    Future<bool> Function()? nfcEnabled,
    DateTime Function()? now,
    Random? random,
  })  : _provider = provider ?? NfcProvider.new,
        _nfcEnabled = nfcEnabled ?? (() async => await NfcProvider.nfcStatus == NfcStatus.enabled),
        _now = now ?? DateTime.now,
        _random = random ?? Random.secure();

  final ComProvider Function() _provider;
  final Future<bool> Function() _nfcEnabled;
  final DateTime Function() _now;
  final Random _random;

  /// The CSCA trust to use (the bundled master list, plus the TEST CSCA only
  /// when the server is in dev mode).
  final Future<CscaTrust> Function() trust;

  Future<ChipCheckResult> read(
    ChipAccess access, {
    void Function(double progress, String step)? onProgress,
  }) async {
    if (!await _nfcEnabled()) {
      throw const ChipReadException('NFC is off. Turn on NFC in your phone settings, then try again.');
    }
    final com = _provider();
    final dataGroups = <int, Uint8List>{};
    try {
      onProgress?.call(0.05, 'Looking for the chip');
      if (com is NfcProvider) {
        await com.connect(timeout: const Duration(seconds: 30));
      } else {
        await com.connect();
      }
      final passport = Passport(com);

      // PACE first (all EU ID cards, newer passports), then BAC.
      String protocol;
      EfCardAccess? cardAccess;
      try {
        cardAccess = await passport.readEfCardAccess();
      } on Object {
        cardAccess = null;
      }
      switch (access) {
        case CanAccess(:final can):
          if (cardAccess == null) {
            throw const ChipReadException(
                "This chip doesn't use a card number (CAN). Use the text lines on the document instead.");
          }
          await passport.startSessionPACE(CanKey(can), cardAccess);
          protocol = 'PACE';
        case MrzAccess(:final key):
          if (cardAccess != null) {
            try {
              await passport.startSessionPACE(key.toDbaKey(paceMode: true), cardAccess);
              protocol = 'PACE';
            } on Object {
              await com.disconnect();
              await com.connect();
              await passport.startSession(key.toDbaKey());
              protocol = 'BAC';
            }
          } else {
            await passport.startSession(key.toDbaKey());
            protocol = 'BAC';
          }
      }
      onProgress?.call(0.3, 'Chip unlocked');

      final efCom = await passport.readEfCOM();
      final dg1 = await passport.readEfDG1();
      dataGroups[1] = dg1.toBytes();
      onProgress?.call(0.5, 'Reading the data');
      if (efCom.dgTags.contains(EfDG14.TAG)) dataGroups[14] = (await passport.readEfDG14()).toBytes();

      var aa = ActiveAuthResult.notOffered;
      Uint8List? aaChallenge;
      Uint8List? aaSignature;
      if (efCom.dgTags.contains(EfDG15.TAG)) {
        dataGroups[15] = (await passport.readEfDG15()).toBytes();
        if (activeAuthSupported(dataGroups[15]!)) {
          aaChallenge = Uint8List.fromList(List<int>.generate(8, (_) => _random.nextInt(256)));
          try {
            aaSignature = await passport.activeAuthenticate(aaChallenge);
          } on Object {
            aaSignature = null;
          }
        } else {
          aa = ActiveAuthResult.notSupported;
        }
      }
      onProgress?.call(0.75, 'Checking the seal');
      final sod = (await passport.readEfSOD()).toBytes();
      final pa = passiveAuthenticate(sod, dataGroups, trust: await trust(), now: _now());
      if (!pa.passed) {
        throw ChipReadException(pa.problem ?? 'The chip seal did not check out.', sealProblem: true);
      }
      // AA is checked only after DG15 is known to be sealed (passive auth passed).
      if (aaChallenge != null) {
        aa = aaSignature == null
            ? ActiveAuthResult.failed
            : verifyActiveAuth(
                dg15: dataGroups[15]!, dg14: dataGroups[14], challenge: aaChallenge, signature: aaSignature);
        if (aa == ActiveAuthResult.failed) {
          throw const ChipReadException(
              "The chip failed the copy test (Active Authentication). It may be a copied chip.",
              sealProblem: true);
        }
      }
      final mrz = dg1.mrz;
      final docType = mrz.documentCode.isEmpty ? '' : mrz.documentCode[0];
      if (!const {'P', 'I', 'A', 'C'}.contains(docType)) {
        throw const ChipReadException('This kind of document is not accepted (only passports, ID cards and residence permits).');
      }
      final state = mrz.country.padRight(3, '<');
      final result = ChipCheckResult(
        accessProtocol: protocol,
        passiveAuth: pa,
        activeAuth: aa,
        docType: docType,
        issuingState: state,
        docExpiry: mrz.dateOfExpiry,
        over18: isAtLeast18(mrz.dateOfBirth, _now()),
        nullifierMessage: docNullifierMessage(state, mrz.documentNumber),
      );
      onProgress?.call(1, 'Done');
      return result;
    } on ChipReadException {
      rethrow;
    } on Object catch (e) {
      throw ChipReadException(_friendly(e));
    } finally {
      // Drop the personal data (name, birth date) right away.
      for (final dg in dataGroups.values) {
        dg.fillRange(0, dg.length, 0);
      }
      dataGroups.clear();
      try {
        await com.disconnect();
      } on Object {
        // Already gone.
      }
    }
  }

  static String _friendly(Object e) {
    final s = e.toString();
    if (s.contains('Timeout') || s.contains('timeout')) {
      return "We couldn't find the chip. Hold the phone still on the document and try again.";
    }
    if (s.contains('Tag was lost') || s.contains('lost')) {
      return 'The chip connection was lost. Keep the phone still.';
    }
    if (s.contains('6300') || s.contains('authentication') || s.contains('BAC') || s.contains('PACE')) {
      return "The chip didn't accept the details. Check them and try again.";
    }
    return "We couldn't read the chip. Try again.";
  }
}
