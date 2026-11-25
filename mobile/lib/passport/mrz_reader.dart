import 'dart:convert';
import 'dart:typed_data';

import 'package:dmrtd/dmrtd.dart';

/// What the chip needs to open (BAC/PACE key): document number, date of birth
/// and expiry date from the MRZ text lines.
///
/// PRIVACY: kept in memory only, never logged, saved or sent. Cleared when the
/// passport flow ends.
class MrzKey {
  MrzKey({
    required this.documentNumber,
    required this.dateOfBirth,
    required this.dateOfExpiry,
  });

  final String documentNumber;
  final DateTime dateOfBirth;
  final DateTime dateOfExpiry;

  DBAKey toDbaKey({bool paceMode = false}) =>
      DBAKey(documentNumber, dateOfBirth, dateOfExpiry, paceMode: paceMode);
}

/// Finds and checks an MRZ in OCR text. Check digits are checked by dmrtd's
/// MRZ parser. Returns null if no valid MRZ is found.
MrzKey? mrzKeyFromOcrText(String text) {
  final lines = text
      .split(RegExp(r'[\r\n]+'))
      .map(_cleanLine)
      .where((l) => l.length >= 28)
      .toList();
  // Try every group of 2 (TD3, TD2) or 3 (TD1) neighbouring lines.
  for (var i = 0; i < lines.length; i++) {
    for (final size in const [2, 3]) {
      if (i + size > lines.length) continue;
      final group = lines.sublist(i, i + size);
      final key = _tryGroup(group);
      if (key != null) return key;
    }
  }
  return null;
}

/// Parses MRZ lines typed or pasted by the user (2 or 3 lines).
MrzKey? mrzKeyFromLines(List<String> lines) => _tryGroup(lines.map(_cleanLine).toList());

MrzKey? _tryGroup(List<String> group) {
  final lengths = group.map((l) => l.length).toSet();
  if (lengths.length != 1) return null;
  final len = lengths.first;
  final ok = (group.length == 2 && (len == 44 || len == 36)) ||
      (group.length == 3 && len == 30);
  if (!ok) return null;
  for (final candidate in _ocrVariants(group)) {
    try {
      final mrz = MRZ(Uint8List.fromList(ascii.encode(candidate.join())));
      return MrzKey(
        documentNumber: mrz.documentNumber,
        dateOfBirth: mrz.dateOfBirth,
        dateOfExpiry: mrz.dateOfExpiry,
      );
    } on Object {
      // Not valid (bad check digit or layout). Try the next variant.
    }
  }
  return null;
}

String _cleanLine(String line) => line
    .toUpperCase()
    .replaceAll('«', '<')
    .replaceAll(RegExp(r'\s'), '')
    .replaceAll(RegExp(r'[^A-Z0-9<]'), '');

/// OCR often mixes up O/0, I/1, B/8, S/5 and Z/2 in number fields. We try
/// the text as read first, then with digits fixed in the second line's
/// date and check-digit fields. dmrtd's check digits decide what is right.
Iterable<List<String>> _ocrVariants(List<String> group) sync* {
  yield group;
  const toDigit = {'O': '0', 'D': '0', 'Q': '0', 'I': '1', 'L': '1', 'Z': '2', 'S': '5', 'B': '8', 'G': '6'};
  String fix(String s, List<(int, int)> ranges) {
    final chars = s.split('');
    for (final (a, b) in ranges) {
      for (var i = a; i < b && i < chars.length; i++) {
        chars[i] = toDigit[chars[i]] ?? chars[i];
      }
    }
    return chars.join();
  }

  if (group.length == 2 && group[0].length == 44) {
    // TD3 line 2: doc check 9, DOB 13-19, expiry 21-27, checks 27, 42, 43.
    yield [group[0], fix(group[1], [(9, 10), (13, 20), (21, 28), (42, 44)])];
  } else if (group.length == 2 && group[0].length == 36) {
    yield [group[0], fix(group[1], [(9, 10), (13, 20), (21, 28), (35, 36)])];
  } else if (group.length == 3) {
    // TD1 line 2: DOB 0-6 + check, expiry 8-14 + check, composite 29.
    yield [group[0], fix(group[1], [(0, 7), (8, 15), (29, 30)]), group[2]];
  }
}
