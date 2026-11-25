// TEST ONLY: a simulated ICAO 9303 chip, so the full chip flow can run where
// there is no NFC (unit tests and the Android emulator). It is NOT part of the
// app. It answers exactly the APDUs dmrtd sends, through dmrtd's real BAC and
// secure messaging (3DES, retail MAC, send sequence counter), using dmrtd's own
// building blocks for the chip side. It holds the TEST document files from
// tool/make_emrtd_fixtures.py and signs Active Authentication challenges with
// the TEST chip's EC key. No PACE (it has no EF.CardAccess), so dmrtd uses BAC.
// ignore_for_file: implementation_imports
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/src/crypto/iso9797.dart';
import 'package:dmrtd/src/proto/bac.dart';
import 'package:dmrtd/src/proto/des_smcipher.dart';
import 'package:dmrtd/src/proto/iso7816/command_apdu.dart';
import 'package:dmrtd/src/proto/iso7816/sm.dart';
import 'package:dmrtd/src/proto/mrtd_sm.dart';
import 'package:dmrtd/src/proto/ssc.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/export.dart' as pc;

/// One TEST document: its chip files, BAC key data and AA private key.
class TestDocument {
  TestDocument({
    required this.files,
    required this.documentNumber,
    required this.dateOfBirth,
    required this.dateOfExpiry,
    required this.aaPrivateKey,
  });

  /// From test/fixtures/emrtd (on the PC). [name] is "adult" or "minor".
  factory TestDocument.fromFixtures(String name, {String dir = 'test/fixtures/emrtd'}) {
    Uint8List f(String n) => File('$dir/${name}_$n.bin').readAsBytesSync();
    final meta = (jsonDecode(File('$dir/documents.json').readAsStringSync()) as Map)['documents'][name] as Map;
    return TestDocument.fromParts(
      com: f('ef_com'),
      dg1: f('dg1'),
      dg14: f('dg14'),
      dg15: f('dg15'),
      sod: f('sod'),
      meta: meta.cast<String, dynamic>(),
    );
  }

  factory TestDocument.fromParts({
    required Uint8List com,
    required Uint8List dg1,
    required Uint8List dg14,
    required Uint8List dg15,
    required Uint8List sod,
    required Map<String, dynamic> meta,
  }) {
    DateTime yymmdd(String s, {required bool birth}) {
      final yy = int.parse(s.substring(0, 2));
      final y = birth ? (yy > DateTime.now().year % 100 ? 1900 + yy : 2000 + yy) : 2000 + yy;
      return DateTime(y, int.parse(s.substring(2, 4)), int.parse(s.substring(4, 6)));
    }

    return TestDocument(
      files: {0x1E: com, 0x01: dg1, 0x0E: dg14, 0x0F: dg15, 0x1D: sod},
      documentNumber: meta['documentNumber'] as String,
      dateOfBirth: yymmdd(meta['dateOfBirth'] as String, birth: true),
      dateOfExpiry: yymmdd(meta['dateOfExpiry'] as String, birth: false),
      aaPrivateKey: BigInt.parse(meta['aaPrivateKeyD'] as String, radix: 16),
    );
  }

  /// SFI -> file bytes.
  final Map<int, Uint8List> files;
  final String documentNumber;
  final DateTime dateOfBirth;
  final DateTime dateOfExpiry;
  final BigInt aaPrivateKey;
}

/// TEST ONLY chip simulator (a dmrtd [ComProvider]).
class TestChip extends ComProvider {
  TestChip(this.doc, {Random? random, this.breakAa = false})
      : _random = random ?? Random.secure(),
        super(Logger('test.chip'));

  final TestDocument doc;
  final Random _random;

  /// Make the AA answer wrong (to test the copy-test failure).
  final bool breakAa;

  bool _connected = false;
  Uint8List? _rndIc;
  MrtdSM? _sm;
  DESedeSSC? _ssc;
  DES_SMCipher? _cipher;
  int? _currentSfi;
  final List<String> log = [];

  @override
  Future<void> connect() async => _connected = true;

  @override
  Future<void> disconnect() async {
    _connected = false;
    _sm = null;
    _ssc = null;
    _cipher = null;
  }

  @override
  bool isConnected() => _connected;

  @override
  Future<Uint8List> transceive(Uint8List apdu) async {
    if (!_connected) throw const ComProviderError('not connected');
    final cla = apdu[0], ins = apdu[1], p1 = apdu[2], p2 = apdu[3];
    var data = Uint8List(0);
    var ne = 0;
    if (apdu.length == 5) {
      ne = apdu[4] == 0 ? 256 : apdu[4];
    } else if (apdu.length > 5) {
      final lc = apdu[4];
      data = Uint8List.fromList(apdu.sublist(5, 5 + lc));
      if (apdu.length > 5 + lc) ne = apdu[5 + lc] == 0 ? 256 : apdu[5 + lc];
    }
    if (cla & 0x0C == 0x0C) {
      // Secure messaging.
      if (_sm == null) return _sw(0x6987);
      final unwrapped = _unwrap(cla, ins, p1, p2, data);
      if (unwrapped == null) return _sw(0x6988);
      final (plain, le) = unwrapped;
      final (out, sw) = _process(ins, p1, p2, plain, le);
      return _wrap(out, sw);
    }
    final (out, sw) = _process(ins, p1, p2, data, ne);
    return Uint8List.fromList([...out, sw >> 8, sw & 0xFF]);
  }

  static Uint8List _sw(int sw) => Uint8List.fromList([sw >> 8, sw & 0xFF]);

  (Uint8List, int) _process(int ins, int p1, int p2, Uint8List data, int ne) {
    log.add('INS ${ins.toRadixString(16)} P1 ${p1.toRadixString(16)}');
    switch (ins) {
      case 0xA4: // SELECT
        if (p1 == 0x02 && data.length == 2) {
          final fid = (data[0] << 8) | data[1];
          final sfi = {0x011E: 0x1E, 0x0101: 0x01, 0x010E: 0x0E, 0x010F: 0x0F, 0x011D: 0x1D}[fid];
          if (sfi == null || !doc.files.containsKey(sfi)) return (Uint8List(0), 0x6A82);
          _currentSfi = sfi;
        }
        return (Uint8List(0), 0x9000);
      case 0xB0: // READ BINARY
        int offset;
        if (p1 & 0x80 != 0) {
          _currentSfi = p1 & 0x1F;
          offset = p2;
        } else {
          offset = ((p1 & 0x7F) << 8) | p2;
        }
        final f = doc.files[_currentSfi];
        if (f == null) return (Uint8List(0), 0x6A82);
        // Before BAC every file is locked (except none: this chip has no EF.CardAccess).
        if (_sm == null) return (Uint8List(0), 0x6982);
        if (offset >= f.length) return (Uint8List(0), 0x6B00);
        final end = min(f.length, offset + (ne == 0 ? 256 : ne));
        return (Uint8List.fromList(f.sublist(offset, end)), 0x9000);
      case 0x84: // GET CHALLENGE
        _rndIc = _bytes(8);
        return (_rndIc!, 0x9000);
      case 0x82: // EXTERNAL AUTHENTICATE (BAC, ICAO 9303-11 4.3)
        return _bac(data);
      case 0x88: // INTERNAL AUTHENTICATE (Active Authentication)
        if (_sm == null) return (Uint8List(0), 0x6982);
        return (_aaSign(data), 0x9000);
      case 0x22: // MSE:SET AT (PACE): not offered by this chip
      case 0x86:
        return (Uint8List(0), 0x6A80);
      default:
        return (Uint8List(0), 0x6D00);
    }
  }

  (Uint8List, int) _bac(Uint8List data) {
    final rndIc = _rndIc;
    if (rndIc == null || data.length != 40) return (Uint8List(0), 0x6985);
    final key = DBAKey(doc.documentNumber, doc.dateOfBirth, doc.dateOfExpiry);
    final eIfd = Uint8List.fromList(data.sublist(0, 32));
    final mIfd = Uint8List.fromList(data.sublist(32));
    if (!_eq(BAC.MAC(Kmac: key.macKey, Eifd: eIfd), mIfd)) return (Uint8List(0), 0x6300);
    final s = BAC.D(Kdec: key.encKey, Eicc: eIfd); // RND.IFD || RND.IC || K.IFD
    final rndIfd = Uint8List.fromList(s.sublist(0, 8));
    if (!_eq(s.sublist(8, 16), rndIc)) return (Uint8List(0), 0x6300);
    final kIfd = Uint8List.fromList(s.sublist(16, 32));
    final kIc = _bytes(16);
    final r = Uint8List.fromList([...rndIc, ...rndIfd, ...kIc]);
    final eIc = BAC.E(Kenc: key.encKey, S: r);
    final mIc = BAC.MAC(Kmac: key.macKey, Eifd: eIc);
    final ks = BAC.calculateSessionKeys(Kifd: kIfd, Kicc: kIc);
    _ssc = BAC.calculateSCC(RNDifd: rndIfd, RNDicc: rndIc);
    _cipher = DES_SMCipher(ks.first, ks.second);
    _sm = MrtdSM(_cipher!, _ssc!);
    return (Uint8List.fromList([...eIc, ...mIc]), 0x9000);
  }

  /// Chip side of ICAO 9303-11 9.8 (protected command -> plain).
  (Uint8List, int)? _unwrap(int cla, int ins, int p1, int p2, Uint8List data) {
    final sm = _sm!;
    _ssc!.increment();
    var p = 0;
    var dataDo = Uint8List(0), do97 = Uint8List(0);
    Uint8List? mac;
    DecodedTV? enc;
    var le = 0;
    while (p < data.length) {
      final tv = TLV.decode(Uint8List.fromList(data.sublist(p)));
      final raw = Uint8List.fromList(data.sublist(p, p + tv.encodedLen));
      switch (tv.tag.value) {
        case 0x87:
        case 0x85:
          dataDo = raw;
          enc = tv;
        case 0x97:
          do97 = raw;
          le = tv.value.isEmpty ? 0 : (tv.value.length == 1 ? (tv.value[0] == 0 ? 256 : tv.value[0]) : 65536);
        case 0x8E:
          mac = Uint8List.fromList(tv.value);
      }
      p += tv.encodedLen;
    }
    final m = sm.generateM(cmd: CommandAPDU(cla: cla, ins: ins, p1: p1, p2: p2), dataDO: dataDo, do97: do97);
    final n = sm.generateN(M: m);
    if (mac == null || !_eq(_cipher!.mac(n), mac)) return null;
    final plain = sm.decryptDataDO(enc) ?? Uint8List(0);
    return (plain, le);
  }

  /// Chip side of the protected response.
  Uint8List _wrap(Uint8List data, int sw) {
    _ssc!.increment();
    final do87 = data.isEmpty
        ? Uint8List(0)
        : SecureMessaging.do87(_cipher!.encrypt(ISO9797.pad(data, 8)), dataIsPadded: true);
    final do99 = Uint8List.fromList([0x99, 0x02, sw >> 8, sw & 0xFF]);
    final k = _sm!.generateK(data: Uint8List.fromList([...do87, ...do99]));
    final do8e = SecureMessaging.do8E(_cipher!.mac(k));
    return Uint8List.fromList([...do87, ...do99, ...do8e, 0x90, 0x00]);
  }

  /// ECDSA (P-256, SHA-256, plain r||s) over the 8-byte challenge, as DG14 says.
  Uint8List _aaSign(Uint8List challenge) {
    final domain = pc.ECDomainParameters('prime256v1');
    final signer = pc.ECDSASigner(pc.SHA256Digest(), pc.HMac(pc.SHA256Digest(), 64))
      ..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(pc.ECPrivateKey(doc.aaPrivateKey, domain)));
    final s = signer.generateSignature(breakAa ? Uint8List.fromList([...challenge, 1]) : challenge) as pc.ECSignature;
    Uint8List i2os(BigInt v) {
      final out = Uint8List(32);
      var x = v;
      for (var i = 31; i >= 0; i--) {
        out[i] = (x & BigInt.from(0xFF)).toInt();
        x = x >> 8;
      }
      return out;
    }

    return Uint8List.fromList([...i2os(s.r), ...i2os(s.s)]);
  }

  Uint8List _bytes(int n) => Uint8List.fromList(List<int>.generate(n, (_) => _random.nextInt(256)));

  static bool _eq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
