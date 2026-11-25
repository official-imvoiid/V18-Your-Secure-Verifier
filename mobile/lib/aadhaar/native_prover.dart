import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

import '../crypto/b64.dart';
import 'anon_aadhaar.dart';
import 'artifacts.dart';

typedef _ProveC = Pointer<Utf8> Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef _StageC = Uint32 Function();
typedef _StageDart = int Function();
typedef _FreeC = Void Function(Pointer<Utf8>);
typedef _FreeDart = void Function(Pointer<Utf8>);

/// The Rust prover in `libv18_prover.so` (mobile/native/v18_prover):
/// ark-circom runs the official witness program, ark-groth16 makes the
/// Groth16 proof with the official proving key, and the proof is checked
/// against the key's own verifying key before it comes back.
class NativeAnonAadhaarProver implements AnonAadhaarProver {
  NativeAnonAadhaarProver({this.libraryName = 'libv18_prover.so', this.cacheDir});

  final String libraryName;

  /// Where the compiled witness program is cached (app private storage).
  final Future<Directory> Function()? cacheDir;

  static String? _loadError;

  /// False on phones where the native prover cannot load (for example 32-bit phones).
  @override
  bool get available {
    try {
      DynamicLibrary.open(libraryName);
      return true;
    } on Object catch (e) {
      _loadError = e.toString();
      return false;
    }
  }

  String? get loadError => _loadError;

  @override
  Future<AnonAadhaarProof> prove(
    AnonAadhaarInputs inputs,
    AadhaarArtifactPaths files, {
    void Function(ProverStage stage)? onStage,
  }) async {
    final inputsJson = jsonEncode(inputs.circuitInputs);
    inputs.wipe();
    final lib = libraryName;
    final cache = (await cacheDir?.call())?.path;
    final stageLib = DynamicLibrary.open(lib);
    final stage = stageLib.lookupFunction<_StageC, _StageDart>('v18_aa_stage');
    var last = -1;
    final timer = Timer.periodic(const Duration(milliseconds: 200), (_) {
      final s = stage();
      if (s != last) {
        last = s;
        onStage?.call(ProverStage.fromCode(s));
      }
    });
    final String out;
    try {
      out = await _runInIsolate(lib, files.wasm, files.zkey, files.vkey, inputsJson, cache);
    } finally {
      timer.cancel();
    }
    final j = jsonDecode(out) as Map<String, dynamic>;
    if (j['error'] != null) {
      throw ProverFailed('The proof could not be made: ${j['error']}');
    }
    return AnonAadhaarProof.fromProver(j);
  }
}

/// Top level, so the closure sent to the isolate holds only these strings.
Future<String> _runInIsolate(
        String lib, String wasm, String zkey, String vkey, String inputs, String? cache) =>
    Isolate.run(() => _proveInIsolate(lib, wasm, zkey, vkey, inputs, cache));

String _proveInIsolate(
    String lib, String wasm, String zkey, String vkey, String inputs, String? cache) {
  final dl = DynamicLibrary.open(lib);
  final prove = dl.lookupFunction<_ProveC, _ProveC>('v18_aa_prove');
  final free = dl.lookupFunction<_FreeC, _FreeDart>('v18_free_string');
  final w = wasm.toNativeUtf8();
  final z = zkey.toNativeUtf8();
  final v = vkey.toNativeUtf8();
  final i = inputs.toNativeUtf8();
  final c = cache?.toNativeUtf8() ?? nullptr.cast<Utf8>();
  try {
    final r = prove(w, z, v, i, c);
    try {
      return r.toDartString();
    } finally {
      free(r);
    }
  } finally {
    // The inputs hold the QR data: overwrite before freeing.
    final bytes = i.cast<Uint8>();
    final n = inputs.length;
    for (var k = 0; k < n; k++) {
      bytes[k] = 0;
    }
    malloc.free(w);
    malloc.free(z);
    malloc.free(v);
    malloc.free(i);
    if (c != nullptr) malloc.free(c);
  }
}

/// Random proof id, like @anon-aadhaar/core's (it is not sent anywhere else).
String newProofId() => b64urlEncode(randomBytes(16));
