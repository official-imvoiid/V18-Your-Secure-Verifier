import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:pointycastle/export.dart' as pc;

import '../api/v18_api.dart';
import '../crypto/b64.dart';

/// One Anon Aadhaar circuit file from `GET /v1/artifacts/manifest` (PROTOCOL 4c.1).
class ArtifactInfo {
  ArtifactInfo({required this.name, required this.sha256, required this.bytes, this.url, this.role});

  static ArtifactInfo? fromJson(Object? j) {
    if (j is! Map) return null;
    final name = j['name'];
    final sha = j['sha256'];
    if (name is! String || sha is! String || !RegExp(r'^[0-9a-f]{64}$').hasMatch(sha)) return null;
    if (!RegExp(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$').hasMatch(name)) return null;
    final bytes = j['bytes'];
    return ArtifactInfo(
      name: name,
      sha256: sha,
      bytes: bytes is num ? bytes.toInt() : null,
      url: j['url'] is String ? j['url'] as String : null,
      role: j['role'] is String ? j['role'] as String : null,
    );
  }

  final String name;
  final String sha256;
  final int? bytes;
  final String? url;
  final String? role;
}

/// The three files the phone needs to make an Aadhaar proof.
class AadhaarArtifacts {
  const AadhaarArtifacts({required this.wasm, required this.zkey, required this.vkey});
  final ArtifactInfo wasm;
  final ArtifactInfo zkey;
  final ArtifactInfo vkey;

  List<ArtifactInfo> get all => [wasm, zkey, vkey];

  int get totalBytes => all.fold(0, (a, f) => a + (f.bytes ?? 0));

  /// Picks the files by role (if the server sends roles), then by name.
  static AadhaarArtifacts? pick(List<ArtifactInfo> files) {
    ArtifactInfo? find(String role, bool Function(String) byName) {
      for (final f in files) {
        if (f.role == role) return f;
      }
      for (final f in files) {
        if (f.role == null && byName(f.name)) return f;
      }
      return null;
    }

    final wasm = find('witness_wasm', (n) => n.endsWith('.wasm'));
    final zkey = find('proving_key', (n) => n.endsWith('.zkey'));
    final vkey = find('verification_key', (n) => n == 'vkey.json');
    if (wasm == null || zkey == null || vkey == null) return null;
    return AadhaarArtifacts(wasm: wasm, zkey: zkey, vkey: vkey);
  }
}

/// Local copies of the files, all checked by SHA-256.
class AadhaarArtifactPaths {
  const AadhaarArtifactPaths({required this.wasm, required this.zkey, required this.vkey});
  final String wasm;
  final String zkey;
  final String vkey;
}

class ArtifactException implements Exception {
  const ArtifactException(this.message);
  final String message;
  @override
  String toString() => 'ArtifactException($message)';
}

/// Downloads the circuit files on first use, checks each one's SHA-256
/// against the server's manifest while it downloads, and keeps them in the
/// app's private storage. A file is only ever used under its own SHA-256
/// name, so a changed file on the server means a new download.
class ArtifactStore {
  ArtifactStore({required this.dir, http.Client? client}) : _client = client ?? http.Client();

  /// The app's private folder (path_provider in the app, a temp folder in tests).
  final Future<Directory> Function() dir;
  final http.Client _client;

  Future<Directory> _folder() async {
    final d = Directory('${(await dir()).path}${Platform.pathSeparator}aadhaar-artifacts');
    if (!d.existsSync()) d.createSync(recursive: true);
    return d;
  }

  /// `GET /v1/artifacts/manifest`. Accepts a JSON array or `{files: [...]}`.
  Future<AadhaarArtifacts> manifest(String server) async {
    final http.Response res;
    try {
      res = await _client
          .get(Uri.parse('$server/v1/artifacts/manifest'), headers: {'Accept': 'application/json'})
          .timeout(const Duration(seconds: 15));
    } on TimeoutException {
      throw const OfflineException('timeout');
    } on SocketException catch (e) {
      throw OfflineException(e.osError?.message);
    } on http.ClientException catch (e) {
      throw OfflineException(e.message);
    }
    if (res.statusCode == 404) {
      throw const ArtifactException("This V18 server doesn't offer the Aadhaar proof files.");
    }
    if (res.statusCode >= 400) {
      throw ArtifactException('The V18 server could not list the proof files (${res.statusCode}).');
    }
    final Object? j;
    try {
      j = jsonDecode(res.body);
    } on FormatException {
      throw const ArtifactException('The proof file list from the server was not readable.');
    }
    final list = j is List ? j : (j is Map && j['files'] is List ? j['files'] as List : const []);
    final files = list.map(ArtifactInfo.fromJson).whereType<ArtifactInfo>().toList();
    final picked = AadhaarArtifacts.pick(files);
    if (picked == null) {
      throw const ArtifactException('The V18 server has not set up the Aadhaar proof files yet.');
    }
    return picked;
  }

  File _fileFor(Directory d, ArtifactInfo a) =>
      File('${d.path}${Platform.pathSeparator}${a.sha256}-${a.name}');

  /// True when every file is already on the phone (checked by size; the
  /// SHA-256 was checked when it was saved).
  Future<bool> isCached(AadhaarArtifacts a) async {
    final d = await _folder();
    for (final f in a.all) {
      final file = _fileFor(d, f);
      if (!file.existsSync()) return false;
      if (f.bytes != null && file.lengthSync() != f.bytes) return false;
    }
    return true;
  }

  Uri _downloadUri(String server, ArtifactInfo a) {
    final base = Uri.parse('$server/v1/artifacts/');
    final u = a.url;
    if (u != null) {
      final resolved = base.resolve(u);
      // Same server, or any HTTPS host (the SHA-256 check protects the bytes).
      if (resolved.origin == base.origin || resolved.scheme == 'https') return resolved;
    }
    return base.resolve(Uri.encodeComponent(a.name));
  }

  /// Makes sure all files are on the phone. [onProgress] gets bytes done and
  /// bytes in total (total may be 0 if the server gave no sizes).
  Future<AadhaarArtifactPaths> ensure(
    String server,
    AadhaarArtifacts a, {
    void Function(int done, int total)? onProgress,
    bool Function()? cancelled,
  }) async {
    final d = await _folder();
    final total = a.totalBytes;
    var doneBefore = 0;
    for (final f in a.all) {
      final file = _fileFor(d, f);
      if (file.existsSync() && (f.bytes == null || file.lengthSync() == f.bytes)) {
        doneBefore += f.bytes ?? file.lengthSync();
        onProgress?.call(doneBefore, total);
        continue;
      }
      await _download(_downloadUri(server, f), f, file, (n) => onProgress?.call(doneBefore + n, total),
          cancelled);
      doneBefore += f.bytes ?? file.lengthSync();
    }
    // Remove old copies (files whose SHA-256 is no longer in the manifest).
    final keep = a.all.map((f) => _fileFor(d, f).path).toSet();
    for (final e in d.listSync()) {
      if (e is File && !keep.contains(e.path)) {
        try {
          e.deleteSync();
        } on Object {
          // Best effort.
        }
      }
    }
    return AadhaarArtifactPaths(
      wasm: _fileFor(d, a.wasm).path,
      zkey: _fileFor(d, a.zkey).path,
      vkey: _fileFor(d, a.vkey).path,
    );
  }

  Future<void> _download(Uri uri, ArtifactInfo a, File dest, void Function(int) onBytes,
      bool Function()? cancelled) async {
    final part = File('${dest.path}.part');
    if (part.existsSync()) part.deleteSync();
    final sha = pc.SHA256Digest();
    final req = http.Request('GET', uri);
    http.StreamedResponse res;
    try {
      res = await _client.send(req).timeout(const Duration(seconds: 30));
    } on TimeoutException {
      throw const OfflineException('timeout');
    } on SocketException catch (e) {
      throw OfflineException(e.osError?.message);
    } on http.ClientException catch (e) {
      throw OfflineException(e.message);
    }
    if (res.statusCode != 200) {
      throw ArtifactException('Downloading ${a.name} failed (${res.statusCode}).');
    }
    final sink = part.openWrite();
    var n = 0;
    try {
      await for (final chunk in res.stream.timeout(const Duration(seconds: 60))) {
        if (cancelled?.call() == true) throw const ArtifactException('Download cancelled.');
        final bytes = chunk is Uint8List ? chunk : Uint8List.fromList(chunk);
        sha.update(bytes, 0, bytes.length);
        sink.add(bytes);
        n += bytes.length;
        onBytes(n);
      }
    } on TimeoutException {
      await sink.close();
      part.deleteSync();
      throw const OfflineException('timeout');
    } on Object {
      await sink.close();
      if (part.existsSync()) part.deleteSync();
      rethrow;
    }
    await sink.flush();
    await sink.close();
    final out = Uint8List(32);
    sha.doFinal(out, 0);
    if (bytesToHex(out) != a.sha256 || (a.bytes != null && n != a.bytes)) {
      part.deleteSync();
      throw ArtifactException('${a.name} did not match its fingerprint (SHA-256), so it was thrown away.');
    }
    part.renameSync(dest.path);
  }

  /// Deletes every downloaded file (Settings > Free up space).
  Future<void> clear() async {
    final d = await _folder();
    if (d.existsSync()) d.deleteSync(recursive: true);
  }

  /// Bytes the files take on this phone.
  Future<int> usedBytes() async {
    final d = await _folder();
    var n = 0;
    for (final e in d.listSync()) {
      if (e is File) n += e.lengthSync();
    }
    return n;
  }
}
