import 'package:flutter/foundation.dart';

/// Production server URL, set at build time (PROTOCOL 4c.7):
///   flutter build apk --release --dart-define=V18_SERVER_URL=https://api.your-domain
/// The default is the protocol's placeholder until the project owns a domain.
/// Only an https origin is accepted; anything else falls back to the placeholder.
const String _builtServerUrl = String.fromEnvironment('V18_SERVER_URL', defaultValue: 'https://api.v18.example');
final String productionServerUrl = _validProductionUrl(_builtServerUrl);

String _validProductionUrl(String s) {
  final u = Uri.tryParse(s.trim());
  if (u == null || u.scheme != 'https' || u.host.isEmpty || u.hasQuery || u.hasFragment || u.userInfo.isNotEmpty) {
    return 'https://api.v18.example';
  }
  return u.hasPort ? 'https://${u.host}:${u.port}' : 'https://${u.host}';
}

/// Built-in server allowlist (PROTOCOL.md section 3.10).
///
/// Apps accept `server=` values only from this list. Debug builds also allow
/// the PC's dev server, as seen from a USB phone with `adb reverse`
/// (localhost) and from the Android emulator (10.0.2.2).
class ServerAllowlist {
  const ServerAllowlist(this.entries);

  factory ServerAllowlist.forBuild({bool debug = kDebugMode}) =>
      ServerAllowlist([
        if (debug) 'http://localhost:8080',
        if (debug) 'http://10.0.2.2:8080',
        productionServerUrl,
      ]);

  final List<String> entries;

  /// Returns the allowlisted server origin (no trailing slash, no /v1), or
  /// null if [raw] is not on the list.
  ///
  /// The protocol writes the base URL both as `http://localhost:8080/v1`
  /// (section 3) and `http://localhost:8080` (section 3.10), so a trailing
  /// `/v1` or `/` is accepted and removed. Anything else in the path, a
  /// query, a fragment or user info is refused.
  String? normalize(String? raw) {
    if (raw == null || raw.isEmpty) return null;
    final Uri uri;
    try {
      uri = Uri.parse(raw.trim());
    } on FormatException {
      return null;
    }
    if (!uri.hasScheme || uri.host.isEmpty) return null;
    if (uri.userInfo.isNotEmpty || uri.hasQuery || uri.hasFragment) {
      return null;
    }
    final path = uri.path;
    if (!(path.isEmpty || path == '/' || path == '/v1' || path == '/v1/')) {
      return null;
    }
    final origin = _origin(uri);
    return entries.contains(origin) ? origin : null;
  }

  bool allows(String? raw) => normalize(raw) != null;
}

String _origin(Uri uri) {
  final scheme = uri.scheme.toLowerCase();
  final host = uri.host.toLowerCase();
  final defaultPort = scheme == 'https' ? 443 : (scheme == 'http' ? 80 : -1);
  final port = uri.hasPort && uri.port != defaultPort ? ':${uri.port}' : '';
  return '$scheme://$host$port';
}

/// Normalizes a website origin (`scheme://host[:port]`). Returns null if it
/// is not a plain web origin. Plain http is allowed only for local test
/// sites in debug builds.
String? normalizeWebOrigin(String? raw, {bool debug = kDebugMode}) {
  if (raw == null || raw.isEmpty || raw.length > 300) return null;
  final Uri uri;
  try {
    uri = Uri.parse(raw.trim());
  } on FormatException {
    return null;
  }
  final scheme = uri.scheme.toLowerCase();
  if (scheme != 'https' && scheme != 'http') return null;
  if (uri.host.isEmpty || uri.userInfo.isNotEmpty) return null;
  if (uri.hasQuery || uri.hasFragment) return null;
  if (!(uri.path.isEmpty || uri.path == '/')) return null;
  if (scheme == 'http') {
    const localHosts = {'localhost', '127.0.0.1', '10.0.2.2'};
    final local = localHosts.contains(uri.host.toLowerCase()) ||
        uri.host.toLowerCase().endsWith('.localhost') ||
        uri.host.toLowerCase().endsWith('.test');
    if (!(debug && local)) return null;
  }
  return _origin(uri);
}

sealed class DeepLink {
  const DeepLink();
}

/// `v18://verify?session=<id>&origin=<urlenc>&challenge=<urlenc>&minAge=18&server=<urlenc base URL>`
class VerifyLink extends DeepLink {
  const VerifyLink({
    required this.sessionId,
    required this.origin,
    required this.challenge,
    required this.minAge,
    required this.server,
  });

  final String sessionId;

  /// Normalized web origin, shown to the user and put in the ticket.
  final String origin;
  final String challenge;
  final int minAge;

  /// Allowlisted server origin, without /v1.
  final String server;

  /// The host part of [origin], for display ("example-site.com").
  String get displayHost => Uri.parse(origin).host;
}

/// `v18://link?id=<linkId>&server=<urlenc>`
class LinkApprovalLink extends DeepLink {
  const LinkApprovalLink({required this.linkId, required this.server});
  final String linkId;
  final String server;
}

class DeepLinkError implements Exception {
  const DeepLinkError(this.reason, {this.serverNotAllowed = false});

  /// Plain-English reason, safe to show on screen.
  final String reason;
  final bool serverNotAllowed;

  @override
  String toString() => 'DeepLinkError($reason)';
}

final RegExp _idPattern = RegExp(r'^[A-Za-z0-9_-]{16,200}$');

/// Parses a `v18://` link from a deep link or a scanned QR code.
///
/// [defaultServer] is used when a verify link has no `server=` value.
/// Throws [DeepLinkError] if the link is not valid.
DeepLink parseDeepLink(
  String text, {
  required ServerAllowlist allowlist,
  String? defaultServer,
  bool debug = kDebugMode,
}) {
  final Uri uri;
  try {
    uri = Uri.parse(text.trim());
  } on FormatException {
    throw const DeepLinkError('This is not a V18 code.');
  }
  if (uri.scheme.toLowerCase() != 'v18') {
    throw const DeepLinkError('This is not a V18 code.');
  }
  final q = uri.queryParameters;
  final rawServer = q['server'];

  String server() {
    if (rawServer == null || rawServer.isEmpty) {
      final s = allowlist.normalize(defaultServer);
      if (s == null) {
        throw const DeepLinkError('This code has no V18 server.');
      }
      return s;
    }
    final s = allowlist.normalize(rawServer);
    if (s == null) {
      throw const DeepLinkError(
          'This code points to a server V18 does not trust.',
          serverNotAllowed: true);
    }
    return s;
  }

  switch (uri.host.toLowerCase()) {
    case 'verify':
      final session = q['session'] ?? '';
      if (!_idPattern.hasMatch(session)) {
        throw const DeepLinkError('The website code is missing its session.');
      }
      final origin = normalizeWebOrigin(q['origin'], debug: debug);
      if (origin == null) {
        throw const DeepLinkError('The website address in this code is not valid.');
      }
      final challenge = q['challenge'] ?? '';
      if (challenge.isEmpty ||
          challenge.length > 512 ||
          RegExp(r'[\x00-\x1F\x7F]').hasMatch(challenge)) {
        throw const DeepLinkError('The website code has no valid challenge.');
      }
      final minAge = int.tryParse(q['minAge'] ?? '');
      if (minAge == null || minAge < 1 || minAge > 99) {
        throw const DeepLinkError('The website code has no valid age.');
      }
      return VerifyLink(
        sessionId: session,
        origin: origin,
        challenge: challenge,
        minAge: minAge,
        server: server(),
      );
    case 'link':
      final id = q['id'] ?? '';
      if (!_idPattern.hasMatch(id)) {
        throw const DeepLinkError('The PC link code is not valid.');
      }
      if (rawServer == null || rawServer.isEmpty) {
        throw const DeepLinkError('The PC link code has no V18 server.');
      }
      return LinkApprovalLink(linkId: id, server: server());
    default:
      throw const DeepLinkError('This V18 code is not one this app knows.');
  }
}
