/// The country catalog from `GET /v1/catalog?platform=android` (PROTOCOL 4d.2).
///
/// The app has NO country list of its own: every country and method on the
/// "Where is your ID from?" and "Choose a way" screens comes from here, and the
/// server has already removed what this deployment does not support.
library;

/// How private a method is, best first (PROTOCOL 4d.1).
enum MethodPrivacy {
  zeroKnowledge('zero_knowledge'),
  onDevice('on_device'),
  wallet('wallet'),
  login('login'),
  estimate('estimate');

  const MethodPrivacy(this.wire);
  final String wire;

  static MethodPrivacy? parse(Object? s) {
    for (final p in values) {
      if (p.wire == s) return p;
    }
    return null;
  }
}

class CatalogMethod {
  CatalogMethod({
    required this.method,
    required this.label,
    required this.documents,
    required this.docTypes,
    required this.needs,
    required this.privacy,
  });

  static CatalogMethod? fromJson(Object? j) {
    if (j is! Map) return null;
    final method = j['method'];
    final label = j['label'];
    final privacy = MethodPrivacy.parse(j['privacy']);
    if (method is! String || label is! String || privacy == null) return null;
    List<String> strings(Object? v) => v is List ? v.whereType<String>().toList() : const [];
    return CatalogMethod(
      method: method,
      label: label,
      documents: strings(j['documents']),
      docTypes: strings(j['docTypes']),
      needs: strings(j['needs']),
      privacy: privacy,
    );
  }

  /// `anon_aadhaar`, `emrtd_attested`, `mdoc_app`, `connector:singpass`, ...
  final String method;
  final String label;
  final List<String> documents;

  /// First MRZ letters for chip documents: P, I, A, C.
  final List<String> docTypes;
  final List<String> needs;
  final MethodPrivacy privacy;

  bool get isConnector => method.startsWith('connector:');
  String? get connectorId => isConnector ? method.substring('connector:'.length) : null;
}

class CatalogCountry {
  CatalogCountry({required this.code, required this.name, required this.region, required this.methods});

  static CatalogCountry? fromJson(Object? j) {
    if (j is! Map) return null;
    final code = j['code'];
    final name = j['name'];
    if (code is! String || name is! String || !RegExp(r'^[A-Z]{2}$').hasMatch(code)) return null;
    final methods = (j['methods'] is List ? j['methods'] as List : const [])
        .map(CatalogMethod.fromJson)
        .whereType<CatalogMethod>()
        .toList();
    return CatalogCountry(code: code, name: name, region: j['region'] as String? ?? '', methods: methods);
  }

  final String code;
  final String name;
  final String region;
  final List<CatalogMethod> methods;
}

class Catalog {
  Catalog(this.countries);

  factory Catalog.fromJson(Map<String, dynamic> j) {
    final list = j['countries'] is List ? j['countries'] as List : const [];
    final cs = list.map(CatalogCountry.fromJson).whereType<CatalogCountry>().toList()
      ..sort((a, b) => a.name.compareTo(b.name));
    return Catalog(cs);
  }

  final List<CatalogCountry> countries;

  CatalogCountry? byCode(String? code) {
    if (code == null) return null;
    for (final c in countries) {
      if (c.code == code.toUpperCase()) return c;
    }
    return null;
  }
}

/// What THIS app build can really do. A catalog method this app cannot do is
/// never shown (PROTOCOL 4c: everything visible works).
class AppCapabilities {
  const AppCapabilities({
    required this.aadhaarProver,
    required this.nfc,
    required this.digitalCredentials,
    required this.customTabs,
    this.faceModel = false,
    this.myNumber = false,
  });

  /// The native Anon Aadhaar prover loads on this phone.
  final bool aadhaarProver;

  /// The phone has NFC hardware (chip documents).
  final bool nfc;

  /// Android Credential Manager can ask other wallets for a digital credential.
  final bool digitalCredentials;

  /// A browser for login connectors.
  final bool customTabs;

  /// A face model that meets PROTOCOL 4c.6 is bundled. False in v1:
  /// No face model meets PROTOCOL.md 4c.6 in v1.
  final bool faceModel;

  /// The My Number Card (JPKI) reader is built in.
  final bool myNumber;

  /// Null if the method can be offered, else why not (plain English).
  /// Methods this app does not know at all return '' and are hidden.
  String? whyNot(CatalogMethod m) {
    switch (m.method) {
      case 'anon_aadhaar':
        return aadhaarProver ? null : "This phone can't run the Aadhaar proof (it needs a 64-bit phone).";
      case 'emrtd_attested':
      case 'passport_attested':
        return nfc ? null : 'This phone has no NFC, so it cannot read a chip.';
      case 'mynumber_attested':
        if (!myNumber) return '';
        return nfc ? null : 'This phone has no NFC, so it cannot read a chip.';
      case 'mdoc_app':
        return digitalCredentials ? null : "This phone can't share wallet IDs with apps yet.";
      case 'face_estimate':
        return faceModel ? null : '';
      default:
        if (m.isConnector) return customTabs ? null : 'This phone has no browser for the login.';
        // philsys_qr_attested and anything new: not built into this app.
        return '';
    }
  }

  /// The methods to show for [c], best privacy first. Hidden ones are left out.
  List<CatalogMethod> visible(CatalogCountry c) {
    final out = c.methods.where((m) => whyNot(m) != '').toList();
    // Stable sort by privacy rank (4d.1), keeping the catalog's order inside a rank.
    final indexed = [for (var i = 0; i < out.length; i++) (i, out[i])];
    indexed.sort((a, b) {
      final r = a.$2.privacy.index.compareTo(b.$2.privacy.index);
      return r != 0 ? r : a.$1.compareTo(b.$1);
    });
    return [for (final e in indexed) e.$2];
  }
}
