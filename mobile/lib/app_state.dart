import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';

import 'package:path_provider/path_provider.dart';

import 'aadhaar/anon_aadhaar.dart';
import 'aadhaar/artifacts.dart';
import 'dart:async';

import 'aadhaar/native_prover.dart';
import 'catalog/catalog.dart';
import 'device/wallet.dart';
import 'flows/connect.dart';
import 'package:flutter/services.dart' show rootBundle;

import 'passport/chip_reader.dart';
import 'passport/csca.dart';
import 'api/v18_api.dart';
import 'flows/flows.dart';
import 'protocol/deep_links.dart';
import 'storage/card_store.dart';

/// App-wide state: settings, the age card (if any) and the server's health.
class AppState extends ChangeNotifier {
  AppState({
    required this.store,
    required this.services,
    ServerAllowlist? allowlist,
    AnonAadhaarProver? prover,
    ArtifactStore? artifacts,
    AppCapabilities? capabilities,
    this.chipReaderFactory,
    DigitalCredentials? wallet,
  })  : _fixedCaps = capabilities,
        wallet = wallet ?? AndroidDigitalCredentials(),
        allowlist = allowlist ?? ServerAllowlist.forBuild(),
        prover = prover ?? NativeAnonAadhaarProver(cacheDir: getApplicationCacheDirectory),
        artifacts = artifacts ?? ArtifactStore(dir: getApplicationSupportDirectory);

  final CardStore store;
  final V18Services services;
  final ServerAllowlist allowlist;
  final AnonAadhaarProver prover;

  /// The Anon Aadhaar circuit files, downloaded on first use (PROTOCOL 4c.1).
  final ArtifactStore artifacts;

  final AppCapabilities? _fixedCaps;

  /// Android Credential Manager (mdoc_app).
  final DigitalCredentials wallet;

  final StreamController<String> _connectReturns = StreamController<String>.broadcast();

  /// `state` values from `v18://connect` links (login connectors, 4d.4).
  Stream<String> get connectReturns => _connectReturns.stream;

  /// Called for every `v18://connect` link. Only tells the waiting login
  /// screen to look up its result on the server.
  void onConnectReturn(Uri uri) {
    final st = connectReturnState(uri);
    if (st != null) _connectReturns.add(st);
  }
  /// Tests and the emulator run pass a TEST chip here; null means NFC.
  final ChipReader Function(AppState app)? chipReaderFactory;

  /// The chip reader (NFC). Tests and the emulator run pass a TEST chip instead.
  ChipReader chipReader() =>
      chipReaderFactory?.call(this) ?? ChipReader(trust: cscaTrust, now: services.now);

  /// Countries trusted for chip documents: the bundled BSI CSCA master list.
  /// The V18 TEST CSCA (assets/csca/test/) is added ONLY when the server is in
  /// dev mode, like the Anon Aadhaar TEST key.
  Future<CscaTrust> cscaTrust() async {
    final real = await CscaTrust.bundled();
    if (!devMode) return real;
    final data = await rootBundle.load(testCscaAsset);
    final test = X509.fromBytes(data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes));
    return CscaTrust([...real.all, test]);
  }

  static const String testCscaAsset = 'assets/csca/test/v18-test-csca.der';
  AppCapabilities? _caps;

  /// What this phone and app build can do (decides which catalog methods show).
  AppCapabilities get capabilities =>
      _fixedCaps ??
      _caps ??
      AppCapabilities(aadhaarProver: prover.available, nfc: false, digitalCredentials: false, customTabs: true);

  /// The country catalog from the server (PROTOCOL 4d.2), once loaded.
  Catalog? catalog;
  String? _catalogServer;

  AppSettings settings = const AppSettings();
  AgeCard? card;
  ServerHealth? health;
  bool healthChecked = false;
  bool loaded = false;

  /// Default server: the emulator's view of the PC in debug builds, the
  /// production placeholder in release builds.
  String get defaultServer => kDebugMode ? 'http://10.0.2.2:8080' : productionServerUrl;

  String get server => allowlist.normalize(settings.server) ?? defaultServer;

  /// True when the server says it is in dev mode: show the TEST MODE banner.
  bool get devMode => health?.devMode == true;

  V18Api get api => services.apiFor(server);

  bool get hasActiveCard => card != null && !card!.isExpired(services.now());

  Future<void> load() async {
    settings = await store.loadSettings();
    if (settings.sharedDevice) {
      // Shared-device mode stores no card at all (PROTOCOL 3.10).
      await store.deleteCard();
      try {
        await services.keys.deleteAllKeys();
      } on Object {
        // Best effort.
      }
      card = null;
    } else {
      card = await store.loadCard();
    }
    if (_fixedCaps == null) {
      _caps = AppCapabilities(
        aadhaarProver: prover.available,
        nfc: await services.checks.hasNfc(),
        digitalCredentials: await services.checks.hasDigitalCredentials(),
        customTabs: true,
      );
    }
    loaded = true;
    notifyListeners();
    await refreshHealth();
  }

  /// GET /v1/catalog?platform=android. Kept in memory for this server.
  Future<Catalog> loadCatalog({bool force = false}) async {
    if (!force && catalog != null && _catalogServer == server) return catalog!;
    final c = Catalog.fromJson(await api.catalog(platform: 'android'));
    catalog = c;
    _catalogServer = server;
    notifyListeners();
    return c;
  }

  Future<void> refreshHealth() async {
    try {
      health = await api.health();
    } on Object {
      health = null;
    }
    healthChecked = true;
    notifyListeners();
  }

  Future<void> completeOnboarding() async {
    settings = settings.copyWith(onboarded: true);
    await store.saveSettings(settings);
    notifyListeners();
  }

  Future<void> setServer(String server) async {
    final s = allowlist.normalize(server);
    if (s == null) return;
    settings = settings.copyWith(server: s);
    await store.saveSettings(settings);
    health = null;
    healthChecked = false;
    catalog = null;
    notifyListeners();
    await refreshHealth();
  }

  /// Saves a new card. In shared-device mode it lives in memory only and is
  /// gone when the app closes.
  Future<void> saveCard(AgeCard newCard) async {
    final old = card;
    card = newCard;
    if (!settings.sharedDevice) await store.saveCard(newCard);
    if (old != null && old.keyAlias != newCard.keyAlias) {
      try {
        await services.keys.deleteKey(old.keyAlias);
      } on Object {
        // Best effort.
      }
    }
    notifyListeners();
  }

  /// Removes the card and its key from this phone only.
  Future<void> removeCardFromPhone() async {
    final c = card;
    card = null;
    await store.deleteCard();
    if (c != null) {
      try {
        await services.keys.deleteKey(c.keyAlias);
      } on Object {
        // Best effort.
      }
    }
    notifyListeners();
  }

  Future<void> setSharedDevice(bool on) async {
    settings = settings.copyWith(sharedDevice: on);
    await store.saveSettings(settings);
    if (on) {
      // Nothing may stay stored. A card made now is kept in memory only.
      await store.deleteCard();
    } else if (card != null) {
      await store.saveCard(card!);
    }
    notifyListeners();
  }
}

class AppScope extends InheritedNotifier<AppState> {
  const AppScope({super.key, required AppState state, required super.child})
      : super(notifier: state);

  static AppState of(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<AppScope>()!.notifier!;

  static AppState read(BuildContext context) =>
      context.getInheritedWidgetOfExactType<AppScope>()!.notifier!;
}
