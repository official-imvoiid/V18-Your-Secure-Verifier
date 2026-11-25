import 'package:app_links/app_links.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import 'api/v18_api.dart';
import 'app.dart';
import 'app_state.dart';
import 'device/device_key.dart';
import 'device/platform_checks.dart';
import 'flows/flows.dart';
import 'storage/card_store.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final client = http.Client();
  final state = AppState(
    store: CardStore(SecureKeyValueStore()),
    services: V18Services(
      keys: AndroidDeviceKeyService(),
      checks: PlatformChecks(),
      apiFor: (server) => V18Api(server, client: client),
    ),
  );
  runApp(V18App(state: state, links: AppLinks().uriLinkStream));
  state.load();
}
