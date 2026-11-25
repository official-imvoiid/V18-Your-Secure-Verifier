import 'dart:async';

import 'package:flutter/material.dart';

import 'app_state.dart';
import 'ui/screens/home.dart';
import 'ui/screens/onboarding.dart';
import 'ui/screens/scan_code.dart';
import 'ui/theme.dart';
import 'ui/widgets.dart';

class V18App extends StatefulWidget {
  const V18App({super.key, required this.state, this.links});

  final AppState state;

  /// Incoming `v18://` deep links (app_links in the real app).
  final Stream<Uri>? links;

  @override
  State<V18App> createState() => _V18AppState();
}

class _V18AppState extends State<V18App> {
  final _nav = GlobalKey<NavigatorState>();
  StreamSubscription<Uri>? _sub;
  final List<String> _pending = [];

  @override
  void initState() {
    super.initState();
    _sub = widget.links?.listen((uri) {
      // A login connector coming back: the open login screen handles it.
      if (uri.scheme == 'v18' && uri.host == 'connect') {
        widget.state.onConnectReturn(uri);
        return;
      }
      _pending.add(uri.toString());
      _drain();
    });
    widget.state.addListener(_drain);
  }

  @override
  void dispose() {
    _sub?.cancel();
    widget.state.removeListener(_drain);
    super.dispose();
  }

  bool _drainScheduled = false;

  /// Opens queued deep links once the app has loaded its settings.
  void _drain() {
    if (!widget.state.loaded || _pending.isEmpty || _drainScheduled) return;
    _drainScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      _drainScheduled = false;
      final nav = _nav.currentState;
      if (!mounted || nav == null || _pending.isEmpty) return;
      if (!widget.state.settings.onboarded) {
        await widget.state.completeOnboarding();
      }
      final link = _pending.removeAt(0);
      nav.popUntil((r) => r.isFirst);
      await openV18Link(nav, widget.state, link);
      _drain();
    });
    // A post-frame callback alone does not ask for a frame. Without this, a
    // link that arrives while the app is idle would wait for the next redraw.
    WidgetsBinding.instance.ensureVisualUpdate();
  }

  @override
  Widget build(BuildContext context) {
    return AppScope(
      state: widget.state,
      child: ListenableBuilder(
        listenable: widget.state,
        builder: (context, _) => MaterialApp(
          title: 'V18',
          debugShowCheckedModeBanner: false,
          navigatorKey: _nav,
          theme: v18Theme(Brightness.light),
          darkTheme: v18Theme(Brightness.dark),
          builder: (context, child) => Column(children: [
            if (widget.state.devMode) const TestModeBanner(),
            Expanded(
              child: widget.state.devMode
                  ? MediaQuery.removePadding(context: context, removeTop: true, child: child!)
                  : child!,
            ),
          ]),
          home: const _Root(),
        ),
      ),
    );
  }
}

class _Root extends StatelessWidget {
  const _Root();

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    if (!app.loaded) {
      return const Scaffold(body: Center(child: V18Logo(size: 28)));
    }
    if (!app.settings.onboarded) return const OnboardingScreen();
    return const HomeScreen();
  }
}
