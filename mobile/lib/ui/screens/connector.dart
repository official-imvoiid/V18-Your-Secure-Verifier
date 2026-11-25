import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../app_state.dart';
import '../../flows/connect.dart';
import '../../flows/flows.dart';
import '../widgets.dart';
import 'card_flow.dart';
import 'errors.dart';

/// Government or bank login (PROTOCOL 4d.4), shown only when the server's
/// catalog lists the connector (it does so only when its credentials are set).
/// The login page opens in a Custom Tab; V18 sees the birth date for a moment
/// on the server, decides "18+", and keeps nothing.
class ConnectorScreen extends StatefulWidget {
  const ConnectorScreen({super.key, required this.connectorId, required this.label, required this.country});
  final String connectorId;
  final String label;
  final String country;

  @override
  State<ConnectorScreen> createState() => _ConnectorScreenState();
}

class _ConnectorScreenState extends State<ConnectorScreen> with WidgetsBindingObserver {
  ConnectStart? _start;
  Timer? _poll;
  StreamSubscription<String>? _returns;
  bool _busy = false;
  bool _done = false;
  String? _message;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _poll?.cancel();
    _returns?.cancel();
    final s = _start;
    if (s != null && !_done) unawaited(abandonConnector(AppScope.read(context).services, s));
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Back from the Custom Tab: look at once (the link may not come).
    if (state == AppLifecycleState.resumed && _start != null) unawaited(_check());
  }

  Future<void> _begin() async {
    final app = AppScope.read(context);
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      final start = await startConnector(app.services,
          server: app.server, connectorId: widget.connectorId, debug: kDebugMode);
      _start = start;
      _returns = app.connectReturns.listen((state) {
        if (state == start.state) unawaited(_check());
      });
      _poll = Timer.periodic(const Duration(seconds: 3), (_) => _check());
      final opened = await launchUrl(start.authUrl, mode: LaunchMode.inAppBrowserView);
      if (!opened && mounted) setState(() => _message = "The login page couldn't be opened.");
    } on FlowFailure catch (f) {
      if (!mounted) return;
      if (f.kind == FailureKind.cancelled) {
        setState(() {
          _busy = false;
          _message = 'You cancelled the unlock, so the login did not start.';
        });
        return;
      }
      await Navigator.of(context).pushReplacement(MaterialPageRoute(builder: (ctx) => errorScreenFor(ctx, f)));
    }
  }

  bool _checking = false;

  Future<void> _check() async {
    final start = _start;
    if (start == null || _checking || _done || !mounted) return;
    _checking = true;
    final app = AppScope.read(context);
    try {
      if (app.services.now().isAfter(start.expiresAt)) {
        await _finish(ConnectResult(ConnectOutcome.expired));
        return;
      }
      final r = await checkConnector(app.services, server: app.server, start: start);
      if (r != null) await _finish(r);
    } on FlowFailure catch (f) {
      if (f.kind != FailureKind.offline && mounted) await _finish(ConnectResult(ConnectOutcome.error, code: f.message));
    } finally {
      _checking = false;
    }
  }

  Future<void> _finish(ConnectResult r) async {
    if (_done || !mounted) return;
    _done = true;
    _poll?.cancel();
    final app = AppScope.read(context);
    final start = _start!;
    try {
      await closeInAppWebView();
    } on Object {
      // Not open.
    }
    if (!mounted) return;
    switch (r.outcome) {
      case ConnectOutcome.ok:
        await app.saveCard(r.card!);
        if (!mounted) return;
        await Navigator.of(context).pushReplacement(MaterialPageRoute(
            builder: (_) => CardSavedScreen(
                card: r.card!,
                title: 'Done. Your age card is ready',
                body: 'V18 saw your birth date for a moment, decided "18+", and kept nothing else.')));
      case ConnectOutcome.underAge:
        await abandonConnector(app.services, start);
        if (!mounted) return;
        await Navigator.of(context).pushReplacement(MaterialPageRoute(builder: (ctx) => under18CardErrorScreen(ctx)));
      case ConnectOutcome.expired:
      case ConnectOutcome.error:
        await abandonConnector(app.services, start);
        if (!mounted) return;
        setState(() {
          _start = null;
          _busy = false;
          _done = false;
          _message = r.outcome == ConnectOutcome.expired
              ? 'The login took too long and ran out. Try again.'
              : "The login didn't work (${r.code ?? 'error'}). Try again.";
        });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final waiting = _start != null && !_done;
    return Scaffold(
      appBar: StepTopBar(title: widget.label, step: widget.country),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Text('Log in with ${widget.label}', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(
                'Your login page opens in the browser. The V18 server reads only your birth date (or "over 18") '
                'from it, decides, and forgets it at once. Nothing is stored about you.',
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            const CheckRow('You log in on the official page, not inside V18'),
            const CheckRow('V18 keeps no name, birth date or account number'),
            const CheckRow('Your age card is locked to this phone'),
            if (waiting) ...[
              const SizedBox(height: 16),
              const LinearProgressIndicator(),
              const SizedBox(height: 8),
              const Text('Waiting for the login to finish…'),
            ],
            if (_message != null) ...[
              const SizedBox(height: 16),
              InfoPanel(
                color: cs.errorContainer,
                icon: Icons.info_outline,
                iconColor: cs.onErrorContainer,
                child: Text(_message!, style: TextStyle(color: cs.onErrorContainer)),
              ),
            ],
          ]),
        ),
        BottomActions(children: [
          if (!waiting)
            FilledButton(
              key: const Key('connector-start'),
              onPressed: _busy ? null : _begin,
              child: Text('Log in with ${widget.label}'),
            )
          else
            OutlinedButton(
              onPressed: () => launchUrl(_start!.authUrl, mode: LaunchMode.inAppBrowserView),
              child: const Text('Open the login page again'),
            ),
        ]),
      ]),
    );
  }
}
