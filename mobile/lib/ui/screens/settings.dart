import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../../app_state.dart';
import '../../flows/flows.dart';
import '../widgets.dart';
import 'info_pages.dart';

/// Settings.dc.html
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  Future<void> _toggleShared(bool on) async {
    final app = AppScope.read(context);
    if (on && app.card != null) {
      final ok = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Turn on shared device mode?'),
          content: const Text(
              'Your age card will no longer be saved on this phone. It works until you close the app. '
              'To free its place on the server too, delete the card instead.'),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
            TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Turn on')),
          ],
        ),
      );
      if (ok != true) return;
    }
    await app.setSharedDevice(on);
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final cs = Theme.of(context).colorScheme;
    final card = app.card;
    Widget section(String t) => Padding(
          padding: const EdgeInsets.fromLTRB(24, 20, 24, 4),
          child: Text(t,
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500, color: cs.primary)),
        );
    void push(Widget w) => Navigator.of(context).push(MaterialPageRoute(builder: (_) => w));

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(children: [
        section('Age card'),
        if (card == null)
          const ListTile(
            leading: Icon(Icons.badge_outlined),
            title: Text('No age card on this phone'),
          )
        else ...[
          ListTile(
            leading: const Icon(Icons.event),
            title: const Text('Card validity'),
            subtitle: Text(
                'Valid until ${formatDate(card.validUntil)}. After this, you scan your ID again. '
                'The server sets how long a card lasts.'),
          ),
          const ListTile(
            leading: Icon(Icons.fingerprint),
            title: Text('Lock'),
            subtitle: Text('Fingerprint, face unlock or PIN. Your phone decides which.'),
          ),
          ListTile(
            leading: Icon(Icons.delete_outline, color: cs.error),
            title: Text('Delete age card', style: TextStyle(color: cs.error)),
            subtitle: const Text('Removes it from this phone and the server'),
            onTap: () => push(const DeleteCardScreen()),
          ),
        ],
        section('This phone'),
        SwitchListTile(
          secondary: const Icon(Icons.group_outlined),
          title: const Text('Shared device mode'),
          subtitle: const Text('Nothing is remembered. Every visit needs a fresh ID check.'),
          value: app.settings.sharedDevice,
          onChanged: _toggleShared,
        ),
        if (kDebugMode) ...[
          section('Server (debug builds only)'),
          RadioGroup<String>(
            groupValue: app.server,
            onChanged: (v) {
              if (v != null) app.setServer(v);
            },
            child: Column(children: [
              for (final s in app.allowlist.entries)
                RadioListTile<String>(
                  value: s,
                  title: Text(s),
                  subtitle: s == app.server
                      ? Text(!app.healthChecked
                          ? 'Checking…'
                          : app.health == null
                              ? "Can't reach it"
                              : app.devMode
                                  ? 'Reached · TEST MODE (dev server)'
                                  : 'Reached')
                      : null,
                ),
            ]),
          ),
          section('Test tools (debug builds only)'),
          SwitchListTile(
            secondary: const Icon(Icons.child_care),
            title: const Text('Pretend this is a child account'),
            subtitle: const Text('Shows the child-account screen. TEST only.'),
            value: app.services.checks.simulateChildAccount,
            onChanged: (v) => setState(() => app.services.checks.simulateChildAccount = v),
          ),
        ],
        section('Learn'),
        ListTile(
          leading: const Icon(Icons.privacy_tip_outlined),
          title: const Text("What we store, and what we don't"),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => push(const PrivacyInfoScreen()),
        ),
        ListTile(
          leading: const Icon(Icons.approval_outlined),
          title: const Text('How seals work'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => push(const HowSealsScreen()),
        ),
        ListTile(
          leading: const Icon(Icons.child_care),
          title: const Text('Child accounts'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => push(const ChildAccountInfoScreen()),
        ),
        Padding(
          padding: const EdgeInsets.all(24),
          child: Text('V18 keeps no name, birthday, photo or browsing history.',
              style: TextStyle(color: cs.onSurfaceVariant)),
        ),
      ]),
    );
  }
}

/// DeleteCard.dc.html
class DeleteCardScreen extends StatefulWidget {
  const DeleteCardScreen({super.key});

  @override
  State<DeleteCardScreen> createState() => _DeleteCardScreenState();
}

class _DeleteCardScreenState extends State<DeleteCardScreen> {
  bool _working = false;
  String? _problem;

  Future<void> _delete() async {
    final app = AppScope.read(context);
    final card = app.card;
    if (card == null) return;
    setState(() {
      _working = true;
      _problem = null;
    });
    try {
      await deleteCardEverywhere(app.services, card);
      await app.removeCardFromPhone();
      if (mounted) goHome(context);
    } on FlowFailure catch (f) {
      if (!mounted) return;
      setState(() {
        _working = false;
        _problem = f.kind == FailureKind.cancelled ? null : f.message;
      });
    }
  }

  Future<void> _removeLocally() async {
    await AppScope.read(context).removeCardFromPhone();
    if (mounted) goHome(context);
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            CircleAvatar(
              radius: 32,
              backgroundColor: cs.errorContainer,
              child: Icon(Icons.delete_outline, size: 34, color: cs.onErrorContainer),
            ),
            const SizedBox(height: 20),
            Text('Delete your age card?', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(
                "It will be removed from this phone and turned off on the server, and this can't be undone. "
                "To get tickets again, you'll need to scan your ID again.",
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            InfoPanel(
              icon: Icons.info_outline,
              child: const Text('Tickets you already sent still work until they expire.'),
            ),
            if (_problem != null) ...[
              const SizedBox(height: 12),
              InfoPanel(
                color: cs.errorContainer,
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(_problem!, style: TextStyle(color: cs.onErrorContainer)),
                  const SizedBox(height: 8),
                  Text(
                      'You can remove it from this phone only. It then stays active on the server until '
                      'it expires, and still counts toward your ID\'s card limit.',
                      style: TextStyle(color: cs.onErrorContainer)),
                  TextButton(
                    onPressed: _removeLocally,
                    child: const Text('Remove from this phone only'),
                  ),
                ]),
              ),
            ],
          ]),
        ),
        BottomActions(children: [
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: cs.error, foregroundColor: cs.onError),
            onPressed: _working ? null : _delete,
            child: Text(_working ? 'Deleting…' : 'Delete'),
          ),
          const SizedBox(height: 4),
          TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Cancel')),
        ]),
      ]),
    );
  }
}
