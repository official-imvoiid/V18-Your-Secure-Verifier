import 'package:flutter/material.dart';

import '../../app_state.dart';
import '../widgets.dart';
import 'country.dart';
import 'scan_code.dart';
import 'settings.dart';

/// HomeEmpty.dc.html, HomeActive.dc.html and ErrorExpired.dc.html
class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final cs = Theme.of(context).colorScheme;
    final card = app.card;
    final expired = card != null && card.isExpired(app.services.now());

    return Scaffold(
      body: SafeArea(
        child: Column(children: [
          SizedBox(
            height: 64,
            child: Row(children: [
              const Padding(padding: EdgeInsets.only(left: 20), child: V18Logo()),
              const Spacer(),
              IconButton(
                tooltip: 'Settings',
                icon: Icon(Icons.tune, color: cs.onSurfaceVariant),
                onPressed: () => Navigator.of(context)
                    .push(MaterialPageRoute(builder: (_) => const SettingsScreen())),
              ),
              const SizedBox(width: 8),
            ]),
          ),
          if (app.healthChecked && app.health == null)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
              child: InfoPanel(
                color: cs.surfaceContainerHigh,
                icon: Icons.cloud_off,
                iconColor: cs.onSurfaceVariant,
                child: Row(children: [
                  const Expanded(
                      child: Text("Can't reach the V18 server right now.",
                          style: TextStyle(fontSize: 14))),
                  TextButton(
                    style: TextButton.styleFrom(minimumSize: const Size(48, 40)),
                    onPressed: app.refreshHealth,
                    child: const Text('Retry'),
                  ),
                ]),
              ),
            ),
          Expanded(
            child: ListView(padding: const EdgeInsets.fromLTRB(16, 8, 16, 0), children: [
              if (card == null) ..._empty(context),
              if (card != null && expired) ..._expired(context),
              if (card != null && !expired) ..._active(context),
            ]),
          ),
          BottomActions(children: [
            if (card == null)
              FilledButton(
                onPressed: () => _openCountry(context),
                child: const Text('Get an age card'),
              ),
            if (card != null && expired) ...[
              FilledButton(
                onPressed: () => _openCountry(context),
                child: const Text('Renew age card'),
              ),
            ],
            if (card != null && !expired) ...[
              FilledButton.tonalIcon(
                style: FilledButton.styleFrom(
                    minimumSize: const Size.fromHeight(52), shape: const StadiumBorder()),
                onPressed: () => Navigator.of(context)
                    .push(MaterialPageRoute(builder: (_) => const ScanCodeScreen())),
                icon: const Icon(Icons.qr_code_scanner),
                label: const Text('Scan a website or PC code'),
              ),
              const SizedBox(height: 4),
              TextButton(
                onPressed: () => _openCountry(context),
                child: const Text('Renew or use another ID'),
              ),
            ],
          ]),
        ]),
      ),
    );
  }

  void _openCountry(BuildContext context) => Navigator.of(context)
      .push(MaterialPageRoute(builder: (_) => const CountryScreen()));

  List<Widget> _empty(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    Widget point(IconData i, String t, String s) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                  color: cs.secondaryContainer, borderRadius: BorderRadius.circular(12)),
              child: Icon(i, color: cs.onSecondaryContainer, size: 22),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(t, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w500)),
                Text(s, style: TextStyle(fontSize: 14, color: cs.onSurfaceVariant)),
              ]),
            ),
          ]),
        );
    return [
      Container(
        height: 190,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(28),
          border: Border.all(color: cs.outlineVariant, width: 2),
        ),
        alignment: Alignment.center,
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(Icons.badge_outlined, size: 40, color: cs.onSurfaceVariant),
          const SizedBox(height: 8),
          Text('Your age card will show here', style: TextStyle(color: cs.onSurfaceVariant)),
        ]),
      ),
      const SizedBox(height: 24),
      Text('No age card yet', style: Theme.of(context).textTheme.headlineMedium),
      const SizedBox(height: 8),
      Text(
          'Make one once with your ID. It takes about 2 minutes and works on any site that uses V18.',
          style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
      const SizedBox(height: 20),
      Text('Why it\'s private',
          style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500, color: cs.primary)),
      const SizedBox(height: 4),
      point(Icons.phone_android, 'Your ID stays on this phone', "It's read here, then deleted."),
      point(Icons.check_circle_outline, 'Sites only see "18+ yes"', 'No name, birthday or photo.'),
      point(Icons.autorenew, 'Every ticket is new', "So sites can't link your visits."),
    ];
  }

  List<Widget> _active(BuildContext context) {
    final app = AppScope.of(context);
    final cs = Theme.of(context).colorScheme;
    return [
      AgeCardView(card: app.card!, expired: false),
      const SizedBox(height: 16),
      InfoPanel(
        color: cs.secondaryContainer,
        icon: Icons.shield_outlined,
        iconColor: cs.onSecondaryContainer,
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Nothing about you is stored',
              style: TextStyle(
                  fontSize: 16, fontWeight: FontWeight.w500, color: cs.onSecondaryContainer)),
          const SizedBox(height: 2),
          Text('No name, birthday, photo or ID number. Not on this phone, not on our servers.',
              style: TextStyle(fontSize: 14, height: 1.4, color: cs.onSecondaryContainer)),
        ]),
      ),
      Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Icon(Icons.history_toggle_off, color: cs.onSurfaceVariant),
          const SizedBox(width: 14),
          Expanded(
            child: Text("No history here. We don't keep a list of the sites you visit.",
                style: TextStyle(fontSize: 14, color: cs.onSurfaceVariant)),
          ),
        ]),
      ),
      if (app.settings.sharedDevice)
        Padding(
          padding: const EdgeInsets.only(top: 12),
          child: InfoPanel(
            icon: Icons.group_outlined,
            child: const Text(
                'Shared device mode is on. This card is kept only until the app is closed.'),
          ),
        ),
    ];
  }

  List<Widget> _expired(BuildContext context) {
    final app = AppScope.of(context);
    final cs = Theme.of(context).colorScheme;
    return [
      AgeCardView(card: app.card!, expired: true),
      const SizedBox(height: 24),
      Text('Your age card has expired', style: Theme.of(context).textTheme.headlineMedium),
      const SizedBox(height: 8),
      Text(
          'Age cards last a few months, so the check stays fresh. Scan your ID again to make a new one. It takes about 2 minutes.',
          style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
      const SizedBox(height: 16),
      InfoPanel(
        icon: Icons.info_outline,
        child: const Text(
            'No new tickets can be made until you renew. The old card held nothing about you.'),
      ),
    ];
  }
}
