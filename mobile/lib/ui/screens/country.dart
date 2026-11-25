import 'dart:io' show Platform;

import 'package:flutter/material.dart';

import '../../app_state.dart';
import '../../catalog/catalog.dart';
import '../../flows/flows.dart';
import '../theme.dart';
import '../widgets.dart';
import 'aadhaar.dart';
import 'connector.dart';
import 'passport.dart';
import 'test_card.dart';
import 'wallet_id.dart';

/// Country.dc.html. Every country comes from the server's catalog
/// (GET /v1/catalog?platform=android, PROTOCOL 4d.2). Nothing is hard-coded.
class CountryScreen extends StatefulWidget {
  const CountryScreen({super.key});

  @override
  State<CountryScreen> createState() => _CountryScreenState();
}

class _CountryScreenState extends State<CountryScreen> {
  String _query = '';
  FlowFailure? _failure;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Future<void> _load() async {
    final app = AppScope.read(context);
    setState(() {
      _loading = true;
      _failure = null;
    });
    try {
      await app.loadCatalog();
    } on Object catch (e) {
      if (mounted) setState(() => _failure = FlowFailure.from(e));
    }
    if (mounted) setState(() => _loading = false);
  }

  /// The phone's region (for example "IN" from "en_IN"), if any.
  static String? phoneRegion() {
    try {
      final parts = Platform.localeName.split(RegExp(r'[_\-.]'));
      for (final p in parts.skip(1)) {
        if (RegExp(r'^[A-Z]{2}$').hasMatch(p)) return p;
      }
    } on Object {
      // No locale.
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final app = AppScope.of(context);
    final catalog = app.catalog;
    final caps = app.capabilities;
    Widget tile(CatalogCountry c) => ListTile(
          key: Key('country-${c.code}'),
          contentPadding: const EdgeInsets.symmetric(horizontal: 16),
          leading: CircleAvatar(
            backgroundColor: cs.secondaryContainer,
            foregroundColor: cs.onSecondaryContainer,
            child: Text(c.code, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
          ),
          title: Text(c.name, style: const TextStyle(fontSize: 16)),
          subtitle: Text(_summary(caps.visible(c))),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => Navigator.of(context)
              .push(MaterialPageRoute(builder: (_) => MethodsScreen(country: c))),
        );

    final children = <Widget>[
      Padding(
        padding: const EdgeInsets.fromLTRB(24, 0, 24, 4),
        child: Text('Where is your ID from?', style: Theme.of(context).textTheme.headlineMedium),
      ),
      Padding(
        padding: const EdgeInsets.fromLTRB(24, 0, 24, 12),
        child: Text("We'll show the ways that work there.",
            style: TextStyle(fontSize: 16, color: cs.onSurfaceVariant)),
      ),
    ];
    if (_loading && catalog == null) {
      children.add(const Padding(
          padding: EdgeInsets.all(32), child: Center(child: CircularProgressIndicator())));
    } else if (catalog == null) {
      children.add(Padding(
        padding: const EdgeInsets.symmetric(horizontal: 24),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          InfoPanel(
            color: cs.errorContainer,
            icon: Icons.cloud_off,
            iconColor: cs.onErrorContainer,
            child: Text(
                _failure?.kind == FailureKind.offline
                    ? "You're offline. Connect to the internet to see the ways to prove your age."
                    : "We couldn't get the list of countries from the V18 server. ${_failure?.message ?? ''}",
                style: TextStyle(color: cs.onErrorContainer)),
          ),
          const SizedBox(height: 12),
          FilledButton(onPressed: _load, child: const Text('Try again')),
        ]),
      ));
    } else {
      final shown = catalog.countries.where((c) => caps.visible(c).isNotEmpty || app.devMode).toList();
      final q = _query.trim().toLowerCase();
      final filtered = q.isEmpty
          ? shown
          : shown.where((c) => c.name.toLowerCase().contains(q) || c.code.toLowerCase() == q).toList();
      final suggested = catalog.byCode(phoneRegion());
      children.add(Padding(
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
        child: TextField(
          key: const Key('country-search'),
          decoration: const InputDecoration(
              prefixIcon: Icon(Icons.search), hintText: 'Search countries', border: OutlineInputBorder()),
          onChanged: (v) => setState(() => _query = v),
        ),
      ));
      if (q.isEmpty && suggested != null && shown.contains(suggested)) {
        children
          ..add(_section(context, 'Suggested for this phone'))
          ..add(tile(suggested));
      }
      children.add(_section(context, q.isEmpty ? 'All countries' : 'Results'));
      children.addAll(filtered.map(tile));
      if (filtered.isEmpty) {
        children.add(Padding(
          padding: const EdgeInsets.all(24),
          child: Text('No country matches "$_query". V18 lists only the countries it can check.',
              style: TextStyle(color: cs.onSurfaceVariant)),
        ));
      }
    }
    children.add(const SizedBox(height: 24));
    return Scaffold(appBar: AppBar(), body: ListView(children: children));
  }

  static String _summary(List<CatalogMethod> ms) {
    if (ms.isEmpty) return 'Test card only (dev server)';
    final labels = ms.map((m) => m.label).toSet().toList();
    return labels.length <= 3 ? labels.join(' · ') : '${labels.take(3).join(' · ')} +${labels.length - 3}';
  }

  Widget _section(BuildContext context, String t) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 12, 24, 4),
        child: Text(t,
            style: TextStyle(
                fontSize: 14, fontWeight: FontWeight.w500, color: Theme.of(context).colorScheme.primary)),
      );
}

/// MethodsIndia / MethodsPhilippines / MethodsGermany .dc.html, built from
/// the catalog entry of [country], best privacy first (PROTOCOL 4d.1).
class MethodsScreen extends StatelessWidget {
  const MethodsScreen({super.key, required this.country});
  final CatalogCountry country;

  static IconData iconFor(CatalogMethod m) {
    if (m.isConnector) return Icons.login;
    return switch (m.method) {
      'anon_aadhaar' => Icons.qr_code_2,
      'emrtd_attested' || 'passport_attested' =>
        m.docTypes.contains('P') ? Icons.menu_book_outlined : Icons.badge_outlined,
      'mynumber_attested' => Icons.badge_outlined,
      'mdoc_app' => Icons.wallet_outlined,
      _ => Icons.verified_user_outlined,
    };
  }

  static String bodyFor(CatalogMethod m) {
    final docs = m.documents.isEmpty ? '' : ' Works with: ${m.documents.join(', ')}.';
    return switch (m.privacy) {
      MethodPrivacy.zeroKnowledge => 'Your phone makes a maths proof that says only "18+".$docs',
      MethodPrivacy.onDevice => m.needs.contains('nfc')
          ? 'Hold your phone on the document. Its chip is checked on this phone.$docs'
          : 'Checked on this phone. Only "18+" is sent.$docs',
      MethodPrivacy.wallet => 'Share only "over 18" from an ID in another wallet app on this phone.$docs',
      MethodPrivacy.login =>
        'Log in with ${m.label}. V18 sees your birth date for a moment, decides "18+", and keeps nothing.$docs',
      MethodPrivacy.estimate => 'An age estimate from your face, on this phone.$docs',
    };
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final cs = Theme.of(context).colorScheme;
    final warn = V18Colors.of(context);
    final methods = app.capabilities.visible(country);

    Widget tagFor(CatalogMethod m) => switch (m.privacy) {
          MethodPrivacy.zeroKnowledge =>
            TagChip('Most private', background: cs.primaryContainer, foreground: cs.onPrimaryContainer),
          MethodPrivacy.onDevice =>
            TagChip('Checked on phone', background: cs.secondaryContainer, foreground: cs.onSecondaryContainer),
          MethodPrivacy.wallet =>
            TagChip('Wallet', background: cs.secondaryContainer, foreground: cs.onSecondaryContainer),
          MethodPrivacy.login =>
            TagChip('Login', background: cs.surfaceContainerHigh, foreground: cs.onSurfaceVariant),
          MethodPrivacy.estimate =>
            TagChip('Weaker', background: warn.warningContainer, foreground: warn.onWarningContainer),
        };

    void push(Widget w) => Navigator.of(context).push(MaterialPageRoute(builder: (_) => w));

    VoidCallback? routeFor(CatalogMethod m) {
      if (m.isConnector) {
        return () => push(ConnectorScreen(connectorId: m.connectorId!, label: m.label, country: country.name));
      }
      return switch (m.method) {
        'anon_aadhaar' => () => push(const AadhaarScanScreen()),
        'emrtd_attested' || 'passport_attested' => () => push(PassportScanScreen(
              document: m.label,
              docTypes: m.docTypes.isEmpty ? const ['P'] : m.docTypes,
              method: m.method,
            )),
        'mdoc_app' => () => push(WalletIdScreen(label: m.label, documents: m.documents)),
        _ => null,
      };
    }

    final groups = <MethodPrivacy, List<CatalogMethod>>{};
    for (final m in methods) {
      groups.putIfAbsent(m.privacy, () => []).add(m);
    }

    String groupTitle(MethodPrivacy p) => switch (p) {
          MethodPrivacy.zeroKnowledge => 'Zero-knowledge proof',
          MethodPrivacy.onDevice => 'Chip or seal checked on this phone',
          MethodPrivacy.wallet => 'Wallet IDs',
          MethodPrivacy.login => 'Government and bank logins',
          MethodPrivacy.estimate => 'No ID',
        };

    return Scaffold(
      appBar: AppBar(),
      body: ListView(padding: const EdgeInsets.symmetric(horizontal: 16), children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(8, 0, 8, 12),
          child: Text('Choose a way to prove your age', style: Theme.of(context).textTheme.headlineMedium),
        ),
        Align(
          alignment: Alignment.centerLeft,
          child: Padding(
            padding: const EdgeInsets.only(left: 8),
            child: OutlinedButton.icon(
              style: OutlinedButton.styleFrom(
                  minimumSize: const Size(0, 36),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10))),
              onPressed: () => Navigator.of(context).pop(),
              icon: const Icon(Icons.public, size: 18),
              label: Text('${country.name} · Change'),
            ),
          ),
        ),
        for (final p in MethodPrivacy.values)
          if (groups[p] != null) ...[
            _label(context, groupTitle(p)),
            for (final m in groups[p]!)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: MethodTile(
                  key: Key('method-${m.method}-${m.docTypes.join()}'),
                  icon: iconFor(m),
                  title: m.label,
                  tag: tagFor(m),
                  body: app.capabilities.whyNot(m) ?? bodyFor(m),
                  onTap: app.capabilities.whyNot(m) == null ? routeFor(m) : null,
                ),
              ),
          ],
        if (methods.isEmpty)
          Padding(
            padding: const EdgeInsets.all(8),
            child: Text('This V18 server has no way to check an ID from ${country.name} on this phone yet.',
                style: TextStyle(color: cs.onSurfaceVariant)),
          ),
        if (app.devMode) ...[
          _label(context, 'Test only'),
          MethodTile(
            key: const Key('method-test_dev'),
            icon: Icons.science_outlined,
            iconBg: warn.warningContainer,
            iconFg: warn.onWarningContainer,
            title: 'Test ID',
            tag: TagChip('TEST', background: warn.warningContainer, foreground: warn.onWarningContainer),
            body: 'Makes a test card on the dev server. Not a real age check.',
            onTap: () => push(const TestCardScreen()),
          ),
        ],
        const SizedBox(height: 16),
        InfoPanel(
          color: cs.tertiaryContainer,
          icon: Icons.phone_android,
          iconColor: cs.onTertiaryContainer,
          child: Text('Whichever you pick, V18 never keeps your name, birth date or ID number.',
              style: TextStyle(color: cs.onTertiaryContainer)),
        ),
        const SizedBox(height: 24),
      ]),
    );
  }

  Widget _label(BuildContext context, String t) => Padding(
        padding: const EdgeInsets.fromLTRB(8, 16, 8, 8),
        child: Text(t,
            style: TextStyle(
                fontSize: 14, fontWeight: FontWeight.w500, color: Theme.of(context).colorScheme.primary)),
      );
}

class MethodTile extends StatelessWidget {
  const MethodTile({
    super.key,
    required this.icon,
    required this.title,
    required this.tag,
    required this.body,
    this.onTap,
    this.iconBg,
    this.iconFg,
  });

  final IconData icon;
  final String title;
  final Widget tag;
  final String body;
  final VoidCallback? onTap;
  final Color? iconBg;
  final Color? iconFg;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final enabled = onTap != null;
    return Material(
      color: enabled ? cs.surfaceContainerLow : Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
        side: enabled ? BorderSide.none : BorderSide(color: cs.outlineVariant),
      ),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(children: [
            Container(
              width: 48,
              height: 48,
              decoration: BoxDecoration(
                color: iconBg ?? (enabled ? cs.primaryContainer : cs.surfaceContainerHigh),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Icon(icon, color: iconFg ?? (enabled ? cs.onPrimaryContainer : cs.onSurfaceVariant)),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Wrap(spacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
                  Text(title,
                      style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w500,
                          color: enabled ? cs.onSurface : cs.onSurfaceVariant)),
                  tag,
                ]),
                const SizedBox(height: 2),
                Text(body, style: TextStyle(fontSize: 14, height: 1.4, color: cs.onSurfaceVariant)),
              ]),
            ),
            if (enabled) const Icon(Icons.chevron_right),
          ]),
        ),
      ),
    );
  }
}
