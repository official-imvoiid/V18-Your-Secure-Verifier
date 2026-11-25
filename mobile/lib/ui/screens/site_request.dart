import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app_state.dart';
import '../../flows/flows.dart';
import '../../protocol/deep_links.dart';
import '../../protocol/ticket.dart';
import '../../storage/card_store.dart';
import '../widgets.dart';
import 'country.dart';
import 'errors.dart';

const _ticketMinutes = maxTicketLifetimeSeconds ~/ 60;

/// SiteRequest.dc.html: "(site) asks: are you 18+?"
class SiteRequestScreen extends StatefulWidget {
  const SiteRequestScreen({super.key, required this.link});
  final VerifyLink link;

  @override
  State<SiteRequestScreen> createState() => _SiteRequestScreenState();
}

class _SiteRequestScreenState extends State<SiteRequestScreen> {
  bool _connecting = true;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _prepare());
  }

  Future<void> _prepare() async {
    final app = AppScope.read(context);
    final card = app.card;
    if (card == null) {
      setState(() => _connecting = false);
      return;
    }
    try {
      await preflightTicket(app.services, widget.link, card);
      await connectToSession(app.services, widget.link);
      if (mounted) setState(() => _connecting = false);
    } on FlowFailure catch (f) {
      if (!mounted) return;
      await Navigator.of(context).pushReplacement(MaterialPageRoute(
          builder: (ctx) => errorScreenFor(ctx, f,
              siteHost: widget.link.displayHost,
              onRetry: () => Navigator.of(ctx).pushReplacement(MaterialPageRoute(
                  builder: (_) => SiteRequestScreen(link: widget.link))))));
    }
  }

  Future<void> _dontSend() async {
    final app = AppScope.read(context);
    try {
      await app.services.apiFor(widget.link.server).pairingCancel(widget.link.sessionId);
    } on Object {
      // The website will time out on its own.
    }
    if (mounted) goHome(context);
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final cs = Theme.of(context).colorScheme;
    final link = widget.link;
    final card = app.card;
    final host = link.displayHost;
    final initial = host.isEmpty ? '?' : host[0].toUpperCase();

    return Scaffold(
      body: SafeArea(
        child: Column(children: [
          SizedBox(
            height: 64,
            child: Row(children: [
              const SizedBox(width: 4),
              IconButton(
                tooltip: 'Close and go back',
                icon: const Icon(Icons.close),
                onPressed: _dontSend,
              ),
              const Spacer(),
              const V18Logo(size: 16),
              const SizedBox(width: 20),
            ]),
          ),
          Expanded(
            child: ListView(padding: const EdgeInsets.fromLTRB(16, 8, 16, 0), children: [
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8),
                child: Row(children: [
                  Container(
                    width: 48,
                    height: 48,
                    alignment: Alignment.center,
                    decoration: BoxDecoration(
                        color: cs.tertiaryContainer, borderRadius: BorderRadius.circular(14)),
                    child: Text(initial,
                        style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.w700,
                            color: cs.onTertiaryContainer)),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Text(host, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w500)),
                      Text('${link.origin} asks:',
                          style: TextStyle(fontSize: 13, color: cs.onSurfaceVariant)),
                    ]),
                  ),
                ]),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(8, 14, 8, 20),
                child: Text('Are you ${link.minAge}+?',
                    style: Theme.of(context).textTheme.headlineLarge),
              ),
              if (card == null) ...[
                InfoPanel(
                  icon: Icons.badge_outlined,
                  child: const Text(
                      'You need an age card first. Make one with your ID, then scan the website code again.'),
                ),
              ] else ...[
                InfoPanel(
                  color: cs.secondaryContainer,
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text('THE SITE GETS',
                        style: TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w500,
                            letterSpacing: 0.4,
                            color: cs.onSecondaryContainer)),
                    const SizedBox(height: 12),
                    Row(children: [
                      CircleAvatar(
                          radius: 14,
                          backgroundColor: cs.primary,
                          child: Icon(Icons.check, size: 18, color: cs.onPrimary)),
                      const SizedBox(width: 12),
                      Text('${link.minAge}+: yes',
                          style: TextStyle(
                              fontSize: 17,
                              fontWeight: FontWeight.w500,
                              color: cs.onSecondaryContainer)),
                    ]),
                    const SizedBox(height: 12),
                    Text('As a one-time ticket that works once.',
                        style: TextStyle(fontSize: 14, color: cs.onSecondaryContainer)),
                  ]),
                ),
                const SizedBox(height: 12),
                InfoPanel(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text("THE SITE DOESN'T GET",
                        style: TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w500,
                            letterSpacing: 0.4,
                            color: cs.onSurfaceVariant)),
                    const SizedBox(height: 12),
                    LayoutBuilder(
                      builder: (context, box) => Wrap(runSpacing: 12, spacing: 8, children: [
                        for (final t in const ['Your name', 'Birthday', 'Photo', 'ID number'])
                          SizedBox(
                            // Two columns, like the design; one column if very narrow.
                            width: box.maxWidth >= 260 ? (box.maxWidth - 8) / 2 : box.maxWidth,
                            child: Row(children: [
                              CircleAvatar(
                                  radius: 12,
                                  backgroundColor: cs.errorContainer,
                                  child: Icon(Icons.close, size: 16, color: cs.onErrorContainer)),
                              const SizedBox(width: 10),
                              Expanded(child: Text(t, style: const TextStyle(fontSize: 15))),
                            ]),
                          ),
                      ]),
                    ),
                    const SizedBox(height: 12),
                    Text("It also can't tell who you are, or link this visit to other sites.",
                        style: TextStyle(fontSize: 14, color: cs.onSurfaceVariant)),
                  ]),
                ),
                Padding(
                  padding: const EdgeInsets.fromLTRB(8, 16, 8, 0),
                  child: Row(children: [
                    Icon(Icons.schedule, color: cs.onSurfaceVariant),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text('The ticket expires in $_ticketMinutes minutes.',
                          style: TextStyle(fontSize: 14, color: cs.onSurfaceVariant)),
                    ),
                  ]),
                ),
              ],
            ]),
          ),
          BottomActions(children: [
            if (card == null)
              FilledButton(
                onPressed: () => Navigator.of(context).pushReplacement(
                    MaterialPageRoute(builder: (_) => const CountryScreen())),
                child: const Text('Get an age card'),
              )
            else
              FilledButton.icon(
                onPressed: _connecting
                    ? null
                    : () => Navigator.of(context).push(MaterialPageRoute(
                        builder: (_) => FingerprintScreen(link: link, card: card))),
                icon: _connecting
                    ? const SizedBox(
                        width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.send),
                label: Text(_connecting ? 'Connecting…' : 'Send ${link.minAge}+ ticket'),
              ),
            const SizedBox(height: 4),
            TextButton(onPressed: _dontSend, child: const Text("Don't send")),
          ]),
        ]),
      ),
    );
  }
}

/// Fingerprint.dc.html. The real unlock is Android's own BiometricPrompt,
/// shown on top of this screen.
class FingerprintScreen extends StatefulWidget {
  const FingerprintScreen({super.key, required this.link, required this.card});
  final VerifyLink link;
  final AgeCard card;

  @override
  State<FingerprintScreen> createState() => _FingerprintScreenState();
}

class _FingerprintScreenState extends State<FingerprintScreen> {
  bool _working = false;
  String? _note;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _send());
  }

  Future<void> _send() async {
    if (_working) return;
    setState(() {
      _working = true;
      _note = null;
    });
    final app = AppScope.read(context);
    try {
      final sent = await sendTicket(app.services, widget.link, widget.card);
      if (!mounted) return;
      await Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(
            builder: (_) => TicketSentScreen(host: widget.link.displayHost, expiresAt: sent.expiresAt)),
        (r) => r.isFirst,
      );
    } on FlowFailure catch (f) {
      if (!mounted) return;
      if (f.kind == FailureKind.cancelled) {
        setState(() {
          _working = false;
          _note = f.message == 'Cancelled.' ? 'Not sent. Touch the button to try again.' : f.message;
        });
        return;
      }
      await Navigator.of(context).pushReplacement(MaterialPageRoute(
          builder: (ctx) => errorScreenFor(ctx, f, siteHost: widget.link.displayHost)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final host = widget.link.displayHost;
    return Scaffold(
      body: SafeArea(
        child: Column(children: [
          const SizedBox(height: 48),
          Text('$host asks:', style: TextStyle(color: cs.onSurfaceVariant)),
          Text('Are you ${widget.link.minAge}+?',
              style: Theme.of(context).textTheme.headlineMedium),
          const Spacer(),
          Container(
            margin: const EdgeInsets.all(16),
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
                color: cs.surfaceContainerHigh, borderRadius: BorderRadius.circular(28)),
            child: Column(children: [
              const V18Logo(size: 16),
              const SizedBox(height: 16),
              Text("Confirm it's you", style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 8),
              Text(
                  'Unlock with your fingerprint, face or PIN to send a one-time ${widget.link.minAge}+ ticket to $host.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: cs.onSurfaceVariant)),
              const SizedBox(height: 20),
              Semantics(
                button: true,
                label: 'Unlock to send the ticket',
                child: InkWell(
                  customBorder: const CircleBorder(),
                  onTap: _working ? null : _send,
                  child: CircleAvatar(
                    radius: 36,
                    backgroundColor: cs.primaryContainer,
                    child: _working
                        ? const CircularProgressIndicator()
                        : Icon(Icons.fingerprint, size: 44, color: cs.onPrimaryContainer),
                  ),
                ),
              ),
              if (_note != null) ...[
                const SizedBox(height: 12),
                Text(_note!, textAlign: TextAlign.center),
              ],
              const SizedBox(height: 8),
              TextButton(
                  onPressed: _working ? null : () => Navigator.of(context).pop(),
                  child: const Text('Cancel')),
            ]),
          ),
        ]),
      ),
    );
  }
}

/// TicketSent.dc.html
class TicketSentScreen extends StatelessWidget {
  const TicketSentScreen({super.key, required this.host, required this.expiresAt});
  final String host;
  final DateTime expiresAt;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    Widget line(IconData i, String t) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(children: [
            Icon(i, size: 20, color: cs.onPrimary),
            const SizedBox(width: 10),
            Expanded(child: Text(t, style: TextStyle(color: cs.onPrimary, fontSize: 15))),
          ]),
        );
    return Scaffold(
      body: SafeArea(
        child: Column(children: [
          Expanded(
            child: ListView(padding: const EdgeInsets.fromLTRB(24, 48, 24, 0), children: [
              CircleAvatar(
                radius: 32,
                backgroundColor: cs.primaryContainer,
                child: Icon(Icons.check, size: 36, color: cs.onPrimaryContainer),
              ),
              const SizedBox(height: 20),
              Text('Ticket sent', style: Theme.of(context).textTheme.headlineLarge),
              const SizedBox(height: 8),
              Text(
                  "$host got a one-time 18+ ticket. It can't tell who you are, or link this visit to any other.",
                  style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.all(22),
                decoration:
                    BoxDecoration(color: cs.primary, borderRadius: BorderRadius.circular(28)),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Text('TICKET',
                        style: TextStyle(
                            color: cs.onPrimary, letterSpacing: 0.8, fontWeight: FontWeight.w500)),
                    const Spacer(),
                    Text('18+',
                        style: TextStyle(
                            color: cs.onPrimary, fontSize: 28, fontWeight: FontWeight.w500)),
                  ]),
                  const SizedBox(height: 12),
                  line(Icons.looks_one_outlined, 'Works once'),
                  line(Icons.schedule, 'Expires in $_ticketMinutes minutes'),
                  line(Icons.history_toggle_off, 'Not saved in any history'),
                ]),
              ),
            ]),
          ),
          BottomActions(children: [
            FilledButton(
              onPressed: () => SystemNavigator.pop(),
              child: Text('Back to $host'),
            ),
            const SizedBox(height: 4),
            TextButton(onPressed: () => goHome(context), child: const Text('Done')),
          ]),
        ]),
      ),
    );
  }
}
