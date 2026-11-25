import 'package:flutter/material.dart';

import '../widgets.dart';

class _InfoPage extends StatelessWidget {
  const _InfoPage({required this.title, required this.children});
  final String title;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(),
        body: ListView(padding: const EdgeInsets.fromLTRB(24, 0, 24, 32), children: [
          Semantics(
              header: true,
              child: Text(title, style: Theme.of(context).textTheme.headlineMedium)),
          const SizedBox(height: 16),
          ...children,
        ]),
      );
}

Widget _heading(BuildContext context, String t) => Padding(
      padding: const EdgeInsets.only(top: 20, bottom: 8),
      child: Text(t,
          style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w500,
              color: Theme.of(context).colorScheme.primary)),
    );

Widget _bullet(IconData i, String t, {Color? color}) => Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(i, size: 22, color: color),
        const SizedBox(width: 12),
        Expanded(child: Text(t, style: const TextStyle(fontSize: 15, height: 1.4))),
      ]),
    );

/// PrivacyInfo.dc.html
class PrivacyInfoScreen extends StatelessWidget {
  const PrivacyInfoScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return _InfoPage(title: 'What we store', children: [
      InfoPanel(
        color: cs.errorContainer,
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Never stored, anywhere',
              style: TextStyle(fontWeight: FontWeight.w500, color: cs.onErrorContainer)),
          const SizedBox(height: 4),
          for (final t in const [
            'ID scans and photos',
            'Name, birthday, ID number',
            'Your face',
            'Which sites you visit',
          ])
            _bullet(Icons.block, t, color: cs.onErrorContainer),
        ]),
      ),
      _heading(context, 'On this phone only'),
      const Text(
          'Your age card, locked inside the phone\'s secure chip. Delete it any time in Settings.',
          style: TextStyle(fontSize: 15, height: 1.4)),
      const SizedBox(height: 8),
      Text(
          'Exactly what the app saves: the card ID, how it was made, its end date, the name of '
          'its lock key (the key itself stays in the secure chip), the server address and your '
          'settings. In shared device mode, not even the card is saved.',
          style: TextStyle(fontSize: 14, height: 1.4, color: cs.onSurfaceVariant)),
      _heading(context, 'Kept safely on our servers'),
      _bullet(Icons.key_outlined, 'Our signing keys, in a locked key vault'),
      _bullet(Icons.fingerprint, 'Anonymous codes that stop one ID making too many cards'),
      _bullet(Icons.account_balance_outlined, 'Government public keys, used to check seals'),
      _bullet(Icons.public, "Each country's age rules"),
      _bullet(Icons.bar_chart, 'Anonymous totals, like "1,200 passport checks today"'),
      const SizedBox(height: 16),
      InfoPanel(
        color: cs.secondaryContainer,
        child: Text('None of these can be linked back to you.',
            style: TextStyle(color: cs.onSecondaryContainer)),
      ),
    ]);
  }
}

/// HowSeals.dc.html
class HowSealsScreen extends StatelessWidget {
  const HowSealsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    Widget step(int n, String t, String b) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 10),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            CircleAvatar(
              radius: 16,
              backgroundColor: cs.primary,
              foregroundColor: cs.onPrimary,
              child: Text('$n', style: const TextStyle(fontWeight: FontWeight.w700)),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(t, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w500)),
                const SizedBox(height: 2),
                Text(b, style: TextStyle(fontSize: 14, height: 1.4, color: cs.onSurfaceVariant)),
              ]),
            ),
          ]),
        );
    return _InfoPage(title: 'How seals work', children: [
      Text('A seal is a maths stamp. Only its owner can make it. Anyone can check it.',
          style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
      const SizedBox(height: 16),
      Row(children: [
        Expanded(
          child: InfoPanel(
            color: cs.primaryContainer,
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Icon(Icons.key, color: cs.onPrimaryContainer),
              const SizedBox(height: 6),
              Text('Private key',
                  style: TextStyle(fontWeight: FontWeight.w500, color: cs.onPrimaryContainer)),
              Text('The secret stamp. Only the owner has it.',
                  style: TextStyle(fontSize: 13, color: cs.onPrimaryContainer)),
            ]),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: InfoPanel(
            color: cs.tertiaryContainer,
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Icon(Icons.visibility_outlined, color: cs.onTertiaryContainer),
              const SizedBox(height: 6),
              Text('Public key',
                  style: TextStyle(fontWeight: FontWeight.w500, color: cs.onTertiaryContainer)),
              Text('What the stamp looks like. Everyone can use it to check.',
                  style: TextStyle(fontSize: 13, color: cs.onTertiaryContainer)),
            ]),
          ),
        ),
      ]),
      const SizedBox(height: 8),
      step(1, 'The government seals your ID',
          "Your passport chip or Aadhaar QR carries a seal made with the issuer's private key."),
      step(2, 'Change one letter, the seal breaks',
          'So a changed birthday or a fake QR is caught at once.'),
      step(3, 'We seal your ticket without seeing it',
          "This is called a blind seal. Even we can't link a ticket back to you."),
      step(4, 'Each ticket works once',
          "Every check uses a fresh one-time number, like an OTP, so old tickets can't be reused."),
      const SizedBox(height: 8),
      InfoPanel(
        icon: Icons.dns_outlined,
        child: const Text(
            'Websites check our seal on their own server, so tickets work even if V18 is down.'),
      ),
    ]);
  }
}

/// Plain-English page about child accounts (linked from Settings).
class ChildAccountInfoScreen extends StatelessWidget {
  const ChildAccountInfoScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return _InfoPage(title: 'Child accounts', children: [
      Text("V18 should never make an 18+ ticket on a child's phone. Here is what Android lets an app see today.",
          style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
      _heading(context, 'What V18 can do now'),
      _bullet(Icons.fingerprint,
          'Ask for the phone owner\'s fingerprint, face unlock or PIN for every ticket.'),
      _bullet(Icons.timer_outlined, 'Keep every ticket short-lived (5 minutes) and single use.'),
      _bullet(Icons.group_outlined, 'Shared device mode: keep no card on a family phone.'),
      _heading(context, 'What Android does not tell apps (yet)'),
      _bullet(Icons.help_outline,
          'Whether the phone is a Google Family Link (child) account. Android has no public way for a normal app to ask this.'),
      _bullet(Icons.help_outline,
          "The user's age. Google's Play Age Signals service can give an age range, but only to apps installed from Google Play. V18 does not use it yet."),
      const SizedBox(height: 12),
      const NoticeBox(
          'Android does not tell apps about child accounts, so V18 cannot detect them. '
          'It never treats "unknown" as "adult": every ticket still needs the phone owner\'s unlock.',
          title: 'The limit today'),
      _heading(context, 'The honest limit'),
      const Text(
          "If a child knows the parent's PIN, or a parent unlocks the phone for them, no app can stop that.",
          style: TextStyle(fontSize: 15, height: 1.4)),
    ]);
  }
}
