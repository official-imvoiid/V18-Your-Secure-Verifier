import 'package:flutter/material.dart';

import '../storage/card_store.dart';
import 'theme.dart';

/// The V18 shield logo and word mark.
class V18Logo extends StatelessWidget {
  const V18Logo({super.key, this.size = 20});
  final double size;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Row(mainAxisSize: MainAxisSize.min, children: [
      Icon(Icons.verified_user, color: cs.primary, size: size * 1.4),
      const SizedBox(width: 8),
      Text.rich(
        TextSpan(children: [
          const TextSpan(text: 'V'),
          TextSpan(text: '18', style: TextStyle(color: cs.primary)),
        ]),
        style: TextStyle(fontSize: size, fontWeight: FontWeight.w700, letterSpacing: -0.2),
      ),
    ]);
  }
}

/// Orange strip shown on every screen while the app talks to a dev-mode
/// server (PROTOCOL 3.1).
class TestModeBanner extends StatelessWidget {
  const TestModeBanner({super.key});

  @override
  Widget build(BuildContext context) {
    final c = V18Colors.of(context);
    return Material(
      color: c.warningContainer,
      child: SafeArea(
        bottom: false,
        child: Semantics(
          label: 'Test mode. This app is talking to a test server. Cards made now are not real.',
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
            child: Row(children: [
              Icon(Icons.science_outlined, size: 18, color: c.onWarningContainer),
              const SizedBox(width: 8),
              Expanded(
                child: Text('TEST MODE · test server, cards are not real',
                    style: TextStyle(
                        color: c.onWarningContainer,
                        fontWeight: FontWeight.w700,
                        fontSize: 13,
                        letterSpacing: 0.4)),
              ),
            ]),
          ),
        ),
      ),
    );
  }
}

/// Small labelled chip: Most private, Checked on phone, Wallet, Login, Weaker, TEST.
class TagChip extends StatelessWidget {
  const TagChip(this.label, {super.key, required this.background, required this.foreground});
  final String label;
  final Color background;
  final Color foreground;

  @override
  Widget build(BuildContext context) => Container(
        height: 22,
        padding: const EdgeInsets.symmetric(horizontal: 8),
        decoration: BoxDecoration(color: background, borderRadius: BorderRadius.circular(6)),
        alignment: Alignment.center,
        child: Text(label,
            style: TextStyle(color: foreground, fontSize: 12, fontWeight: FontWeight.w500)),
      );
}

/// "Aadhaar QR · Step 1 of 3" header with a back button.
class StepTopBar extends StatelessWidget implements PreferredSizeWidget {
  const StepTopBar({super.key, required this.title, this.step, this.onBack});
  final String title;
  final String? step;
  final VoidCallback? onBack;

  @override
  Size get preferredSize => const Size.fromHeight(64);

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return SizedBox(
      height: 64,
      child: Row(children: [
        const SizedBox(width: 4),
        IconButton(
          tooltip: 'Back',
          icon: const Icon(Icons.arrow_back),
          onPressed: onBack ?? () => Navigator.of(context).maybePop(),
        ),
        const SizedBox(width: 4),
        Expanded(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w500)),
              if (step != null)
                Text(step!, style: TextStyle(fontSize: 13, color: cs.onSurfaceVariant)),
            ],
          ),
        ),
      ]),
    );
  }
}

/// A round icon followed by text, used in check lists.
class CheckRow extends StatelessWidget {
  const CheckRow(this.text, {super.key, this.state = CheckState.done, this.detail});
  final String text;
  final String? detail;
  final CheckState state;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final warn = V18Colors.of(context);
    final (IconData icon, Color bg, Color fg) = switch (state) {
      CheckState.done => (Icons.check, cs.primary, cs.onPrimary),
      CheckState.working => (Icons.more_horiz, cs.secondaryContainer, cs.onSecondaryContainer),
      CheckState.waiting => (Icons.circle_outlined, cs.surfaceContainerHigh, cs.onSurfaceVariant),
      CheckState.notChecked => (Icons.remove, warn.warningContainer, warn.onWarningContainer),
      CheckState.failed => (Icons.close, cs.errorContainer, cs.onErrorContainer),
    };
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Container(
          width: 28,
          height: 28,
          decoration: BoxDecoration(color: bg, shape: BoxShape.circle),
          child: state == CheckState.working
              ? Padding(
                  padding: const EdgeInsets.all(6),
                  child: CircularProgressIndicator(strokeWidth: 2.5, color: fg))
              : Icon(icon, size: 18, color: fg),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.only(top: 4),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(text, style: const TextStyle(fontSize: 16)),
              if (detail != null)
                Text(detail!,
                    style: TextStyle(fontSize: 13, height: 1.4, color: cs.onSurfaceVariant)),
            ]),
          ),
        ),
      ]),
    );
  }
}

enum CheckState { done, working, waiting, notChecked, failed }

/// Rounded info panel (the design's tinted boxes).
class InfoPanel extends StatelessWidget {
  const InfoPanel({
    super.key,
    required this.child,
    this.color,
    this.icon,
    this.iconColor,
    this.padding = const EdgeInsets.all(16),
  });
  final Widget child;
  final Color? color;
  final IconData? icon;
  final Color? iconColor;
  final EdgeInsets padding;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      width: double.infinity,
      padding: padding,
      decoration: BoxDecoration(
          color: color ?? cs.surfaceContainerLow, borderRadius: BorderRadius.circular(20)),
      child: icon == null
          ? child
          : Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Icon(icon, color: iconColor),
              const SizedBox(width: 14),
              Expanded(child: child),
            ]),
    );
  }
}

/// A clearly labelled warning box: TEST-only things and honest limits.
class NoticeBox extends StatelessWidget {
  const NoticeBox(this.text, {super.key, required this.title});
  final String title;
  final String text;

  @override
  Widget build(BuildContext context) {
    final w = V18Colors.of(context);
    return InfoPanel(
      color: w.warningContainer,
      icon: Icons.construction,
      iconColor: w.onWarningContainer,
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(title,
            style: TextStyle(
                fontWeight: FontWeight.w700, fontSize: 15, color: w.onWarningContainer)),
        const SizedBox(height: 4),
        Text(text, style: TextStyle(fontSize: 14, height: 1.4, color: w.onWarningContainer)),
      ]),
    );
  }
}

String methodLabel(String method) => switch (method) {
      'anon_aadhaar' => 'Aadhaar QR',
      'emrtd_attested' || 'passport_attested' => 'Chip document',
      'mynumber_attested' => 'My Number Card',
      'mdoc_app' => 'Wallet ID',
      'test_dev' => 'Test ID (not real)',
      _ when method.startsWith('connector:') => 'Login (${method.substring(10)})',
      _ => method,
    };

const _months = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
];

/// "8 Nov 2027"
String formatDate(DateTime d) {
  final l = d.toLocal();
  return '${l.day} ${_months[l.month - 1]} ${l.year}';
}

/// The teal age card from HomeActive / CardSaved / ErrorExpired.
class AgeCardView extends StatelessWidget {
  const AgeCardView({super.key, required this.card, required this.expired});
  final AgeCard card;
  final bool expired;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final bg = expired ? cs.surfaceContainerHighest : cs.primary;
    final fg = expired ? cs.onSurfaceVariant : cs.onPrimary;
    final test = card.method == 'test_dev';
    return Semantics(
      label: 'Age card, ${expired ? 'expired' : 'active'}, 18 plus, made with '
          '${methodLabel(card.method)}, ${expired ? 'ended' : 'valid until'} ${formatDate(card.validUntil)}',
      child: Container(
        padding: const EdgeInsets.all(22),
        decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(28)),
        child: Stack(children: [
          Positioned(
            right: -30,
            bottom: -40,
            child: Icon(Icons.shield, size: 180, color: fg.withValues(alpha: 0.10)),
          ),
          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(
                child: Text('AGE CARD',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                        color: fg, fontSize: 13, fontWeight: FontWeight.w500, letterSpacing: 0.8)),
              ),
              const SizedBox(width: 8),
              Flexible(
                child: Container(
                  height: 28,
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                  decoration: BoxDecoration(
                      color: expired ? cs.errorContainer : cs.onPrimary,
                      borderRadius: BorderRadius.circular(14)),
                  child: Row(mainAxisSize: MainAxisSize.min, children: [
                    Container(
                      width: 8,
                      height: 8,
                      decoration: BoxDecoration(
                          color: expired ? cs.onErrorContainer : cs.primary,
                          shape: BoxShape.circle),
                    ),
                    const SizedBox(width: 6),
                    Flexible(
                      child: Text(expired ? 'Expired' : (test ? 'Active · TEST' : 'Active'),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                              fontSize: 13,
                              fontWeight: FontWeight.w500,
                              color: expired ? cs.onErrorContainer : cs.primary)),
                    ),
                  ]),
                ),
              ),
            ]),
            const SizedBox(height: 18),
            Text('18+',
                style: TextStyle(
                    color: fg, fontSize: 72, height: 1, letterSpacing: -1)),
            const SizedBox(height: 18),
            Row(children: [
              Expanded(child: _kv('Made with', methodLabel(card.method), fg)),
              Expanded(
                  child: _kv(expired ? 'Ended' : 'Valid until', formatDate(card.validUntil), fg)),
            ]),
            const SizedBox(height: 18),
            Row(children: [
              Icon(Icons.lock_outline, size: 18, color: fg.withValues(alpha: 0.9)),
              const SizedBox(width: 8),
              Expanded(
                child: Text('Locked with your phone lock · in the secure chip',
                    style: TextStyle(fontSize: 13, color: fg.withValues(alpha: 0.9))),
              ),
            ]),
          ]),
        ]),
      ),
    );
  }

  Widget _kv(String k, String v, Color fg) =>
      Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(k, style: TextStyle(fontSize: 12, color: fg.withValues(alpha: 0.85))),
        Text(v, style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500, color: fg)),
      ]);
}

/// Bottom area with the main buttons.
class BottomActions extends StatelessWidget {
  const BottomActions({super.key, required this.children});
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 12, 24, 20),
          child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: children),
        ),
      );
}

/// Pops back to the home screen (the first route).
void goHome(BuildContext context) =>
    Navigator.of(context).popUntil((route) => route.isFirst);
