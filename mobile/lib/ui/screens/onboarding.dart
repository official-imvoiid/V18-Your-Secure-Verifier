import 'package:flutter/material.dart';

import '../../app_state.dart';
import '../widgets.dart';

/// Main.dc.html, Onboarding2.dc.html, Onboarding3.dc.html
class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final _pages = PageController();
  int _page = 0;

  Future<void> _finish() => AppScope.read(context).completeOnboarding();

  @override
  void dispose() {
    _pages.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final last = _page == 2;
    return Scaffold(
      body: SafeArea(
        child: Column(children: [
          SizedBox(
            height: 64,
            child: Row(children: [
              if (_page > 0)
                IconButton(
                  tooltip: 'Back',
                  icon: const Icon(Icons.arrow_back),
                  onPressed: () => _pages.previousPage(
                      duration: const Duration(milliseconds: 250), curve: Curves.easeOut),
                )
              else
                const Padding(padding: EdgeInsets.only(left: 20), child: V18Logo()),
              const Spacer(),
              if (!last) TextButton(onPressed: _finish, child: const Text('Skip')),
              const SizedBox(width: 8),
            ]),
          ),
          Expanded(
            child: PageView(
              controller: _pages,
              onPageChanged: (p) => setState(() => _page = p),
              children: const [_Welcome(), _Promise(), _HowItWorks()],
            ),
          ),
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            for (var i = 0; i < 3; i++)
              AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                margin: const EdgeInsets.all(4),
                width: i == _page ? 24 : 8,
                height: 8,
                decoration: BoxDecoration(
                  color: i == _page
                      ? Theme.of(context).colorScheme.primary
                      : Theme.of(context).colorScheme.outlineVariant,
                  borderRadius: BorderRadius.circular(4),
                ),
              ),
          ]),
          BottomActions(children: [
            FilledButton(
              onPressed: last
                  ? _finish
                  : () => _pages.nextPage(
                      duration: const Duration(milliseconds: 250), curve: Curves.easeOut),
              child: Text(last ? 'Get started' : 'Next'),
            ),
          ]),
        ]),
      ),
    );
  }
}

class _Page extends StatelessWidget {
  const _Page({required this.art, required this.title, required this.body});
  final Widget art;
  final String title;
  final String body;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
      art,
      const SizedBox(height: 28),
      Text(title, style: Theme.of(context).textTheme.headlineMedium),
      const SizedBox(height: 12),
      Text(body, style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
    ]);
  }
}

class _Welcome extends StatelessWidget {
  const _Welcome();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    Widget pill(String t, bool yes) => Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          decoration: BoxDecoration(
              color: cs.surfaceContainerLowest, borderRadius: BorderRadius.circular(16)),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Icon(yes ? Icons.check_circle : Icons.visibility_off,
                size: 16, color: yes ? cs.primary : cs.onSurfaceVariant),
            const SizedBox(width: 6),
            Text(t, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500)),
          ]),
        );
    return _Page(
      art: Container(
        height: 300,
        decoration:
            BoxDecoration(color: cs.primaryContainer, borderRadius: BorderRadius.circular(32)),
        child: Stack(alignment: Alignment.center, children: [
          Container(
            width: 190,
            height: 190,
            decoration: BoxDecoration(color: cs.surfaceContainerLowest, shape: BoxShape.circle),
            child: Icon(Icons.verified_user, size: 110, color: cs.primary),
          ),
          Positioned(top: 28, left: 20, child: pill('18+ yes', true)),
          Positioned(bottom: 40, left: 24, child: pill('Name hidden', false)),
          Positioned(bottom: 76, right: 18, child: pill('Birthday hidden', false)),
        ]),
      ),
      title: "Prove you're 18+ without saying who you are",
      body: 'Websites learn one thing: you are over 18. Not your name, your birthday or your face.',
    );
  }
}

class _Promise extends StatelessWidget {
  const _Promise();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    Widget row(IconData i, String t) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Row(children: [
            Icon(i, color: cs.onErrorContainer, size: 22),
            const SizedBox(width: 12),
            Expanded(
              child: Text(t,
                  style: TextStyle(
                      fontSize: 16,
                      color: cs.onErrorContainer,
                      decoration: TextDecoration.lineThrough)),
            ),
          ]),
        );
    return _Page(
      art: Container(
        padding: const EdgeInsets.all(22),
        decoration:
            BoxDecoration(color: cs.errorContainer, borderRadius: BorderRadius.circular(32)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('NEVER STORED, ANYWHERE',
              style: TextStyle(
                  fontSize: 13,
                  letterSpacing: 0.8,
                  fontWeight: FontWeight.w500,
                  color: cs.onErrorContainer)),
          const SizedBox(height: 8),
          row(Icons.badge_outlined, 'ID scans and photos'),
          row(Icons.person_outline, 'Name, birthday, ID number'),
          row(Icons.face_outlined, 'Your face'),
          row(Icons.history, 'Which sites you visit'),
        ]),
      ),
      title: 'We never keep your details',
      body: 'Your ID is read on this phone only. Just a proof leaves it. '
          'Not even V18 knows who you are.',
    );
  }
}

class _HowItWorks extends StatelessWidget {
  const _HowItWorks();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    Widget step(String when, String title, String body, IconData icon, Color bg, Color fg) =>
        Container(
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(24)),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Icon(icon, color: fg, size: 30),
            const SizedBox(width: 14),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(when,
                    style: TextStyle(
                        fontSize: 12, letterSpacing: 0.8, fontWeight: FontWeight.w500, color: fg)),
                Text(title,
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.w500, color: fg)),
                const SizedBox(height: 4),
                Text(body, style: TextStyle(fontSize: 14, height: 1.4, color: fg)),
              ]),
            ),
          ]),
        );
    return _Page(
      art: Column(children: [
        step('ONCE', 'Make an age card',
            'Scan your ID one time. The card stays locked on this phone for 6 to 12 months.',
            Icons.badge_outlined, cs.primaryContainer, cs.onPrimaryContainer),
        const SizedBox(height: 12),
        step('EVERY VISIT', 'Touch to get a ticket',
            'A site asks. You touch your fingerprint. It gets a one-time 18+ ticket.',
            Icons.fingerprint, cs.secondaryContainer, cs.onSecondaryContainer),
      ]),
      title: 'Two simple steps',
      body: "Each ticket is new and works once, so sites can't follow you around the web.",
    );
  }
}
