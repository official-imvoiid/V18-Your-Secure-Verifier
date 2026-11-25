import 'dart:async';

import 'package:flutter/material.dart';

import '../../app_state.dart';
import '../../device/device_key.dart';
import '../../flows/flows.dart';
import '../../storage/card_store.dart';
import '../widgets.dart';
import 'errors.dart';

/// SetLock.dc.html
///
/// Design change, on purpose: the design shows this AFTER the card is saved.
/// In the real protocol the device key must sign the card request
/// (PROTOCOL 3.4 "proof of possession"), so the lock is set up first.
class SetLockScreen extends StatefulWidget {
  const SetLockScreen({super.key, required this.methodTitle, required this.next});
  final String methodTitle;
  final WidgetBuilder next;

  @override
  State<SetLockScreen> createState() => _SetLockScreenState();
}

class _SetLockScreenState extends State<SetLockScreen> {
  LockStatus? _status;

  @override
  void initState() {
    super.initState();
    _check();
  }

  Future<void> _check() async {
    LockStatus s;
    try {
      s = await AppScope.read(context).services.keys.lockStatus();
    } on Object {
      s = LockStatus.unavailable;
    }
    if (mounted) setState(() => _status = s);
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    Widget option(IconData i, String t, String s) => ListTile(
          contentPadding: EdgeInsets.zero,
          leading: CircleAvatar(
              backgroundColor: cs.secondaryContainer,
              foregroundColor: cs.onSecondaryContainer,
              child: Icon(i)),
          title: Text(t, style: const TextStyle(fontWeight: FontWeight.w500)),
          subtitle: Text(s),
        );
    final ready = _status == LockStatus.ready;
    return Scaffold(
      appBar: StepTopBar(title: widget.methodTitle, step: 'Lock'),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Text('Lock your age card', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 12),
            Text(
                "Every ticket will need you to unlock it. If someone else picks up your phone, they can't use your card.",
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            option(Icons.fingerprint, 'Fingerprint', 'Fastest. Recommended'),
            option(Icons.face_outlined, 'Face unlock',
                "Only if your phone's face unlock is a strong (secure) one"),
            option(Icons.pin_outlined, 'Phone PIN', 'Your screen lock PIN or pattern (Android 11 and newer)'),
            const SizedBox(height: 8),
            Text('Your phone decides which of these it offers when you unlock.',
                style: TextStyle(fontSize: 13, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            if (_status != null && !ready)
              InfoPanel(
                color: cs.errorContainer,
                icon: Icons.lock_open,
                iconColor: cs.onErrorContainer,
                child: Text(
                    _status == LockStatus.noneEnrolled
                        ? 'This phone has no fingerprint, face unlock or screen lock set up. Add one in your phone settings, then come back.'
                        : "This phone's lock can't protect a V18 card.",
                    style: TextStyle(color: cs.onErrorContainer)),
              ),
            InfoPanel(
              icon: Icons.privacy_tip_outlined,
              child: const Text('Your fingerprint and face stay in the phone\'s own lock. V18 never sees them.'),
            ),
          ]),
        ),
        BottomActions(children: [
          FilledButton(
            key: const Key('turn-on-lock'),
            onPressed: ready
                ? () => Navigator.of(context)
                    .pushReplacement(MaterialPageRoute(builder: widget.next))
                : (_status == null ? null : _check),
            child: Text(ready ? 'Turn on lock' : (_status == null ? 'Checking…' : 'Check again')),
          ),
        ]),
      ]),
    );
  }
}

/// One line on the progress screen.
class IssueStep {
  const IssueStep(this.label, {this.alreadyDone = false});
  final String label;
  final bool alreadyDone;
}

/// Builds the method's `proof`. [report] updates the live line under the
/// current step (for example the prover's stage).
typedef ProgressProofBuilder = Future<Map<String, Object?>> Function(
    String challenge, String deviceKeyThumbprint, void Function(String detail) report);

/// AadhaarProof.dc.html / BuildProof.dc.html / SendProof.dc.html
///
/// Runs the real card-issue flow (PROTOCOL 3.5) and shows its steps.
class IssueProgressScreen extends StatefulWidget {
  const IssueProgressScreen({
    super.key,
    required this.methodTitle,
    required this.stepLabel,
    required this.method,
    required this.steps,
    required this.proofStepIndex,
    required this.buildProof,
    this.attest = false,
    this.title = 'Building your proof',
    this.intro = 'Your phone makes a proof that says only "18+". Your ID details never leave the phone.',
    this.waitNote = 'This can take a few seconds. Keep the app open.',
    this.doneTitle = 'Your age card is ready',
    this.doneBody = "It's saved in this phone's secure chip. Your ID data has been deleted.",
    this.doneExtra,
  });

  final String methodTitle;
  final String stepLabel;
  final String method;
  final List<IssueStep> steps;

  /// Which step is "making the proof"; the steps after it are "sending".
  final int proofStepIndex;
  final ProgressProofBuilder buildProof;

  /// Make the device key with Android key attestation (PROTOCOL 4c.3).
  final bool attest;
  final String title;
  final String intro;
  final String waitNote;
  final String doneTitle;
  final String doneBody;

  /// Extra line for the done screen, given how long the proof step took.
  final String? Function(Duration proofTime)? doneExtra;

  @override
  State<IssueProgressScreen> createState() => _IssueProgressScreenState();
}

class _IssueProgressScreenState extends State<IssueProgressScreen> {
  late int _current = widget.steps.indexWhere((s) => !s.alreadyDone);
  FlowFailure? _failure;
  String? _detail;
  final Stopwatch _proofClock = Stopwatch();
  Timer? _tick;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _run());
  }

  @override
  void dispose() {
    _tick?.cancel();
    super.dispose();
  }

  Future<void> _run() async {
    final app = AppScope.read(context);
    setState(() {
      _failure = null;
      _detail = null;
      _current = widget.steps.indexWhere((s) => !s.alreadyDone);
    });
    try {
      final card = await issueCard(
        app.services,
        server: app.server,
        method: widget.method,
        attest: widget.attest,
        buildProof: (challenge, thumb) async {
          if (mounted) setState(() => _current = widget.proofStepIndex);
          _proofClock
            ..reset()
            ..start();
          _tick?.cancel();
          _tick = Timer.periodic(const Duration(seconds: 1), (_) {
            if (mounted) setState(() {});
          });
          try {
            return await widget.buildProof(challenge, thumb, (d) {
              if (mounted) setState(() => _detail = d);
            });
          } finally {
            _proofClock.stop();
            _tick?.cancel();
            if (mounted) {
              setState(() {
                _detail = null;
                _current = widget.proofStepIndex + 1;
              });
            }
          }
        },
      );
      await app.saveCard(card);
      if (!mounted) return;
      Navigator.of(context).pushReplacement(MaterialPageRoute(
          builder: (_) => CardSavedScreen(
              card: card,
              title: widget.doneTitle,
              body: widget.doneBody,
              extra: widget.doneExtra?.call(_proofClock.elapsed))));
    } on FlowFailure catch (f) {
      if (!mounted) return;
      if (f.kind == FailureKind.proofFailed || f.kind == FailureKind.cancelled) {
        setState(() => _failure = f);
        return;
      }
      Navigator.of(context).pushReplacement(MaterialPageRoute(
          builder: (ctx) => errorScreenFor(ctx, f)));
    }
  }

  String _elapsed() {
    final s = _proofClock.elapsed.inSeconds;
    return s < 60 ? '$s s' : '${s ~/ 60} min ${s % 60} s';
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final f = _failure;
    return Scaffold(
      appBar: StepTopBar(title: widget.methodTitle, step: widget.stepLabel),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Text(widget.title, style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 12),
            Text(widget.intro,
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 20),
            for (var i = 0; i < widget.steps.length; i++)
              CheckRow(widget.steps[i].label,
                  state: _stateFor(i, f),
                  detail: i == widget.proofStepIndex &&
                          i == _current &&
                          f == null &&
                          _proofClock.isRunning
                      ? '${_detail ?? 'Working'} · ${_elapsed()}'
                      : null),
            const SizedBox(height: 16),
            if (f?.kind == FailureKind.proofFailed)
              InfoPanel(
                color: cs.errorContainer,
                icon: Icons.error_outline,
                iconColor: cs.onErrorContainer,
                child: Text('${f!.message} No card was made and nothing about you was sent.',
                    style: TextStyle(color: cs.onErrorContainer)),
              ),
            if (f?.kind == FailureKind.cancelled)
              InfoPanel(
                icon: Icons.lock_outline,
                child: Text(f!.message == 'Cancelled.'
                    ? 'You cancelled the unlock, so the card was not saved.'
                    : f.message),
              ),
            if (f == null)
              Text(widget.waitNote, style: TextStyle(fontSize: 14, color: cs.onSurfaceVariant)),
          ]),
        ),
        if (f != null)
          BottomActions(children: [
            if (f.kind == FailureKind.cancelled)
              FilledButton(onPressed: _run, child: const Text('Try again')),
            TextButton(onPressed: () => goHome(context), child: const Text('Back to home')),
          ]),
      ]),
    );
  }

  CheckState _stateFor(int i, FlowFailure? f) {
    if (widget.steps[i].alreadyDone || i < _current) return CheckState.done;
    if (i == _current) return f == null ? CheckState.working : CheckState.failed;
    return CheckState.waiting;
  }
}

/// CardSaved.dc.html / AadhaarDone.dc.html
class CardSavedScreen extends StatelessWidget {
  const CardSavedScreen(
      {super.key, required this.card, required this.title, required this.body, this.extra});
  final AgeCard card;
  final String title;
  final String body;
  final String? extra;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final app = AppScope.of(context);
    return Scaffold(
      body: SafeArea(
        child: Column(children: [
          Expanded(
            child: ListView(padding: const EdgeInsets.fromLTRB(24, 32, 24, 0), children: [
              CircleAvatar(
                radius: 32,
                backgroundColor: cs.primaryContainer,
                child: Icon(Icons.check, size: 36, color: cs.onPrimaryContainer),
              ),
              const SizedBox(height: 20),
              Text(title, style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 8),
              Text(body, style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
              if (extra != null) ...[
                const SizedBox(height: 8),
                Text(extra!, style: TextStyle(fontSize: 14, color: cs.onSurfaceVariant)),
              ],
              const SizedBox(height: 20),
              AgeCardView(card: card, expired: false),
              const SizedBox(height: 16),
              InfoPanel(
                color: cs.secondaryContainer,
                icon: Icons.lock_outline,
                iconColor: cs.onSecondaryContainer,
                child: Text(
                    app.settings.sharedDevice
                        ? 'Locked with your phone lock. Shared device mode is on, so this card is forgotten when the app closes.'
                        : 'Locked with your phone lock. Every ticket needs your fingerprint, face unlock or PIN.',
                    style: TextStyle(color: cs.onSecondaryContainer)),
              ),
            ]),
          ),
          BottomActions(children: [
            FilledButton(
                key: const Key('card-saved-done'),
                onPressed: () => goHome(context),
                child: const Text('Done')),
          ]),
        ]),
      ),
    );
  }
}
