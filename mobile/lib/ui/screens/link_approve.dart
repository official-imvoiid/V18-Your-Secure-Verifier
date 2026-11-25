import 'package:flutter/material.dart';

import '../../app_state.dart';
import '../../flows/flows.dart';
import '../../protocol/deep_links.dart';
import '../widgets.dart';
import 'errors.dart';

/// Device link approval (PROTOCOL 3.9): a PC asks for its own age card.
/// There is no design for this screen; it follows the same style.
class LinkApproveScreen extends StatefulWidget {
  const LinkApproveScreen({super.key, required this.link});
  final LinkApprovalLink link;

  @override
  State<LinkApproveScreen> createState() => _LinkApproveScreenState();
}

class _LinkApproveScreenState extends State<LinkApproveScreen> {
  bool _working = false;
  bool _done = false;
  String? _note;

  Future<void> _approve() async {
    final app = AppScope.read(context);
    final card = app.card;
    if (card == null) return;
    setState(() {
      _working = true;
      _note = null;
    });
    try {
      await approveDeviceLink(app.services, widget.link, card);
      if (mounted) setState(() => _done = true);
    } on FlowFailure catch (f) {
      if (!mounted) return;
      if (f.kind == FailureKind.cancelled) {
        setState(() => _note = 'Not approved. You can try again.');
      } else {
        await Navigator.of(context)
            .pushReplacement(MaterialPageRoute(builder: (ctx) => errorScreenFor(ctx, f)));
        return;
      }
    }
    if (mounted) setState(() => _working = false);
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final cs = Theme.of(context).colorScheme;
    final card = app.card;
    final active = app.hasActiveCard;
    Widget point(IconData i, String t) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Icon(i, color: cs.primary),
            const SizedBox(width: 14),
            Expanded(child: Text(t, style: const TextStyle(fontSize: 15, height: 1.4))),
          ]),
        );
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
            tooltip: 'Close', icon: const Icon(Icons.close), onPressed: () => goHome(context)),
      ),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 0, 24, 0), children: [
            CircleAvatar(
              radius: 32,
              backgroundColor: cs.tertiaryContainer,
              child: Icon(_done ? Icons.check : Icons.computer,
                  size: 34, color: cs.onTertiaryContainer),
            ),
            const SizedBox(height: 20),
            Text(_done ? 'Your PC has its own age card' : 'Add an age card to your PC?',
                style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(
                _done
                    ? 'Go back to your PC. It will finish in a few seconds.'
                    : 'A PC asked to get its own age card from your phone. Only approve this if you just scanned the code on your own PC.',
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            if (!_done) ...[
              point(Icons.lock_outline,
                  "The PC gets a new card, locked to the PC's own Windows Hello. Your phone's card stays here."),
              point(Icons.event, card == null
                  ? 'It ends no later than your phone\'s card.'
                  : "It ends no later than your phone's card (${formatDate(card.validUntil)})."),
              point(Icons.numbers, 'It counts toward the number of cards your ID can have.'),
              point(Icons.visibility_off_outlined, 'Nothing about you is shared with the PC or anyone else.'),
              point(Icons.timer_outlined, 'The code works once and only for 2 minutes.'),
            ],
            if (!active)
              InfoPanel(
                color: cs.errorContainer,
                child: Text('You need an active age card on this phone first.',
                    style: TextStyle(color: cs.onErrorContainer)),
              ),
            if (_note != null) ...[const SizedBox(height: 8), Text(_note!)],
          ]),
        ),
        BottomActions(children: [
          if (_done)
            FilledButton(onPressed: () => goHome(context), child: const Text('Done'))
          else ...[
            FilledButton(
              onPressed: active && !_working ? _approve : null,
              child: Text(_working ? 'Waiting for unlock…' : 'Approve with fingerprint'),
            ),
            const SizedBox(height: 4),
            TextButton(onPressed: () => goHome(context), child: const Text("Don't approve")),
          ],
        ]),
      ]),
    );
  }
}
