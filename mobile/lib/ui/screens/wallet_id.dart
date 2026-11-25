import 'package:flutter/material.dart';

import '../../app_state.dart';
import '../../device/wallet.dart';
import '../../flows/flows.dart';
import '../widgets.dart';
import 'card_flow.dart';

/// `mdoc_app` (PROTOCOL 4d.3): another wallet on this phone shares ONLY
/// "over 18" from an ID it holds (an EU digital identity wallet, a Google
/// Wallet ID, a national mobile driving licence app). The wallet's answer is
/// encrypted to the V18 server; this app passes it on without reading it.
class WalletIdScreen extends StatelessWidget {
  const WalletIdScreen({super.key, required this.label, this.documents = const []});
  final String label;
  final List<String> documents;

  Widget _issue(AppState app) => IssueProgressScreen(
        methodTitle: label,
        stepLabel: 'Step 2 of 2',
        method: 'mdoc_app',
        title: 'Asking your wallet',
        intro: 'Your wallet app shows what V18 asks for: only "over 18". Nothing else is shared.',
        steps: const [
          IssueStep('Lock key made in the secure chip', alreadyDone: true),
          IssueStep('Wallet shares "over 18"'),
          IssueStep('V18 server checks the wallet seal'),
        ],
        proofStepIndex: 1,
        waitNote: 'Pick the ID in the wallet window and confirm.',
        doneTitle: 'Done. Your age card is ready',
        doneBody: 'Only "over 18" was shared from your wallet. The age card is kept in this phone\'s secure chip.',
        buildProof: (challenge, thumbprint, report) async {
          report('Getting the request from the V18 server');
          final req = await app.api.walletAppRequest(challenge: challenge);
          final digital = req['digital'];
          if (digital is! Map<String, dynamic>) {
            throw const FlowFailure(FailureKind.server, 'The V18 server sent no wallet request.');
          }
          report('Waiting for your wallet');
          final Map<String, dynamic> cred;
          try {
            cred = await app.wallet.get(digital);
          } on WalletException catch (e) {
            throw switch (e.code) {
              'cancelled' => const FlowFailure(FailureKind.cancelled, 'Cancelled.'),
              'no_credential' => const FlowFailure(FailureKind.methodNotReady,
                  'No wallet app on this phone has an ID that can share "over 18". Pick another way.'),
              _ => const FlowFailure(FailureKind.other, "The wallet didn't answer. Try again."),
            };
          }
          // In dev mode the server may not know this app's signing key, so the
          // TEST app says which origin Credential Manager used (API.md section 14).
          if (app.devMode) {
            final origin = await app.wallet.appOrigin();
            if (origin != null) return {...cred, 'origin': origin};
          }
          return cred;
        },
      );

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final app = AppScope.of(context);
    return Scaffold(
      appBar: StepTopBar(title: label, step: 'Step 1 of 2'),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Text('Use an ID in your wallet', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(
                'If an app on this phone already holds your ID (a government wallet, a digital driving licence, '
                'or a wallet ID), it can tell V18 only that you are over 18.',
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            if (documents.isNotEmpty)
              InfoPanel(icon: Icons.wallet_outlined, child: Text('Works with: ${documents.join(', ')}.')),
            const SizedBox(height: 8),
            const CheckRow('Only "over 18" is asked for'),
            const CheckRow('No name, photo or birth date'),
            const CheckRow('The wallet seal is checked by the V18 server, then forgotten'),
          ]),
        ),
        BottomActions(children: [
          FilledButton(
            key: const Key('wallet-continue'),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute(
                builder: (_) => SetLockScreen(methodTitle: label, next: (_) => _issue(app)))),
            child: const Text('Choose a wallet ID'),
          ),
        ]),
      ]),
    );
  }
}
