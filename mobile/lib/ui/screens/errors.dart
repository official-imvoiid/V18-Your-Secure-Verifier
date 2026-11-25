import 'package:flutter/material.dart';

import '../../flows/flows.dart';
import '../widgets.dart';

/// One layout for every error screen in the V18 design mock-ups and
/// ChildAccount.dc.html.
class ErrorScreen extends StatelessWidget {
  const ErrorScreen({
    super.key,
    required this.icon,
    required this.title,
    required this.body,
    this.panelTitle,
    this.panelLines = const [],
    this.footnote,
    this.testNote,
    this.primaryLabel,
    this.onPrimary,
    this.secondaryLabel,
    this.onSecondary,
    this.danger = true,
  });

  final IconData icon;
  final String title;
  final String body;
  final String? panelTitle;
  final List<String> panelLines;
  final String? footnote;
  /// Only for screens a debug test switch shows. Labelled TEST.
  final String? testNote;
  final String? primaryLabel;
  final VoidCallback? onPrimary;
  final String? secondaryLabel;
  final VoidCallback? onSecondary;
  final bool danger;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          tooltip: 'Close',
          icon: const Icon(Icons.close),
          onPressed: () => Navigator.of(context).maybePop(),
        ),
      ),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Container(
              width: 72,
              height: 72,
              alignment: Alignment.center,
              decoration: BoxDecoration(
                color: danger ? cs.errorContainer : cs.secondaryContainer,
                borderRadius: BorderRadius.circular(24),
              ),
              child: Icon(icon,
                  size: 36, color: danger ? cs.onErrorContainer : cs.onSecondaryContainer),
            ),
            const SizedBox(height: 24),
            Semantics(
              header: true,
              child: Text(title, style: Theme.of(context).textTheme.headlineMedium),
            ),
            const SizedBox(height: 12),
            Text(body, style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            if (panelTitle != null || panelLines.isNotEmpty) ...[
              const SizedBox(height: 20),
              InfoPanel(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  if (panelTitle != null)
                    Text(panelTitle!,
                        style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w500)),
                  for (final l in panelLines)
                    Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: Text(l, style: const TextStyle(fontSize: 14, height: 1.4)),
                    ),
                ]),
              ),
            ],
            if (testNote != null) ...[
              const SizedBox(height: 16),
              NoticeBox(testNote!, title: 'TEST'),
            ],
            if (footnote != null) ...[
              const SizedBox(height: 16),
              Row(children: [
                Icon(Icons.lock_outline, size: 18, color: cs.onSurfaceVariant),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(footnote!,
                      style: TextStyle(fontSize: 14, color: cs.onSurfaceVariant)),
                ),
              ]),
            ],
            const SizedBox(height: 24),
          ]),
        ),
        BottomActions(children: [
          if (primaryLabel != null)
            FilledButton(onPressed: onPrimary, child: Text(primaryLabel!)),
          if (secondaryLabel != null) ...[
            const SizedBox(height: 4),
            TextButton(onPressed: onSecondary, child: Text(secondaryLabel!)),
          ],
        ]),
      ]),
    );
  }
}

/// ErrorSeal.dc.html (chip version).
Widget chipSealErrorScreen(BuildContext context, {String? detail}) => ErrorScreen(
      icon: Icons.gpp_bad_outlined,
      title: "We couldn't confirm this ID",
      body: "The chip didn't pass the check, or its government seal isn't valid. "
          'This can happen with a damaged or fake ID.${detail == null ? '' : '\n\n$detail'}',
      panelTitle: 'Things to try',
      panelLines: const [
        '• Take off the phone case and hold still for longer',
        '• Move the phone slowly to find the chip',
        '• Use a different ID',
      ],
      footnote: 'Nothing was saved or sent.',
      primaryLabel: 'Try again',
      onPrimary: () => Navigator.of(context).pop(),
      secondaryLabel: 'Use another ID',
      onSecondary: () => goHome(context),
    );

/// ErrorSeal.dc.html, Aadhaar QR version.
Widget aadhaarSealErrorScreen(BuildContext context) => ErrorScreen(
      icon: Icons.gpp_bad_outlined,
      title: "We couldn't confirm this QR",
      body: "This QR wasn't signed by UIDAI, or something in it was changed. "
          'A photo of a photocopy, a fake QR, or an old QR format can cause this.',
      panelTitle: 'Things to try',
      panelLines: const [
        '• Use the big Secure QR on the Aadhaar letter, card or a new e-Aadhaar PDF',
        '• Download a fresh e-Aadhaar from the UIDAI website',
        '• Use your passport instead',
      ],
      footnote: 'Nothing was saved or sent.',
      primaryLabel: 'Try again',
      onPrimary: () => Navigator.of(context).pop(),
      secondaryLabel: 'Use another ID',
      onSecondary: () => goHome(context),
    );

/// ErrorOffline.dc.html
Widget offlineErrorScreen(BuildContext context, {VoidCallback? onRetry}) => ErrorScreen(
      icon: Icons.wifi_off,
      danger: false,
      title: "You're offline",
      body: 'This step needs the internet for a few seconds. Connect to Wi-Fi or mobile data, then try again.',
      panelTitle: 'Good to know',
      panelLines: const ['Your age card is safe on this phone. Tickets you already sent still work.'],
      primaryLabel: 'Try again',
      onPrimary: onRetry ?? () => Navigator.of(context).pop(),
      secondaryLabel: 'Back',
      onSecondary: () => goHome(context),
    );

/// ErrorUnder18.dc.html, when a website asked.
Widget under18SiteErrorScreen(BuildContext context, String siteHost) => ErrorScreen(
      icon: Icons.do_not_disturb_on_outlined,
      danger: false,
      title: 'This site is 18+',
      body: "Your age card can't prove the age this site needs, so we can't send a ticket to $siteHost. "
          "That's okay. There's lots online that's made for you.",
      panelTitle: 'What the site knows',
      panelLines: const ['Only that no ticket was sent. Not your age, your name or anything else.'],
      primaryLabel: 'Back to browser',
      onPrimary: () => goHome(context),
    );

/// ErrorUnder18.dc.html, when the ID shows under 18 while making a card.
Widget under18CardErrorScreen(BuildContext context) => ErrorScreen(
      icon: Icons.do_not_disturb_on_outlined,
      danger: false,
      title: "You're under 18",
      body: "Your ID shows you're under 18, so V18 can't make an age card. "
          "That's okay. There's lots online that's made for you.",
      footnote: 'Your ID data was deleted from this phone. Nothing was sent.',
      primaryLabel: 'Back to home',
      onPrimary: () => goHome(context),
    );

/// ChildAccount.dc.html
Widget childAccountErrorScreen(BuildContext context, String siteHost, {bool simulated = true}) =>
    ErrorScreen(
      icon: Icons.child_care,
      danger: false,
      title: 'This phone has a child account',
      body: "V18 doesn't make 18+ tickets on child accounts. It's one of the ways we help keep young people safe online.",
      panelTitle: 'Think this is a mistake?',
      panelLines: const [
        "Ask the parent or guardian who manages this account to check the phone's family settings."
      ],
      testNote: simulated
          ? 'You see this screen because the debug test switch in Settings is on.'
          : null,
      footnote: 'Nothing about you was shared with $siteHost.',
      primaryLabel: 'Back to browser',
      onPrimary: () => goHome(context),
    );

/// Expired card (ErrorExpired.dc.html is shown on the home screen itself).
Widget expiredErrorScreen(BuildContext context) => ErrorScreen(
      icon: Icons.event_busy,
      title: 'Your age card has expired',
      body: 'Scan your ID again to make a new one. It takes about 2 minutes.',
      footnote: 'No new tickets can be made until you renew. The old card held nothing about you.',
      primaryLabel: 'Back to home',
      onPrimary: () => goHome(context),
    );

/// Picks the right screen for a [FlowFailure].
Widget errorScreenFor(BuildContext context, FlowFailure f,
    {String siteHost = 'the site', VoidCallback? onRetry}) {
  switch (f.kind) {
    case FailureKind.offline:
      return offlineErrorScreen(context, onRetry: onRetry);
    case FailureKind.cardExpired:
      return expiredErrorScreen(context);
    case FailureKind.childAccount:
      return childAccountErrorScreen(context, siteHost);
    case FailureKind.siteNeedsHigherAge:
      return under18SiteErrorScreen(context, siteHost);
    case FailureKind.under18:
      return under18CardErrorScreen(context);
    default:
      return ErrorScreen(
        icon: Icons.error_outline,
        title: _titleFor(f.kind),
        body: f.message,
        footnote: 'Nothing about you was shared.',
        primaryLabel: 'Back to home',
        onPrimary: () => goHome(context),
      );
  }
}

String _titleFor(FailureKind k) => switch (k) {
      FailureKind.methodNotReady => 'Not on this server',
      FailureKind.attestation => "We couldn't confirm this phone",
      FailureKind.wrongServer => 'Different V18 server',
      FailureKind.sessionGone => 'This code has expired',
      FailureKind.codeMismatch => "This code doesn't match",
      FailureKind.keyInvalidated => 'Your card lock was reset',
      FailureKind.noLock => 'Set up a screen lock first',
      FailureKind.tooManyCards => 'Too many cards for this ID',
      FailureKind.noTicketKey => 'No ticket key right now',
      _ => 'Something went wrong',
    };
