import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../app_state.dart';
import '../../protocol/deep_links.dart';
import '../widgets.dart';
import 'errors.dart';
import 'link_approve.dart';
import 'site_request.dart';

/// Opens the right screen for a `v18://` link (deep link or scanned QR).
Future<void> openV18Link(NavigatorState nav, AppState app, String text) async {
  try {
    final link = parseDeepLink(text, allowlist: app.allowlist, defaultServer: app.server);
    switch (link) {
      case VerifyLink():
        await nav.push(MaterialPageRoute(builder: (_) => SiteRequestScreen(link: link)));
      case LinkApprovalLink():
        await nav.push(MaterialPageRoute(builder: (_) => LinkApproveScreen(link: link)));
    }
  } on DeepLinkError catch (e) {
    await nav.push(MaterialPageRoute(
      builder: (ctx) => ErrorScreen(
        icon: e.serverNotAllowed ? Icons.gpp_maybe_outlined : Icons.qr_code_2,
        title: e.serverNotAllowed ? 'Untrusted server' : "This code can't be used",
        body: e.reason,
        footnote: 'Nothing was sent.',
        primaryLabel: 'Back',
        onPrimary: () => Navigator.of(ctx).pop(),
      ),
    ));
  }
}

/// Scan a website's "Verify age" QR or a PC's link QR.
class ScanCodeScreen extends StatefulWidget {
  const ScanCodeScreen({super.key, this.useCamera = true});
  final bool useCamera;

  @override
  State<ScanCodeScreen> createState() => _ScanCodeScreenState();
}

class _ScanCodeScreenState extends State<ScanCodeScreen> {
  MobileScannerController? _camera;
  bool _handled = false;

  @override
  void initState() {
    super.initState();
    if (widget.useCamera) {
      _camera = MobileScannerController(formats: const [BarcodeFormat.qrCode]);
    }
  }

  @override
  void dispose() {
    _camera?.dispose();
    super.dispose();
  }

  Future<void> _open(String text) async {
    if (_handled) return;
    _handled = true;
    await _camera?.stop();
    if (!mounted) return;
    final nav = Navigator.of(context);
    final app = AppScope.read(context);
    nav.pop();
    await openV18Link(nav, app, text);
  }

  Future<void> _paste() async {
    final c = TextEditingController();
    final text = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Paste a V18 link'),
        content: TextField(
          controller: c,
          maxLines: 3,
          decoration: const InputDecoration(
              hintText: 'v18://verify?... or v18://link?...', border: OutlineInputBorder()),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, c.text), child: const Text('Open')),
        ],
      ),
    );
    c.dispose();
    if (text != null && text.trim().isNotEmpty) await _open(text.trim());
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: const StepTopBar(title: 'Scan a code'),
      body: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 24), children: [
        Text("Scan the website's or PC's V18 code",
            style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 8),
        Text('Point the camera at the QR shown next to "Verify age", or on the V18 PC app.',
            style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
        const SizedBox(height: 16),
        AspectRatio(
          aspectRatio: 1,
          child: ClipRRect(
            borderRadius: BorderRadius.circular(28),
            child: _camera != null
                ? MobileScanner(
                    controller: _camera,
                    onDetect: (capture) {
                      for (final b in capture.barcodes) {
                        final raw = b.rawValue;
                        if (raw != null && raw.toLowerCase().startsWith('v18:')) {
                          unawaited(_open(raw));
                          return;
                        }
                      }
                    },
                  )
                : Container(color: cs.inverseSurface),
          ),
        ),
        const SizedBox(height: 16),
        OutlinedButton.icon(
          onPressed: _paste,
          icon: const Icon(Icons.content_paste),
          label: const Text('Paste a link instead'),
        ),
        const SizedBox(height: 16),
        InfoPanel(
          icon: Icons.verified_user_outlined,
          child: const Text(
              'V18 only talks to servers it trusts. Codes pointing anywhere else are refused.'),
        ),
      ]),
    );
  }
}
