import 'dart:async';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../aadhaar/anon_aadhaar.dart';
import '../../aadhaar/artifacts.dart';
import '../../aadhaar/native_prover.dart';
import '../../aadhaar/secure_qr.dart';
import '../../aadhaar/uidai_keys.dart';
import '../../app_state.dart';
import '../../device/pdf_pages.dart';
import '../../flows/flows.dart';
import '../widgets.dart';
import 'card_flow.dart';
import 'errors.dart';
import 'info_pages.dart';

/// AadhaarScan.dc.html. Step 1 of 3.
class AadhaarScanScreen extends StatefulWidget {
  const AadhaarScanScreen({super.key, this.useCamera = true});

  /// Widget tests turn the camera off.
  final bool useCamera;

  @override
  State<AadhaarScanScreen> createState() => _AadhaarScanScreenState();
}

class _AadhaarScanScreenState extends State<AadhaarScanScreen> {
  MobileScannerController? _camera;
  bool _busy = false;
  String? _message;

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

  Future<void> _handleText(String text) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _message = null;
    });
    final app = AppScope.read(context);
    AadhaarSecureQr qr;
    try {
      qr = AadhaarSecureQr.decode(text);
    } on AadhaarQrException catch (e) {
      setState(() {
        _busy = false;
        _message = e.message;
      });
      return;
    }
    final key = qr.verifySeal(trustedAadhaarKeys(devMode: app.devMode));
    if (!mounted) return;
    if (key == null) {
      qr.wipe();
      await Navigator.of(context)
          .push(MaterialPageRoute(builder: (ctx) => aadhaarSealErrorScreen(ctx)));
      if (mounted) setState(() => _busy = false);
      return;
    }
    int age;
    try {
      age = qr.ageOn(app.services.now());
    } on AadhaarQrException catch (e) {
      qr.wipe();
      setState(() {
        _busy = false;
        _message = e.message;
      });
      return;
    }
    if (age < 18) {
      qr.wipe();
      await Navigator.of(context)
          .push(MaterialPageRoute(builder: (ctx) => under18CardErrorScreen(ctx)));
      if (mounted) setState(() => _busy = false);
      return;
    }
    await _camera?.stop();
    if (!mounted) return;
    await Navigator.of(context).push(MaterialPageRoute(
        builder: (_) => SealCheckScreen(qr: qr, testKey: key.isTestKey)));
    if (!mounted) return;
    setState(() => _busy = false);
    await _camera?.start();
  }

  Future<void> _import() async {
    final file = await FilePicker.pickFile(
      type: FileType.custom,
      allowedExtensions: const ['pdf', 'png', 'jpg', 'jpeg'],
    );
    final path = file?.path;
    if (file == null || path == null) return;
    setState(() {
      _busy = true;
      _message = null;
    });
    String? found;
    final pdf = PdfPages();
    try {
      final images = <String>[];
      if (file.name.toLowerCase().endsWith('.pdf')) {
        images.addAll(await _renderPdf(pdf, path));
      } else {
        images.add(path);
      }
      for (final img in images) {
        final capture = await (_camera ?? MobileScannerController())
            .analyzeImage(img, formats: const [BarcodeFormat.qrCode]);
        for (final b in capture?.barcodes ?? const <Barcode>[]) {
          final raw = b.rawValue;
          if (raw != null && RegExp(r'^\d{100,}$').hasMatch(raw.trim())) {
            found = raw;
            break;
          }
        }
        if (found != null) break;
      }
    } on PdfRenderException catch (e) {
      _message = switch (e.code) {
        'pdf_password' => 'That password did not open the PDF. Try again.',
        'pdf_password_unsupported' =>
          "This PDF has a password, and Android before version 15 can't open it inside an app. "
              'Open the PDF yourself, take a screenshot of the big QR, and import the screenshot.',
        _ => "This PDF couldn't be opened.",
      };
    } on Object {
      _message = "We couldn't read that file.";
    } finally {
      // Delete every copy: rendered pages and the picker's cached file.
      await pdf.deleteRenderedPages();
      try {
        await FilePicker.clearTemporaryFiles();
      } on Object {
        // Best effort.
      }
    }
    if (!mounted) return;
    setState(() => _busy = false);
    if (found != null) {
      await _handleText(found);
    } else {
      setState(() => _message ??= 'No Aadhaar Secure QR was found in that file.');
    }
  }

  Future<List<String>> _renderPdf(PdfPages pdf, String path) async {
    try {
      return await pdf.render(path);
    } on PdfRenderException catch (e) {
      if (e.code != 'pdf_password' || !mounted) rethrow;
      final pw = await _askPassword();
      if (pw == null) return const [];
      return pdf.render(path, password: pw);
    }
  }

  Future<String?> _askPassword() {
    final c = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('PDF password'),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text(
              'e-Aadhaar PDFs have a password: the first 4 letters of your name in CAPITALS, then your year of birth. '
              'It is used only to open the file on this phone.'),
          const SizedBox(height: 12),
          TextField(
            controller: c,
            obscureText: true,
            autofocus: true,
            decoration: const InputDecoration(border: OutlineInputBorder(), labelText: 'Password'),
          ),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, c.text), child: const Text('Open')),
        ],
      ),
    ).whenComplete(c.dispose);
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: const StepTopBar(title: 'Aadhaar QR', step: 'Step 1 of 3'),
      body: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 24), children: [
        Text('Scan your Aadhaar QR', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 8),
        Text('Use the big QR on your Aadhaar letter or card, or on the e-Aadhaar PDF.',
            style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
        const SizedBox(height: 16),
        AspectRatio(
          aspectRatio: 1,
          child: ClipRRect(
            borderRadius: BorderRadius.circular(28),
            child: Stack(fit: StackFit.expand, children: [
              if (_camera != null)
                MobileScanner(
                  controller: _camera,
                  onDetect: (capture) {
                    for (final b in capture.barcodes) {
                      final raw = b.rawValue;
                      if (raw != null && raw.isNotEmpty) {
                        unawaited(_handleText(raw));
                        return;
                      }
                    }
                  },
                )
              else
                Container(color: cs.inverseSurface),
              Center(
                child: Container(
                  width: 220,
                  height: 220,
                  decoration: BoxDecoration(
                    border: Border.all(color: cs.primaryContainer, width: 4),
                    borderRadius: BorderRadius.circular(24),
                  ),
                ),
              ),
              Positioned(
                left: 0,
                right: 0,
                bottom: 16,
                child: Center(
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                    decoration: BoxDecoration(
                        color: Colors.black54, borderRadius: BorderRadius.circular(16)),
                    child: Text(_busy ? 'Reading…' : 'Hold steady…',
                        style: const TextStyle(color: Colors.white)),
                  ),
                ),
              ),
            ]),
          ),
        ),
        if (_message != null) ...[
          const SizedBox(height: 12),
          InfoPanel(
            color: cs.errorContainer,
            icon: Icons.info_outline,
            iconColor: cs.onErrorContainer,
            child: Text(_message!, style: TextStyle(color: cs.onErrorContainer)),
          ),
        ],
        const SizedBox(height: 16),
        Row(children: [
          const Expanded(child: Divider()),
          Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: Text('or', style: TextStyle(color: cs.onSurfaceVariant))),
          const Expanded(child: Divider()),
        ]),
        const SizedBox(height: 12),
        OutlinedButton.icon(
          onPressed: _busy ? null : _import,
          icon: const Icon(Icons.picture_as_pdf_outlined),
          label: const Text('Import e-Aadhaar PDF or image'),
        ),
        const SizedBox(height: 16),
        InfoPanel(
          color: cs.tertiaryContainer,
          icon: Icons.phone_android,
          iconColor: cs.onTertiaryContainer,
          child: Text('Use the signed Secure QR. It is read on this phone and never uploaded.',
              style: TextStyle(color: cs.onTertiaryContainer)),
        ),
      ]),
    );
  }
}

/// SealCheck.dc.html. Step 2 of 3.
class SealCheckScreen extends StatefulWidget {
  const SealCheckScreen({super.key, required this.qr, required this.testKey});
  final AadhaarSecureQr qr;
  final bool testKey;

  @override
  State<SealCheckScreen> createState() => _SealCheckScreenState();
}

class _SealCheckScreenState extends State<SealCheckScreen> {
  @override
  void dispose() {
    // The QR data lives only while this flow is open.
    widget.qr.wipe();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final app = AppScope.of(context);
    return Scaffold(
      appBar: const StepTopBar(title: 'Aadhaar QR', step: 'Step 2 of 3'),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            CircleAvatar(
              radius: 32,
              backgroundColor: cs.primaryContainer,
              child: Icon(Icons.verified, size: 36, color: cs.onPrimaryContainer),
            ),
            const SizedBox(height: 20),
            Text('The seal is valid', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(
                widget.testKey
                    ? 'This QR was signed with the Anon Aadhaar TEST key. That is fine on a test server, but it is not a real Aadhaar.'
                    : 'This QR was signed by the government. If anyone changed even one letter, the seal would break.',
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            const CheckRow('QR read on this phone'),
            CheckRow(widget.testKey ? 'Signed with the TEST key (test mode)' : 'Signed by the Aadhaar issuer (UIDAI)'),
            const CheckRow('Nothing was changed'),
            const CheckRow('18 or older (checked on this phone)'),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                style: TextButton.styleFrom(minimumSize: const Size(0, 44)),
                onPressed: () => Navigator.of(context)
                    .push(MaterialPageRoute(builder: (_) => const HowSealsScreen())),
                icon: const Icon(Icons.help_outline),
                label: const Text('How seals work'),
              ),
            ),
          ]),
        ),
        BottomActions(children: [
          FilledButton(
            key: const Key('seal-continue'),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute(
              builder: (_) => AadhaarFilesScreen(
                next: (paths) => SetLockScreen(
                  methodTitle: 'Aadhaar QR',
                  next: (_) => _proofScreen(app, paths),
                ),
              ),
            )),
            child: const Text('Continue'),
          ),
        ]),
      ]),
    );
  }

  Widget _proofScreen(AppState app, AadhaarArtifactPaths paths) => IssueProgressScreen(
        methodTitle: 'Aadhaar QR',
        stepLabel: 'Step 3 of 3',
        method: 'anon_aadhaar',
        steps: const [
          IssueStep('QR read', alreadyDone: true),
          IssueStep('Seal is valid', alreadyDone: true),
          IssueStep('Making the 18+ proof'),
          IssueStep('Sending proof only'),
        ],
        proofStepIndex: 2,
        intro: 'Your phone makes a zero-knowledge proof that says only "18+". '
            'The QR details never leave the phone.',
        waitNote: 'Keep the app open. On most phones this takes under a minute.',
        doneTitle: 'Done. Your age card is ready',
        doneBody: "The QR data has been deleted. Only the age card is kept, inside this phone's secure chip.",
        doneExtra: (t) =>
            'The 18+ proof was made on this phone in ${(t.inMilliseconds / 1000).toStringAsFixed(1)} seconds.',
        buildProof: (challenge, thumbprint, report) async {
          try {
            final seed = app.health?.aadhaarNullifierSeed ??
                (app.devMode ? devAadhaarNullifierSeed : null);
            if (seed == null) {
              throw const FlowFailure(FailureKind.server,
                  "The V18 server didn't share its Aadhaar settings (nullifier seed).");
            }
            final key = widget.testKey ? anonAadhaarTestKey : _matchingProdKey();
            final inputs = AnonAadhaarInputs.build(
              qr: widget.qr,
              uidaiModulus: key.rsaKey.modulus!,
              nullifierSeed: seed,
              signal: anonAadhaarSignal(challenge, thumbprint),
            );
            final proof = await app.prover.prove(inputs, paths, onStage: (st) => report(st.label));
            return proof.toJson(newProofId());
          } finally {
            widget.qr.wipe();
          }
        },
      );

  AadhaarSigningKey _matchingProdKey() =>
      widget.qr.verifySeal(uidaiProductionKeys) ?? uidaiProductionKeys.first;
}

/// One-time download of the Anon Aadhaar circuit files (PROTOCOL 4c.1).
/// Each file is checked against its SHA-256 from the server's list, then
/// kept in the app's private storage.
class AadhaarFilesScreen extends StatefulWidget {
  const AadhaarFilesScreen({super.key, required this.next});
  final Widget Function(AadhaarArtifactPaths paths) next;

  @override
  State<AadhaarFilesScreen> createState() => _AadhaarFilesScreenState();
}

class _AadhaarFilesScreenState extends State<AadhaarFilesScreen> {
  AadhaarArtifacts? _files;
  bool _downloading = false;
  bool _cancel = false;
  int _done = 0;
  int _total = 0;
  String? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  @override
  void dispose() {
    _cancel = true;
    super.dispose();
  }

  Future<void> _load() async {
    final app = AppScope.read(context);
    setState(() => _error = null);
    if (!app.prover.available) {
      setState(() => _error = "This phone can't run the Aadhaar proof (it needs a 64-bit phone). "
          'Pick another way to make your card.');
      return;
    }
    try {
      final files = await app.artifacts.manifest(app.server);
      if (!mounted) return;
      if (await app.artifacts.isCached(files)) {
        await _download(files);
        return;
      }
      setState(() => _files = files);
    } on Object catch (e) {
      if (mounted) {
        setState(() => _error = e is ArtifactException ? e.message : FlowFailure.from(e).message);
      }
    }
  }

  Future<void> _download(AadhaarArtifacts files) async {
    final app = AppScope.read(context);
    setState(() {
      _downloading = true;
      _error = null;
      _cancel = false;
    });
    try {
      final paths = await app.artifacts.ensure(app.server, files,
          onProgress: (d, t) {
            if (mounted) {
              setState(() {
                _done = d;
                _total = t;
              });
            }
          },
          cancelled: () => _cancel);
      if (!mounted) return;
      Navigator.of(context).pushReplacement(MaterialPageRoute(builder: (_) => widget.next(paths)));
    } on Object catch (e) {
      if (mounted) {
        setState(() {
          _downloading = false;
          _error = e is ArtifactException ? e.message : FlowFailure.from(e).message;
        });
      }
    }
  }

  static String _mb(int b) => '${(b / (1024 * 1024)).round()} MB';

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final f = _files;
    return Scaffold(
      appBar: const StepTopBar(title: 'Aadhaar QR', step: 'Proof files'),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Text('Get the proof files', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 12),
            Text(
                'To make a zero-knowledge proof, your phone needs the official Anon Aadhaar files. '
                'You download them once. They hold no personal data.',
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            if (f != null)
              InfoPanel(
                icon: Icons.wifi,
                child: Text('Size: ${_mb(f.totalBytes)}. Use Wi-Fi if you can. '
                    'Every file is checked against its fingerprint (SHA-256) before it is used.'),
              ),
            if (_downloading) ...[
              const SizedBox(height: 16),
              LinearProgressIndicator(value: _total > 0 ? _done / _total : null),
              const SizedBox(height: 8),
              Text(_total > 0 ? '${_mb(_done)} of ${_mb(_total)}' : 'Checking the files…',
                  key: const Key('download-progress')),
            ],
            if (f == null && _error == null && !_downloading) ...[
              const SizedBox(height: 16),
              const Center(child: CircularProgressIndicator()),
            ],
            if (_error != null) ...[
              const SizedBox(height: 16),
              InfoPanel(
                color: cs.errorContainer,
                icon: Icons.error_outline,
                iconColor: cs.onErrorContainer,
                child: Text(_error!, style: TextStyle(color: cs.onErrorContainer)),
              ),
            ],
          ]),
        ),
        BottomActions(children: [
          if (f != null && !_downloading)
            FilledButton(
                key: const Key('download-files'),
                onPressed: () => _download(f),
                child: Text('Download ${_mb(f.totalBytes)}')),
          if (_downloading)
            TextButton(onPressed: () => setState(() => _cancel = true), child: const Text('Cancel')),
          if (_error != null && f == null)
            FilledButton(onPressed: _load, child: const Text('Try again')),
        ]),
      ]),
    );
  }
}
