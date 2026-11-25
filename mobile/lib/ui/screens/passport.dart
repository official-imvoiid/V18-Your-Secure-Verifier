import 'dart:io';

import 'package:camera/camera.dart';
import 'package:flutter/material.dart';
import 'package:google_mlkit_text_recognition/google_mlkit_text_recognition.dart';

import '../../app_state.dart';
import '../../flows/flows.dart';
import '../../passport/active_auth.dart';
import '../../passport/chip_reader.dart';
import '../../passport/mrz_reader.dart';
import '../widgets.dart';
import 'card_flow.dart';
import 'errors.dart';

/// PassportScan.dc.html. Step 1 of 4: how to unlock the chip.
/// Passports: the MRZ text lines (camera or typed). ID cards and residence
/// permits: the 6-digit card access number (CAN) for PACE, or the MRZ.
class PassportScanScreen extends StatefulWidget {
  const PassportScanScreen({
    super.key,
    required this.document,
    this.docTypes = const ['P'],
    this.method = 'emrtd_attested',
    this.useCamera = true,
  });

  /// The catalog label, for example "Passport (chip)" or "ID card (chip)".
  final String document;

  /// First MRZ letters this entry is for (PROTOCOL 4d.3): P, I, A, C.
  final List<String> docTypes;
  final String method;
  final bool useCamera;

  bool get usesCan => !docTypes.contains('P');

  @override
  State<PassportScanScreen> createState() => _PassportScanScreenState();
}

class _PassportScanScreenState extends State<PassportScanScreen> {
  CameraController? _camera;
  bool _cameraFailed = false;
  bool _busy = false;
  bool _manual = false;
  late bool _can = widget.usesCan;
  String? _message;

  final _docNumber = TextEditingController();
  final _canText = TextEditingController();
  DateTime? _dob;
  DateTime? _expiry;

  @override
  void initState() {
    super.initState();
    if (widget.useCamera && !_can) _startCamera();
  }

  Future<void> _startCamera() async {
    try {
      final cams = await availableCameras();
      final back = cams.firstWhere((c) => c.lensDirection == CameraLensDirection.back,
          orElse: () => cams.first);
      final c = CameraController(back, ResolutionPreset.high, enableAudio: false);
      await c.initialize();
      if (!mounted) {
        await c.dispose();
        return;
      }
      setState(() => _camera = c);
    } on Object {
      if (mounted) setState(() => _cameraFailed = true);
    }
  }

  @override
  void dispose() {
    _camera?.dispose();
    _docNumber.dispose();
    _canText.dispose();
    super.dispose();
  }

  Future<void> _scan() async {
    final c = _camera;
    if (c == null || _busy) return;
    setState(() {
      _busy = true;
      _message = null;
    });
    final recognizer = TextRecognizer(script: TextRecognitionScript.latin);
    String? photoPath;
    try {
      final photo = await c.takePicture();
      photoPath = photo.path;
      final text = await recognizer.processImage(InputImage.fromFilePath(photo.path));
      final key = mrzKeyFromOcrText(text.text);
      if (key == null) {
        _message = "We couldn't read the text lines. Fill the frame with the 2 or 3 lines of "
            'letters at the bottom of the photo page, with good light, and try again. '
            'Or type them instead.';
      } else {
        await _goToChip(MrzAccess(key));
      }
    } on Object {
      _message = "The camera picture couldn't be read. Try again or type the details.";
    } finally {
      await recognizer.close();
      if (photoPath != null) {
        try {
          File(photoPath).deleteSync();
        } on Object {
          // Already gone.
        }
      }
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _goToChip(ChipAccess access) async {
    if (!mounted) return;
    await Navigator.of(context).push(MaterialPageRoute(
        builder: (_) => PassportChipScreen(access: access, document: widget.document, method: widget.method)));
  }

  Future<DateTime?> _pickDate(DateTime initial, DateTime first, DateTime last) =>
      showDatePicker(context: context, initialDate: initial, firstDate: first, lastDate: last);

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final manualOk = _docNumber.text.trim().length >= 5 && _dob != null && _expiry != null;
    if (_can) return _canPage(context);
    return Scaffold(
      appBar: StepTopBar(title: widget.document, step: 'Step 1 of 4'),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Text(_manual ? 'Type the details' : 'Scan the text lines',
                style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(
                _manual
                    ? 'These three details unlock the chip. They are on the photo page.'
                    : "Point the camera at the 2 or 3 lines of letters on your ID's photo page. They unlock the chip.",
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            if (!_manual)
              AspectRatio(
                aspectRatio: 4 / 3,
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(24),
                  child: _camera != null
                      ? Stack(fit: StackFit.expand, children: [
                          CameraPreview(_camera!),
                          Align(
                            alignment: const Alignment(0, 0.6),
                            child: FractionallySizedBox(
                              widthFactor: 0.92,
                              heightFactor: 0.28,
                              child: Container(
                                decoration: BoxDecoration(
                                  border: Border.all(color: cs.primaryContainer, width: 3),
                                  borderRadius: BorderRadius.circular(12),
                                ),
                              ),
                            ),
                          ),
                        ])
                      : Container(
                          color: cs.inverseSurface,
                          alignment: Alignment.center,
                          child: Text(
                              _cameraFailed || !widget.useCamera
                                  ? 'Camera not available. Type the details instead.'
                                  : 'Starting camera…',
                              style: TextStyle(color: cs.onInverseSurface)),
                        ),
                ),
              ),
            if (_manual) ...[
              TextField(
                controller: _docNumber,
                textCapitalization: TextCapitalization.characters,
                onChanged: (_) => setState(() {}),
                decoration: const InputDecoration(
                    labelText: 'Document number', border: OutlineInputBorder()),
              ),
              const SizedBox(height: 8),
              ListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('Date of birth'),
                subtitle: Text(_dob == null ? 'Choose' : formatDate(_dob!)),
                trailing: const Icon(Icons.edit_calendar),
                onTap: () async {
                  final d = await _pickDate(DateTime(2000), DateTime(1900), DateTime.now());
                  if (d != null) setState(() => _dob = d);
                },
              ),
              ListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('Date of expiry'),
                subtitle: Text(_expiry == null ? 'Choose' : formatDate(_expiry!)),
                trailing: const Icon(Icons.edit_calendar),
                onTap: () async {
                  final d = await _pickDate(
                      DateTime.now().add(const Duration(days: 365)), DateTime(2000), DateTime(2100));
                  if (d != null) setState(() => _expiry = d);
                },
              ),
            ],
            if (_message != null) ...[
              const SizedBox(height: 12),
              InfoPanel(
                color: cs.errorContainer,
                icon: Icons.info_outline,
                iconColor: cs.onErrorContainer,
                child: Text(_message!, style: TextStyle(color: cs.onErrorContainer)),
              ),
            ],
            const SizedBox(height: 12),
            Row(children: [
              Icon(Icons.lock_outline, size: 18, color: cs.onSurfaceVariant),
              const SizedBox(width: 8),
              Expanded(
                child: Text('These letters never leave this phone.',
                    style: TextStyle(fontSize: 14, color: cs.onSurfaceVariant)),
              ),
            ]),
          ]),
        ),
        BottomActions(children: [
          if (!_manual)
            FilledButton(
              onPressed: _camera == null || _busy ? null : _scan,
              child: Text(_busy ? 'Reading…' : 'Scan text lines'),
            )
          else
            FilledButton(
              key: const Key('mrz-continue'),
              onPressed: manualOk
                  ? () => _goToChip(MrzAccess(MrzKey(
                        documentNumber: _docNumber.text.trim().toUpperCase(),
                        dateOfBirth: _dob!,
                        dateOfExpiry: _expiry!,
                      )))
                  : null,
              child: const Text('Continue'),
            ),
          const SizedBox(height: 4),
          TextButton(
            onPressed: () => setState(() {
              _manual = !_manual;
              _message = null;
            }),
            child: Text(_manual ? 'Use the camera instead' : 'Type them instead'),
          ),
          if (widget.usesCan)
            TextButton(
              onPressed: () => setState(() => _can = true),
              child: const Text('Use the card number (CAN) instead'),
            ),
        ]),
      ]),
    );
  }

  /// CAN entry (ID cards, residence permits): 6 digits printed on the card.
  Widget _canPage(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final can = _canText.text.trim();
    final ok = RegExp(r'^\d{6}$').hasMatch(can);
    return Scaffold(
      appBar: StepTopBar(title: widget.document, step: 'Step 1 of 4'),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Text('Type the card number', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(
                'Find the 6-digit card access number (CAN) on your card. On most EU ID cards it is on the front, '
                'at the bottom right, next to the photo. It unlocks the chip.',
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            TextField(
              key: const Key('can-field'),
              controller: _canText,
              keyboardType: TextInputType.number,
              maxLength: 6,
              onChanged: (_) => setState(() {}),
              decoration:
                  const InputDecoration(labelText: 'Card access number (6 digits)', border: OutlineInputBorder()),
            ),
            Row(children: [
              Icon(Icons.lock_outline, size: 18, color: cs.onSurfaceVariant),
              const SizedBox(width: 8),
              Expanded(
                child: Text('This number never leaves this phone.',
                    style: TextStyle(fontSize: 14, color: cs.onSurfaceVariant)),
              ),
            ]),
          ]),
        ),
        BottomActions(children: [
          FilledButton(
            key: const Key('can-continue'),
            onPressed: ok ? () => _goToChip(CanAccess(can)) : null,
            child: const Text('Continue'),
          ),
          TextButton(
            onPressed: () {
              setState(() => _can = false);
              if (widget.useCamera && _camera == null) _startCamera();
            },
            child: const Text('Use the text lines instead'),
          ),
        ]),
      ]),
    );
  }
}


/// PassportChip.dc.html. Step 2 of 4: read the chip over NFC.
class PassportChipScreen extends StatefulWidget {
  const PassportChipScreen(
      {super.key, required this.access, required this.document, this.method = 'emrtd_attested'});
  final ChipAccess access;
  final String document;
  final String method;

  @override
  State<PassportChipScreen> createState() => _PassportChipScreenState();
}

class _PassportChipScreenState extends State<PassportChipScreen> {
  double _progress = 0;
  String _step = 'Waiting for the chip';
  String? _error;
  bool _reading = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _read());
  }

  Future<void> _read() async {
    final app = AppScope.read(context);
    setState(() {
      _reading = true;
      _error = null;
      _progress = 0;
    });
    try {
      final result = await app.chipReader().read(widget.access, onProgress: (p, s) {
        if (mounted) {
          setState(() {
            _progress = p;
            _step = s;
          });
        }
      });
      if (!mounted) {
        result.wipe();
        return;
      }
      if (!result.over18) {
        result.wipe();
        await Navigator.of(context)
            .pushReplacement(MaterialPageRoute(builder: (ctx) => under18CardErrorScreen(ctx)));
        return;
      }
      if (result.expired) {
        result.wipe();
        await Navigator.of(context).pushReplacement(MaterialPageRoute(
            builder: (ctx) => errorScreenFor(
                ctx, const FlowFailure(FailureKind.server, 'This document has expired. Use one that is still valid.'))));
        return;
      }
      await Navigator.of(context).pushReplacement(MaterialPageRoute(
          builder: (_) => ChipConfirmedScreen(result: result, method: widget.method, document: widget.document)));
    } on ChipReadException catch (e) {
      if (!mounted) return;
      if (e.sealProblem) {
        await Navigator.of(context)
            .pushReplacement(MaterialPageRoute(builder: (ctx) => chipSealErrorScreen(ctx, detail: e.message)));
        return;
      }
      setState(() {
        _error = e.message;
        _reading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final isPassport = widget.access is MrzAccess && widget.document.toLowerCase().contains('passport');
    return Scaffold(
      appBar: StepTopBar(title: widget.document, step: 'Step 2 of 4'),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Text(isPassport ? 'Hold your phone on the passport' : 'Hold your phone on the card',
                style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(
                isPassport
                    ? 'Lay the phone flat on the front cover (or the photo page). Keep still.'
                    : 'Lay the phone flat on the card. Keep still.',
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 24),
            Container(
              height: 200,
              decoration: BoxDecoration(color: cs.primaryContainer, borderRadius: BorderRadius.circular(28)),
              child: Icon(Icons.nfc, size: 96, color: cs.onPrimaryContainer),
            ),
            const SizedBox(height: 24),
            if (_error == null) ...[
              LinearProgressIndicator(value: _reading ? _progress : null),
              const SizedBox(height: 8),
              Text('$_step… ${(_progress * 100).round()}%', style: const TextStyle(fontWeight: FontWeight.w500)),
              Text("Don't move the phone. About 10 seconds.", style: TextStyle(color: cs.onSurfaceVariant)),
            ] else
              InfoPanel(
                color: cs.errorContainer,
                icon: Icons.info_outline,
                iconColor: cs.onErrorContainer,
                child: Text(_error!, style: TextStyle(color: cs.onErrorContainer)),
              ),
          ]),
        ),
        BottomActions(children: [
          if (_error != null) FilledButton(onPressed: _read, child: const Text('Try again')),
          TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Cancel')),
        ]),
      ]),
    );
  }
}

/// ChipConfirmed.dc.html: exactly what the phone checked, then the card.
class ChipConfirmedScreen extends StatefulWidget {
  const ChipConfirmedScreen({super.key, required this.result, required this.method, required this.document});
  final ChipCheckResult result;
  final String method;
  final String document;

  @override
  State<ChipConfirmedScreen> createState() => _ChipConfirmedScreenState();
}

class _ChipConfirmedScreenState extends State<ChipConfirmedScreen> {
  /// Kept so "Try again" after a cancelled unlock does not ask the server again
  /// (the nullifier service allows 5 requests per device key per day).
  NullifierResult? _nullifier;

  @override
  void dispose() {
    // The document number lives only while this flow is open.
    widget.result.wipe();
    super.dispose();
  }

  Widget _issueScreen(AppState app) => IssueProgressScreen(
        methodTitle: widget.document,
        stepLabel: 'Step 4 of 4',
        method: widget.method == 'passport_attested' ? 'passport_attested' : 'emrtd_attested',
        attest: true,
        title: 'Making your age card',
        intro: 'Your phone sends only "18+", the document\'s end date and country, and a one-way code that stops '
            'one document making endless cards. No name, birth date or number.',
        steps: const [
          IssueStep('Chip read and checked', alreadyDone: true),
          IssueStep('One-way code for this document'),
          IssueStep('Sending "18+" only'),
        ],
        proofStepIndex: 1,
        doneTitle: 'Done. Your age card is ready',
        doneBody: "Your document details were deleted. Only the age card is kept, inside this phone's secure chip.",
        buildProof: (challenge, thumbprint, report) async {
          var n = _nullifier;
          if (n == null) {
            report('Asking the V18 server to blind-sign');
            n = await obtainNullifier(app.services, server: app.server, message: widget.result.nullifierMessage);
            _nullifier = n;
            // The document number is not needed any more.
            widget.result.wipe();
          }
          return widget.result.proof(nullifier: n.nullifier, nullifierKeyId: n.keyId);
        },
      );

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final app = AppScope.of(context);
    final r = widget.result;
    final pa = r.passiveAuth;
    final docName = switch (r.docType) {
      'P' => 'passport',
      'I' => 'ID card',
      _ => 'residence permit or travel document',
    };
    return Scaffold(
      appBar: StepTopBar(title: widget.document, step: 'Step 3 of 4'),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Text('Chip read and checked', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text('Here is exactly what this phone checked on your $docName.',
                style: TextStyle(fontSize: 16, height: 1.5, color: cs.onSurfaceVariant)),
            const SizedBox(height: 16),
            CheckRow('Chip unlocked (${r.accessProtocol})'),
            CheckRow('Nothing on it was changed',
                detail: "The data matches the hashes in the chip's seal (data groups ${pa.dataGroupsChecked.join(', ')})."),
            CheckRow("The seal's signature is valid", detail: pa.signatureAlgorithm),
            CheckRow('The seal belongs to a real country',
                detail: pa.cscaCountry == 'UT'
                    ? 'Signed by the V18 TEST country (test mode only).'
                    : 'Signed by the country certificate of ${pa.cscaCountry ?? 'the issuer'} (ICAO master list).'),
            CheckRow('Copy test (Active Authentication)',
                state: r.activeAuth == ActiveAuthResult.passed ? CheckState.done : CheckState.notChecked,
                detail: switch (r.activeAuth) {
                  ActiveAuthResult.passed => 'The chip proved it holds its secret key, so it is not a copy.',
                  ActiveAuthResult.notOffered => "This chip doesn't offer the copy test.",
                  ActiveAuthResult.notSupported => "This chip's kind of copy test (RSA) is not checked by V18 yet.",
                  ActiveAuthResult.failed => 'Failed.',
                }),
            const CheckRow('18 or older (checked on this phone)'),
            const SizedBox(height: 16),
            InfoPanel(
              color: cs.secondaryContainer,
              icon: Icons.delete_outline,
              iconColor: cs.onSecondaryContainer,
              child: Text('Your name and birth date were deleted from this phone as soon as they were checked.',
                  style: TextStyle(color: cs.onSecondaryContainer)),
            ),
          ]),
        ),
        BottomActions(children: [
          FilledButton(
            key: const Key('chip-continue'),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute(
              builder: (_) => SetLockScreen(methodTitle: widget.document, next: (_) => _issueScreen(app)),
            )),
            child: const Text('Continue'),
          ),
          TextButton(onPressed: () => goHome(context), child: const Text('Cancel')),
        ]),
      ]),
    );
  }
}
