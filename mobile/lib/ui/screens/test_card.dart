import 'dart:math';

import 'package:flutter/material.dart';

import '../../app_state.dart';
import '../../crypto/b64.dart';
import '../widgets.dart';
import 'card_flow.dart';

/// TEST ONLY: makes a `test_dev` card (PROTOCOL 3.5) on a dev-mode server.
/// Only reachable when GET /v1/health says devMode is true.
class TestCardScreen extends StatefulWidget {
  const TestCardScreen({super.key});

  @override
  State<TestCardScreen> createState() => _TestCardScreenState();
}

class _TestCardScreenState extends State<TestCardScreen> {
  DateTime _birth = DateTime(2000, 1, 1);
  late final TextEditingController _subject = TextEditingController(
      text: 'test-${b64urlEncode(List<int>.generate(6, (_) => Random.secure().nextInt(256)))}');

  @override
  void dispose() {
    _subject.dispose();
    super.dispose();
  }

  String get _birthText =>
      '${_birth.year.toString().padLeft(4, '0')}-${_birth.month.toString().padLeft(2, '0')}-${_birth.day.toString().padLeft(2, '0')}';

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final cs = Theme.of(context).colorScheme;
    if (!app.devMode) {
      return Scaffold(
        appBar: AppBar(),
        body: const Padding(
          padding: EdgeInsets.all(24),
          child: Text('Test cards only work with a dev-mode V18 server.'),
        ),
      );
    }
    return Scaffold(
      appBar: const StepTopBar(title: 'Test ID', step: 'TEST MODE'),
      body: Column(children: [
        Expanded(
          child: ListView(padding: const EdgeInsets.fromLTRB(24, 8, 24, 0), children: [
            Text('Make a test card', style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 12),
            const NoticeBox(
                'This uses the dev server\'s test issuer. It reads no ID and proves nothing about '
                'anyone. It exists only to test tickets end to end. Use made-up values.',
                title: 'TEST ONLY'),
            const SizedBox(height: 20),
            TextField(
              controller: _subject,
              decoration: const InputDecoration(
                  labelText: 'Test subject ID (made up)', border: OutlineInputBorder()),
            ),
            const SizedBox(height: 16),
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Test birth date (made up)'),
              subtitle: Text(_birthText),
              trailing: const Icon(Icons.edit_calendar),
              onTap: () async {
                final d = await showDatePicker(
                  context: context,
                  initialDate: _birth,
                  firstDate: DateTime(1900),
                  lastDate: DateTime.now(),
                );
                if (d != null) setState(() => _birth = d);
              },
            ),
            Text('Pick a date less than 18 years ago to test the under-18 answer.',
                style: TextStyle(fontSize: 13, color: cs.onSurfaceVariant)),
          ]),
        ),
        BottomActions(children: [
          FilledButton(
            onPressed: _subject.text.trim().isEmpty
                ? null
                : () {
                    final subject = _subject.text.trim();
                    final birth = _birthText;
                    Navigator.of(context).push(MaterialPageRoute(
                      builder: (_) => SetLockScreen(
                        methodTitle: 'Test ID',
                        next: (_) => IssueProgressScreen(
                          methodTitle: 'Test ID',
                          stepLabel: 'TEST MODE',
                          method: 'test_dev',
                          steps: const [
                            IssueStep('Test details entered', alreadyDone: true),
                            IssueStep('Making a lock key in the secure chip'),
                            IssueStep('Sending the test details'),
                          ],
                          proofStepIndex: 1,
                          doneTitle: 'Your TEST card is ready',
                          doneBody: 'This card is for testing only. It is saved in the secure chip.',
                          buildProof: (challenge, thumb, report) async =>
                              {'testSubjectId': subject, 'birthDate': birth},
                        ),
                      ),
                    ));
                  },
            child: const Text('Continue'),
          ),
        ]),
      ]),
    );
  }
}
