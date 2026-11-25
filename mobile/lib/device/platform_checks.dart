import 'package:flutter/services.dart';

enum ChildAccountStatus {
  /// The phone told us this is a supervised (child) account.
  child,

  /// The phone told us this is not a child account.
  notChild,

  /// Android gives normal apps no way to know. This is the usual answer today.
  unknown,
}

/// Play Integrity (PROTOCOL 4c.3) is optional and OFF by default: it needs a
/// Google Play Console project, and the v1 server does not check verdicts.
/// The app shows no integrity step at all unless a build sets
/// `--dart-define=V18_PLAY_INTEGRITY=<cloud project number>`; see
/// docs/mobile/WALKTHROUGH.md "Not in v1".
const String playIntegrityProject = String.fromEnvironment('V18_PLAY_INTEGRITY');
bool get playIntegrityConfigured => playIntegrityProject.isNotEmpty;

/// Checks about the phone itself. See docs/mobile/WALKTHROUGH.md for what
/// Android can and cannot tell an app.
class PlatformChecks {
  PlatformChecks({MethodChannel? channel}) : _ch = channel ?? const MethodChannel('com.v18.app/platform');

  final MethodChannel _ch;

  /// Debug builds only (Settings > Test tools): shows the child-account screen.
  bool simulateChildAccount = false;

  Future<ChildAccountStatus> childAccountStatus() async {
    if (simulateChildAccount) return ChildAccountStatus.child;
    try {
      final s = await _ch.invokeMethod<String>('childAccountStatus');
      return switch (s) {
        'child' => ChildAccountStatus.child,
        'not_child' => ChildAccountStatus.notChild,
        _ => ChildAccountStatus.unknown,
      };
    } on Object {
      return ChildAccountStatus.unknown;
    }
  }

  /// The phone has NFC hardware (it may still be switched off).
  Future<bool> hasNfc() async {
    try {
      return await _ch.invokeMethod<bool>('hasNfc') ?? false;
    } on Object {
      return false;
    }
  }

  /// Android Credential Manager can ask wallets for digital credentials.
  Future<bool> hasDigitalCredentials() async {
    try {
      return await _ch.invokeMethod<bool>('hasDigitalCredentials') ?? false;
    } on Object {
      return false;
    }
  }
}
