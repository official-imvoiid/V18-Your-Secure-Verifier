import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import '../aadhaar/anon_aadhaar.dart';
import '../aadhaar/artifacts.dart';
import '../api/v18_api.dart';
import '../crypto/b64.dart';
import '../crypto/rfc9474.dart';
import '../device/device_key.dart';
import '../device/platform_checks.dart';
import '../protocol/deep_links.dart';
import '../protocol/signing_strings.dart';
import '../protocol/ticket.dart';
import '../storage/card_store.dart';

/// Why a flow stopped. Each kind has its own screen or message.
enum FailureKind {
  offline,
  cancelled,
  cardExpired,
  childAccount,
  wrongServer,
  siteNeedsHigherAge,
  noTicketKey,
  keyInvalidated,
  noLock,
  sessionGone,
  codeMismatch,
  under18,
  methodNotReady,
  methodDisabled,
  tooManyCards,
  proofFailed,
  attestation,
  server,
  other,
}

class FlowFailure implements Exception {
  const FlowFailure(this.kind, this.message);
  final FailureKind kind;

  /// Plain English, safe to show.
  final String message;

  @override
  String toString() => 'FlowFailure($kind: $message)';

  /// Turns any error from the API, the device key or the crypto into a
  /// [FlowFailure].
  static FlowFailure from(Object e) {
    if (e is FlowFailure) return e;
    if (e is ProverFailed) {
      return FlowFailure(FailureKind.proofFailed, e.message);
    }
    if (e is ArtifactException) {
      return FlowFailure(FailureKind.proofFailed, e.message);
    }
    if (e is OfflineException) {
      return const FlowFailure(FailureKind.offline,
          "You're offline. Connect to Wi-Fi or mobile data, then try again.");
    }
    if (e is DeviceKeyException) {
      return switch (e.code) {
        'cancelled' => const FlowFailure(FailureKind.cancelled, 'Cancelled.'),
        'key_invalidated' => const FlowFailure(FailureKind.keyInvalidated,
            "Your phone's fingerprints or screen lock changed, so this card's lock was reset for safety. Delete the card and make a new one."),
        'no_lock' => const FlowFailure(FailureKind.noLock,
            'Set up a screen lock (fingerprint, face unlock or PIN) on this phone first.'),
        'locked_out' => const FlowFailure(FailureKind.cancelled,
            'Too many tries. Wait a little, then try again.'),
        'no_key' => const FlowFailure(FailureKind.keyInvalidated,
            "This card's lock key is missing from the phone. Delete the card and make a new one."),
        _ => FlowFailure(FailureKind.other, "The phone's lock didn't work (${e.code})."),
      };
    }
    if (e is V18ApiException) {
      return switch (e.code) {
        // CARD_REQUIRED carries a reason (docs/server/API.md).
        'CARD_REQUIRED' when e.reason == 'card_expired' =>
          const FlowFailure(FailureKind.cardExpired, 'Your age card has expired.'),
        'CARD_REQUIRED' when e.reason == 'bad_signature' || e.reason == 'missing_signature' =>
          const FlowFailure(FailureKind.keyInvalidated,
              "The server didn't accept this card's lock key. Delete the card and make a new one."),
        'CARD_REQUIRED' || 'CARD_REVOKED' || 'CARD_NOT_FOUND' => const FlowFailure(
            FailureKind.cardExpired, 'This age card is no longer active. Make a new one.'),
        'CARD_EXPIRED' => const FlowFailure(FailureKind.cardExpired, 'Your age card has expired.'),
        'SESSION_EXPIRED' || 'SESSION_NOT_FOUND' || 'ALREADY_SUBMITTED' => const FlowFailure(
            FailureKind.sessionGone, 'This website code has expired. Go back and try again.'),
        'LINK_EXPIRED' || 'LINK_USED' || 'LINK_NOT_FOUND' => const FlowFailure(
            FailureKind.sessionGone, 'This PC code has expired or was already used. Make a new one on the PC.'),
        'MIN_AGE_NOT_CERTIFIED' || 'MIN_AGE_UNSUPPORTED' => const FlowFailure(
            FailureKind.siteNeedsHigherAge, 'Your age card cannot prove the age this site needs.'),
        'KEY_NOT_CURRENT' => const FlowFailure(FailureKind.server,
            'The V18 server just changed its ticket key. Try again.'),
        'CHALLENGE_INVALID' => const FlowFailure(FailureKind.server,
            'That took too long, so the one-time number ran out. Try again.'),
        'ID_EXPIRED' => const FlowFailure(FailureKind.server,
            'This ID has expired. Use an ID that is still valid.'),
        'PROOF_INVALID' => const FlowFailure(FailureKind.server,
            "The V18 server couldn't confirm the proof from this ID."),
        'METHOD_NOT_READY' || 'METHOD_NOT_CONFIGURED' => const FlowFailure(FailureKind.methodNotReady,
            "This V18 server doesn't accept this kind of ID. Pick another way."),
        'ATTESTATION_INVALID' || 'ATTESTATION_REQUIRED' || 'BAD_ATTESTATION' => const FlowFailure(
            FailureKind.attestation,
            "The V18 server couldn't confirm this phone's security chip, so it can't accept a chip-checked ID from it."),
        'METHOD_DISABLED' => const FlowFailure(FailureKind.methodDisabled,
            'This way of making a card is turned off on this server.'),
        'NULLIFIER_OVERUSED' => const FlowFailure(FailureKind.tooManyCards,
            'This ID already has the most age cards allowed. Delete an old card first.'),
        'UNDER_AGE' || 'UNDER_18' || 'AGE_REQUIREMENT_NOT_MET' => const FlowFailure(
            FailureKind.under18, 'The ID shows the person is under 18.'),
        'RATE_LIMITED' => const FlowFailure(FailureKind.server,
            'Too many tickets in the last hour. Try again later.'),
        _ when e.status == 410 ||
                (e.status == 404 && e.message.toLowerCase().contains('session')) =>
          const FlowFailure(FailureKind.sessionGone, 'This website code has expired. Go back and try again.'),
        _ => FlowFailure(FailureKind.server, 'The V18 server said no: ${e.message} (${e.code}).'),
      };
    }
    if (e is BlindRsaException) {
      return const FlowFailure(FailureKind.server,
          "The server's ticket seal didn't check out, so nothing was sent.");
    }
    return FlowFailure(FailureKind.other, 'Something went wrong. Try again. ($e)');
  }
}

/// Everything the flows need, so tests can swap in fakes.
class V18Services {
  V18Services({
    required this.keys,
    required this.checks,
    required this.apiFor,
    DateTime Function()? now,
    Random? random,
  })  : now = now ?? DateTime.now,
        random = random ?? Random.secure();

  final DeviceKeyService keys;
  final PlatformChecks checks;
  final V18Api Function(String server) apiFor;
  final DateTime Function() now;
  final Random random;
}

/// Builds the method-specific `proof` once the challenge and device key exist.
typedef ProofBuilder = Future<Map<String, Object?>> Function(
    String challenge, String deviceKeyThumbprint);

/// POST /v1/card/issue with a new device key (PROTOCOL 3.4, 3.5).
///
/// With [attest] the key is made with the request's challenge as its
/// attestation challenge, and the chain goes in `keyAttestation` (4c.3).
Future<AgeCard> issueCard(
  V18Services s, {
  required String server,
  required String method,
  required ProofBuilder buildProof,
  bool attest = false,
}) async {
  final api = s.apiFor(server);
  final alias = newDeviceKeyAlias(random: s.random);
  var keyMade = false;
  try {
    final challenge = await api.challenge();
    final key = await s.keys.createKey(alias, attestationChallenge: attest ? challenge : null);
    keyMade = true;
    if (attest && (key.attestation == null || key.attestation!.isEmpty)) {
      throw const FlowFailure(FailureKind.attestation,
          "This phone couldn't prove its security chip (no key attestation).");
    }
    final proof = await buildProof(challenge, key.thumbprint);
    final sig = await s.keys.sign(
      alias,
      cardIssueSigningString(challenge: challenge, deviceKeyThumbprint: key.thumbprint),
      title: 'Lock your age card',
      subtitle: 'Unlock to save the card on this phone',
    );
    final issued = await api.issueCard(
      method: method,
      challenge: challenge,
      devicePublicKey: key.jwkWithAlg,
      deviceSignature: sig,
      proof: proof,
      keyAttestation: attest ? key.keyAttestation : null,
    );
    return AgeCard(
      cardId: issued.cardId,
      method: issued.method,
      validUntil: issued.validUntil,
      keyAlias: alias,
      server: server,
    );
  } on Object catch (e) {
    if (keyMade) {
      try {
        await s.keys.deleteKey(alias);
      } on Object {
        // Best effort.
      }
    }
    throw FlowFailure.from(e);
  }
}

/// Checks done before showing the "send 18+ ticket" button.
Future<void> preflightTicket(V18Services s, VerifyLink link, AgeCard card) async {
  if (card.isExpired(s.now())) {
    throw const FlowFailure(FailureKind.cardExpired, 'Your age card has expired.');
  }
  if (card.server != link.server) {
    throw const FlowFailure(FailureKind.wrongServer,
        "This website uses a different V18 server from your age card's.");
  }
  if (link.minAge > card.minAgeCertified) {
    throw FlowFailure(FailureKind.siteNeedsHigherAge,
        'This site asks for ${link.minAge}+. V18 age cards prove 18+ only, for now.');
  }
  if (await s.checks.childAccountStatus() == ChildAccountStatus.child) {
    throw const FlowFailure(FailureKind.childAccount, 'This phone has a child account.');
  }
}

/// Tells the website the phone has the code, and checks the session matches
/// the code (so a changed QR is caught).
Future<void> connectToSession(V18Services s, VerifyLink link) async {
  final api = s.apiFor(link.server);
  try {
    final info = await api.pairingGet(link.sessionId);
    final o = info['origin'];
    final c = info['challenge'];
    if ((o is String && normalizeWebOrigin(o, debug: true) != link.origin) ||
        (c is String && c != link.challenge)) {
      throw const FlowFailure(FailureKind.codeMismatch,
          "This code doesn't match the website's request. Nothing was sent.");
    }
    final status = info['status'];
    // "approved" means a ticket was already handed in for this session.
    if (status is String &&
        (status == 'expired' || status == 'cancelled' || status == 'approved' || status == 'completed')) {
      throw const FlowFailure(FailureKind.sessionGone, 'This website code has expired. Go back and try again.');
    }
    await api.pairingConnect(link.sessionId);
  } on V18ApiException catch (e) {
    if (e.status == 404 || e.status == 410) {
      throw const FlowFailure(FailureKind.sessionGone, 'This website code has expired. Go back and try again.');
    }
    throw FlowFailure.from(e);
  } on Object catch (e) {
    throw FlowFailure.from(e);
  }
}

class TicketSent {
  TicketSent(this.expiresAt, this.keyId);
  final DateTime expiresAt;
  final String keyId;
}

/// Makes the one-time ticket with blind signatures and hands it to the
/// website through the pairing session (PROTOCOL 3.6, 3.8).
Future<TicketSent> sendTicket(V18Services s, VerifyLink link, AgeCard card) async {
  final api = s.apiFor(link.server);
  try {
    await preflightTicket(s, link, card);
    final now = s.now();
    final key = selectTicketKey(await api.keys(),
        siteMinAge: link.minAge, cardMinAge: card.minAgeCertified, now: now);
    if (key == null) {
      throw const FlowFailure(FailureKind.noTicketKey,
          'The V18 server has no ticket key for this age right now.');
    }
    final message = TicketMessage.create(
      origin: link.origin,
      challenge: link.challenge,
      minAge: link.minAge,
      now: now,
      random: s.random,
    );
    final client = BlindRsaClient(BlindRsaVariant.sha384PssRandomized, random: s.random);
    final prepared = client.prepare(message.toBytes());
    final blinding = client.blind(key.publicKey, prepared);
    final blinded = b64urlEncode(blinding.blindedMessage);
    final challenge = await api.challenge();
    final sig = await s.keys.sign(
      card.keyAlias,
      ticketRequestSigningString(
          cardId: card.cardId, challenge: challenge, keyId: key.kid, blindedMessage: blinded),
      title: "Confirm it's you",
      subtitle: 'Send a one-time 18+ ticket to ${link.displayHost}',
    );
    final res = await api.blindSign(
      cardId: card.cardId,
      challenge: challenge,
      keyId: key.kid,
      blindedMessage: blinded,
      deviceSignature: sig,
    );
    if (res.keyId != key.kid) {
      throw const FlowFailure(FailureKind.server, 'The server used a different ticket key.');
    }
    final signature = client.finalize(
        key.publicKey, prepared, b64urlDecode(res.blindSignature), blinding.inverse);
    final ticket = buildTicketString(keyId: key.kid, prepared: prepared, signature: signature);
    await api.pairingSubmit(link.sessionId, ticket);
    return TicketSent(
        DateTime.fromMillisecondsSinceEpoch(message.expiresAt * 1000), key.kid);
  } on Object catch (e) {
    throw FlowFailure.from(e);
  }
}

/// Approves a PC's request for its own age card (PROTOCOL 3.9).
/// The phone never calls GET /v1/card/link/:id, so it cannot take the PC's card.
Future<void> approveDeviceLink(V18Services s, LinkApprovalLink link, AgeCard card) async {
  try {
    if (card.isExpired(s.now())) {
      throw const FlowFailure(FailureKind.cardExpired, 'Your age card has expired.');
    }
    if (card.server != link.server) {
      throw const FlowFailure(FailureKind.wrongServer,
          "This PC uses a different V18 server from your age card's.");
    }
    final api = s.apiFor(link.server);
    final challenge = await api.challenge();
    final sig = await s.keys.sign(
      card.keyAlias,
      linkApproveSigningString(cardId: card.cardId, challenge: challenge, linkId: link.linkId),
      title: "Confirm it's you",
      subtitle: 'Give your PC its own age card',
    );
    await api.approveLink(
        linkId: link.linkId, cardId: card.cardId, challenge: challenge, deviceSignature: sig);
  } on Object catch (e) {
    throw FlowFailure.from(e);
  }
}

/// DELETE /v1/card/:cardId, then removes the key and the stored card.
Future<void> deleteCardEverywhere(V18Services s, AgeCard card) async {
  try {
    final api = s.apiFor(card.server);
    final challenge = await api.challenge();
    final sig = await s.keys.sign(
      card.keyAlias,
      cardDeleteSigningString(cardId: card.cardId, challenge: challenge),
      title: 'Delete your age card',
      subtitle: 'Unlock to delete the card',
    );
    await api.deleteCard(cardId: card.cardId, challenge: challenge, deviceSignature: sig);
    await s.keys.deleteKey(card.keyAlias);
  } on Object catch (e) {
    throw FlowFailure.from(e);
  }
}

/// Gets the document's nullifier from the server's oblivious PRF
/// (PROTOCOL 4c.2): RFC 9474 RSABSSA-SHA384-PSSZERO-Deterministic.
///
/// The server never sees [message] (it holds the document number). It signs
/// a blinded copy; the phone unblinds it and the nullifier is
/// base64url(SHA-256(signature)). Because the signature is deterministic, the
/// same document always gives the same nullifier.
///
/// The request uses its own short-lived attested key (4c.3), made with this
/// request's challenge and deleted right after; see the Design notes.
Future<NullifierResult> obtainNullifier(V18Services s, {required String server, required String message}) async {
  final api = s.apiFor(server);
  final alias = newDeviceKeyAlias(random: s.random);
  var keyMade = false;
  final msgBytes = Uint8List.fromList(utf8.encode(message));
  try {
    final nk = await api.nullifierKey();
    final client = BlindRsaClient(BlindRsaVariant.sha384PssZeroDeterministic, random: s.random);
    final prepared = client.prepare(msgBytes);
    final blinding = client.blind(nk.publicKey, prepared);
    final blinded = b64urlEncode(blinding.blindedMessage);
    final challenge = await api.challenge();
    final key = await s.keys.createKey(alias, attestationChallenge: challenge, userAuth: false);
    keyMade = true;
    final sig = await s.keys.signNoAuth(
        alias,
        nullifierSigningString(
            challenge: challenge, deviceKeyThumbprint: key.thumbprint, blindedMessage: blinded));
    final blindSig = await api.nullifierBlindSign(
      challenge: challenge,
      blindedMessage: blinded,
      devicePublicKey: key.jwkWithAlg,
      deviceSignature: sig,
      keyAttestation: key.keyAttestation,
    );
    final signature = client.finalize(nk.publicKey, prepared, blindSig, blinding.inverse);
    prepared.fillRange(0, prepared.length, 0);
    final digest = pc.SHA256Digest().process(signature);
    return NullifierResult(b64urlEncode(digest), nk.kid);
  } on Object catch (e) {
    throw FlowFailure.from(e);
  } finally {
    msgBytes.fillRange(0, msgBytes.length, 0);
    if (keyMade) {
      try {
        await s.keys.deleteKey(alias);
      } on Object {
        // Best effort.
      }
    }
  }
}

class NullifierResult {
  NullifierResult(this.nullifier, this.keyId);
  final String nullifier;
  final String keyId;
}
