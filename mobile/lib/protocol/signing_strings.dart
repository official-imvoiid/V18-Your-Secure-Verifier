/// Device signing strings from PROTOCOL.md section 3.4.
///
/// Fields are joined with "\n" and there is no trailing newline. The device
/// key signs the UTF-8 bytes of these strings.
library;

String _join(List<String> parts) {
  for (final p in parts) {
    if (p.contains('\n')) {
      throw ArgumentError('Signing string fields must not contain newlines');
    }
  }
  return parts.join('\n');
}

/// Issue card (proof of possession).
String cardIssueSigningString({
  required String challenge,
  required String deviceKeyThumbprint,
}) =>
    _join(['v18-card-issue', challenge, deviceKeyThumbprint]);

/// Request ticket.
String ticketRequestSigningString({
  required String cardId,
  required String challenge,
  required String keyId,
  required String blindedMessage,
}) =>
    _join(['v18-ticket-request', cardId, challenge, keyId, blindedMessage]);

/// Approve device link.
String linkApproveSigningString({
  required String cardId,
  required String challenge,
  required String linkId,
}) =>
    _join(['v18-link-approve', cardId, challenge, linkId]);

/// Delete card.
String cardDeleteSigningString({
  required String cardId,
  required String challenge,
}) =>
    _join(['v18-card-delete', cardId, challenge]);

/// Nullifier blind-sign request (PROTOCOL 4c.2).
String nullifierSigningString({
  required String challenge,
  required String deviceKeyThumbprint,
  required String blindedMessage,
}) =>
    _join(['v18-nullifier', challenge, deviceKeyThumbprint, blindedMessage]);
