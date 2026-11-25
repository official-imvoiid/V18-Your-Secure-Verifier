import * as crypto from 'node:crypto';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { CardService, cardRequired } from '../cards/service.js';
import { ChallengeService } from '../challenge/service.js';
import { parseDeviceSignature, signingStrings } from '../device/device-keys.js';
import { ApiError, badRequest } from '../errors.js';
import { TICKET_ALGORITHM, TicketKeyService } from '../keys/ticket-keys.js';
import { Clock, decodeBase64url, isBase64url, isPlainObject, toBase64url } from '../util.js';
import { RateLimiter } from './rate-limit.js';

export interface BlindSignResponse {
  blindSignature: string;
  keyId: string;
  algorithm: typeof TICKET_ALGORITHM;
}

/**
 * POST /v1/ticket/blind-sign (protocol 3.6).
 *
 * The server signs a BLINDED ticket. It never sees the ticket itself, so it
 * cannot know which site the ticket is for. It only signs for a device that
 * holds an active age card, and only with a key the card is old enough for.
 */
export class TicketService {
  private readonly suite = RSABSSA.SHA384.PSS.Randomized();

  constructor(
    private readonly cards: CardService,
    private readonly keys: TicketKeyService,
    private readonly challenges: ChallengeService,
    private readonly limiter: RateLimiter,
    private readonly clock: Clock,
    private readonly onSigned?: () => void
  ) {}

  async blindSign(rawBody: unknown): Promise<BlindSignResponse> {
    const body = isPlainObject(rawBody) ? rawBody : {};

    // No card or no device signature at all: 401 CARD_REQUIRED straight away.
    if (typeof body.cardId !== 'string' || body.cardId.length === 0) throw cardRequired('missing_card');
    if (!parseDeviceSignature(body.deviceSignature)) throw cardRequired('missing_signature');

    // 1. The challenge is valid, and is used up whatever happens next.
    const challenge = await this.challenges.consumeOrThrow(body.challenge);

    const keyId = body.keyId;
    const blindedMessage = body.blindedMessage;
    if (typeof keyId !== 'string' || keyId.length === 0 || keyId.length > 64) {
      throw badRequest('Missing field: keyId');
    }
    if (!isBase64url(blindedMessage)) {
      throw badRequest('blindedMessage must be base64url without padding');
    }

    // 2. Active, unexpired card, and a valid device signature for its key.
    const card = await this.cards.requireActiveCard(body.cardId, body.deviceSignature, (cardId) =>
      signingStrings.ticketRequest(cardId, challenge, keyId, blindedMessage)
    );

    // 3. The key is current.
    await this.keys.refresh();
    const key = this.keys.find(keyId);
    if (!key || !this.keys.isCurrent(key)) {
      throw new ApiError(400, 'KEY_NOT_CURRENT', `Key ${keyId} is not a current signing key. Fetch GET /v1/keys and use the current key.`);
    }

    // 4. The key's age threshold is no more than the card's certified age.
    if (key.minAge > card.minAgeCertified) {
      throw new ApiError(
        403,
        'MIN_AGE_NOT_CERTIFIED',
        `This card certifies age ${card.minAgeCertified}+, but key ${keyId} is for ${key.minAge}+`
      );
    }

    // 5. The blinded message fits the key (checked before it counts toward the limit).
    const blinded = decodeBase64url(blindedMessage, 'blindedMessage', 1024);
    const kLen = Math.ceil(key.modulusBits / 8);
    if (blinded.length !== kLen) {
      throw new ApiError(400, 'BAD_BLINDED_MESSAGE', `blindedMessage must be ${kLen} bytes for key ${keyId}`);
    }

    // 6. Rate limit per card.
    await this.limiter.takeOrThrow(card.cardId, 'This card asked for too many tickets in the last hour. Try again later.');

    const signature = await this.keys.blindSign(key, blinded);
    this.onSigned?.();
    return { blindSignature: toBase64url(signature), keyId: key.kid, algorithm: TICKET_ALGORITHM };
  }

  /**
   * Makes a complete ticket on the server (format 3.6), for a website's
   * pairing session after a phone wallet proved age_over_18 (4c.5). The
   * server already knows that session's origin and challenge, so nothing new
   * is revealed. It uses the same RFC 9474 steps as an app (prepare, blind,
   * blind-sign, finalize), so the result is an ordinary ticket.
   */
  async issueDirect(input: { origin: string; challenge: string; minAge: number }): Promise<string> {
    await this.keys.refresh();
    const key = this.keys.currentKey(this.keys.thresholdFor(input.minAge));
    const iat = Math.floor(this.clock() / 1000);
    const payload = {
      v: 1,
      ticketId: crypto.randomBytes(16).toString('base64url'),
      origin: input.origin,
      challenge: input.challenge,
      minAge: key.minAge,
      iat,
      expiresAt: iat + 300,
    };
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: key.publicJwk.n, e: key.publicJwk.e, ext: true },
      { name: 'RSA-PSS', hash: 'SHA-384' },
      true,
      ['verify']
    );
    const prepared = this.suite.prepare(new TextEncoder().encode(JSON.stringify(payload)));
    const { blindedMsg, inv } = await this.suite.blind(publicKey, prepared);
    const blindSig = await this.keys.blindSign(key, blindedMsg);
    const signature = await this.suite.finalize(publicKey, prepared, blindSig, inv);
    this.onSigned?.();
    return `${key.kid}.${toBase64url(prepared)}.${toBase64url(signature)}`;
  }
}
