import { CardResponse, CardService } from '../cards/service.js';
import { ChallengeService } from '../challenge/service.js';
import { DocRepo } from '../db/state.js';
import { DeviceKey, parseDevicePublicKey, signingStrings } from '../device/device-keys.js';
import { ApiError } from '../errors.js';
import { Clock, isPlainObject, randomId, systemClock } from '../util.js';

/**
 * Device link (protocol 3.9): copy an age card onto a second device (the PC)
 * without scanning the ID again. The phone approves with its own card.
 * The new card is bound to the PC's key, shares the phone card's nullifier
 * (so it counts toward the cap) and ends no later than the phone card.
 * Links are stored in the database, so any server copy can serve any step.
 */

interface DeviceLink {
  linkId: string;
  deviceKey: Pick<DeviceKey, 'alg' | 'jwk' | 'thumbprint'>;
  /** "approving" is held only while the new card is being made. */
  status: 'waiting' | 'approving' | 'approved';
  card?: CardResponse;
  cardDelivered: boolean;
  expiresAt: number;
}

export const LINK_ID_PATTERN = /^link_[A-Za-z0-9_-]{22}$/;
const KEEP_AFTER_EXPIRY_MS = 5 * 60_000;

export class LinkService {
  constructor(
    private readonly cards: CardService,
    private readonly challenges: ChallengeService,
    private readonly docs: DocRepo,
    private readonly opts: { publicUrl: string; ttlSeconds: number },
    private readonly clock: Clock = systemClock
  ) {}

  /** POST /v1/card/link/start {devicePublicKey, challenge, deviceSignature} (called by the PC). */
  async start(rawBody: unknown) {
    const body = isPlainObject(rawBody) ? rawBody : {};
    const challenge = await this.challenges.consumeOrThrow(body.challenge);
    const deviceKey = await parseDevicePublicKey(body.devicePublicKey);
    this.cards.requireProofOfPossession(deviceKey, body.deviceSignature, challenge);

    const link: DeviceLink = {
      linkId: randomId('link'),
      deviceKey: { alg: deviceKey.alg, jwk: deviceKey.jwk, thumbprint: deviceKey.thumbprint },
      status: 'waiting',
      cardDelivered: false,
      expiresAt: this.clock() + this.opts.ttlSeconds * 1000,
    };
    await this.docs.insert('link', link.linkId, link, link.expiresAt + KEEP_AFTER_EXPIRY_MS);
    return {
      linkId: link.linkId,
      deepLink: `v18://link?id=${link.linkId}&server=${encodeURIComponent(this.opts.publicUrl)}`,
      expiresIn: this.opts.ttlSeconds,
      expiresAt: new Date(link.expiresAt).toISOString(),
    };
  }

  private notFound(): ApiError {
    return new ApiError(404, 'LINK_NOT_FOUND', 'Device link not found or expired');
  }

  private async find(linkId: string): Promise<DeviceLink> {
    const link = LINK_ID_PATTERN.test(linkId) ? await this.docs.get<DeviceLink>('link', linkId) : null;
    if (!link) throw this.notFound();
    return link;
  }

  private change<R>(linkId: string, fn: (l: DeviceLink) => { value?: DeviceLink; result: R }): Promise<R> {
    // R is the caller's result type; DocRepo does the compare-and-set.
    return this.docs.update<DeviceLink, R>('link', linkId, (l) => {
      if (!l) throw this.notFound();
      return fn(l);
    });
  }

  /** POST /v1/card/link/:linkId/approve {cardId, challenge, deviceSignature} (called by the phone). */
  async approve(linkId: string, rawBody: unknown) {
    const link = await this.find(linkId);
    if (link.status !== 'waiting') throw new ApiError(409, 'LINK_USED', 'This link was already used');
    if (this.clock() > link.expiresAt) throw new ApiError(410, 'LINK_EXPIRED', 'This link has expired');

    const body = isPlainObject(rawBody) ? rawBody : {};
    const challenge = await this.challenges.consumeOrThrow(body.challenge);
    const phoneCard = await this.cards.requireActiveCard(body.cardId, body.deviceSignature, (cardId) =>
      signingStrings.linkApprove(cardId, challenge, linkId)
    );

    // Claim the link first, so two approvals (even on two server copies) cannot both make a card.
    await this.change(linkId, (l) => {
      if (l.status !== 'waiting') throw new ApiError(409, 'LINK_USED', 'This link was already used');
      return { value: { ...l, status: 'approving' }, result: null };
    });
    let card: CardResponse;
    try {
      card = await this.cards.createCard({
        method: phoneCard.method,
        deviceKey: link.deviceKey,
        nullifierHash: phoneCard.nullifierHash,
        assuranceLevel: phoneCard.assuranceLevel,
        minAgeCertified: phoneCard.minAgeCertified,
        validUntilMs: Date.parse(phoneCard.validUntil),
      });
    } catch (err) {
      await this.change(linkId, (l) => ({ value: { ...l, status: 'waiting' }, result: null })).catch(() => undefined);
      throw err;
    }
    await this.change(linkId, (l) => ({ value: { ...l, status: 'approved', card }, result: null }));
    return { status: 'approved' as const, validUntil: card.validUntil };
  }

  /** GET /v1/card/link/:linkId (polled by the PC). The new card is returned ONCE. */
  async poll(linkId: string) {
    if (!LINK_ID_PATTERN.test(linkId)) throw this.notFound();
    return this.change<Record<string, unknown>>(linkId, (link) => {
      if (link.status === 'approved') {
        if (link.card) {
          return { value: { ...link, card: undefined, cardDelivered: true }, result: { status: 'approved' as const, card: link.card } };
        }
        return { result: { status: 'approved' as const, cardDelivered: true } };
      }
      if (this.clock() > link.expiresAt) return { result: { status: 'expired' as const } };
      return {
        result: { status: 'waiting' as const, expiresIn: Math.max(0, Math.floor((link.expiresAt - this.clock()) / 1000)) },
      };
    });
  }

  close(): void {}
}
