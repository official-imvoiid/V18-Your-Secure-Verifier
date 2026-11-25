import { AttestationGate } from '../attestation/gate.js';
import type { AttestationResult } from '../attestation/android.js';
import { ChallengeService } from '../challenge/service.js';
import type { Config } from '../config.js';
import type { SqlDb } from '../db/sql.js';
import {
  DeviceKey,
  keyFromStoredJwk,
  parseDevicePublicKey,
  parseDeviceSignature,
  signingStrings,
  verifyDeviceSignature,
} from '../device/device-keys.js';
import { ApiError, badRequest } from '../errors.js';
import { AnonAadhaarProofVerifier, UidaiKey, verifyAnonAadhaarProof } from '../issuers/anon-aadhaar.js';
import { canonicalAttestedMethod, verifyAttestedProof, verifyFaceProof } from '../issuers/attested.js';
import { verifyTestDevProof } from '../issuers/test-dev.js';
import { IssuerResult } from '../issuers/types.js';
import { NullifierStore } from '../nullifier/store.js';
import { Clock, iso, isPlainObject, randomId } from '../util.js';
import { CardMethod, CardRecord, CardStore } from './store.js';

export const CARD_ID_PATTERN = /^card_[A-Za-z0-9_-]{22}$/;

/** Methods accepted by POST /v1/card/issue. Connectors issue cards through /v1/connect (4d.4). */
export const ISSUE_METHODS = [
  'test_dev',
  'anon_aadhaar',
  'emrtd_attested',
  'passport_attested',
  'philsys_qr_attested',
  'mynumber_attested',
  'face_estimate',
  'mdoc_app',
  'passport_zk',
] as const;
export type IssueMethod = (typeof ISSUE_METHODS)[number];

/** The card as the app sees it (protocol 3.5 response). */
export interface CardResponse {
  cardId: string;
  method: string;
  assuranceLevel: string;
  minAgeCertified: number;
  validUntil: string;
}

export type CardState = 'active' | 'revoked' | 'expired';

export function toCardResponse(c: CardRecord, methodAsSent?: string): CardResponse {
  return {
    cardId: c.cardId,
    method: methodAsSent ?? c.method,
    assuranceLevel: c.assuranceLevel,
    minAgeCertified: c.minAgeCertified,
    validUntil: c.validUntil,
  };
}

/** 401 CARD_REQUIRED, with a `reason` so the app can explain what went wrong. */
export function cardRequired(reason: string): ApiError {
  return new ApiError(401, 'CARD_REQUIRED', `A valid age card and device signature are needed (${reason})`, {
    reason,
  });
}

/** The mdoc_app hook (implemented by the wallet service). */
export interface AppWalletVerifier {
  readonly ready: boolean;
  verifyForCard(challenge: string, proof: unknown): Promise<{ validUntilMs: number; credentialKeyHash: string; docType: string }>;
}

export interface CardServiceDeps {
  db: SqlDb;
  cards: CardStore;
  nullifiers: NullifierStore;
  challenges: ChallengeService;
  config: Config;
  clock: Clock;
  aadhaar: { verifier: AnonAadhaarProofVerifier | null; uidaiKeys: UidaiKey[] };
  attestation: AttestationGate;
  appWallet: AppWalletVerifier | null;
  onIssued?: (method: string) => void;
}

export class CardService {
  constructor(private readonly d: CardServiceDeps) {}

  stateOf(card: CardRecord): CardState {
    if (card.status === 'revoked') return 'revoked';
    return Date.parse(card.validUntil) <= this.d.clock() ? 'expired' : 'active';
  }

  /** POST /v1/card/issue */
  async issue(rawBody: unknown): Promise<CardResponse & { attestation?: unknown }> {
    const body = isPlainObject(rawBody) ? rawBody : {};
    const method = body.method;
    if (typeof method !== 'string' || !(ISSUE_METHODS as readonly string[]).includes(method)) {
      const hint = typeof method === 'string' && method.startsWith('connector') ? ' Login connectors start at POST /v1/connect/:id/start.' : '';
      throw new ApiError(400, 'METHOD_UNKNOWN', `method must be one of: ${ISSUE_METHODS.join(', ')}.${hint}`);
    }

    const challenge = await this.d.challenges.consumeOrThrow(body.challenge);
    const cfg = this.d.config;

    if (method === 'passport_zk') {
      throw new ApiError(501, 'METHOD_NOT_READY', 'passport_zk is not in v1; use emrtd_attested (PROTOCOL.md 4c, 4d.3)');
    }
    if (method === 'test_dev' && !cfg.devMode) {
      throw new ApiError(501, 'METHOD_DISABLED', 'test_dev works only on a dev-mode server (V18_DEV_MODE=1)');
    }
    if (method === 'mynumber_attested' && !cfg.enableMyNumber) {
      throw new ApiError(501, 'METHOD_DISABLED', 'mynumber_attested is not in v1 (PROTOCOL.md 4d.4b). V18_ENABLE_MYNUMBER=1 turns it on.');
    }
    if (method === 'face_estimate' && cfg.faceModels.length === 0) {
      throw new ApiError(501, 'METHOD_DISABLED', 'face_estimate is not offered by this server (no V18_FACE_MODELS)');
    }

    const deviceKey = await parseDevicePublicKey(body.devicePublicKey);
    this.requireProofOfPossession(deviceKey, body.deviceSignature, challenge);

    const now = this.d.clock();
    let result: IssuerResult;
    let storedMethod: CardMethod = method as CardMethod;
    let attestation: AttestationResult | null = null;

    switch (method) {
      case 'test_dev':
        result = verifyTestDevProof(body.proof, now);
        break;
      case 'anon_aadhaar':
        result = await verifyAnonAadhaarProof(body.proof, {
          challenge,
          deviceKeyThumbprint: deviceKey.thumbprint,
          devMode: cfg.devMode,
          nullifierSeed: cfg.aadhaarNullifierSeed,
          verifier: this.d.aadhaar.verifier,
          uidaiKeys: this.d.aadhaar.uidaiKeys,
          nowMs: now,
        });
        break;
      case 'emrtd_attested':
      case 'passport_attested':
      case 'philsys_qr_attested':
      case 'mynumber_attested': {
        const canonical = canonicalAttestedMethod(method)!;
        attestation = await this.d.attestation.check(body.keyAttestation, challenge, deviceKey.keyObject);
        result = verifyAttestedProof(canonical, body.proof, now, method === 'passport_attested');
        storedMethod = canonical;
        break;
      }
      case 'face_estimate':
        attestation = await this.d.attestation.check(body.keyAttestation, challenge, deviceKey.keyObject);
        result = verifyFaceProof(body.proof, {
          models: cfg.faceModels,
          minChallengeAge: cfg.faceChallengeAge,
          thumbprint: deviceKey.thumbprint,
          nowMs: now,
        });
        break;
      case 'mdoc_app': {
        if (!this.d.appWallet?.ready) {
          throw new ApiError(503, 'METHOD_NOT_CONFIGURED', 'mdoc_app is not set up on this server (no trusted IACA or app origin)');
        }
        if (body.keyAttestation !== undefined) {
          attestation = await this.d.attestation.check(body.keyAttestation, challenge, deviceKey.keyObject);
        }
        const w = await this.d.appWallet.verifyForCard(challenge, body.proof);
        result = {
          // A wallet shares no ID number. The credential's own holder key is
          // stable per credential, so its hash caps cards per wallet ID.
          rawNullifier: w.credentialKeyHash,
          assuranceLevel: 'substantial',
          minAgeCertified: 18,
          validUntilMs: Math.min(now + 180 * 86_400_000, w.validUntilMs),
        };
        break;
      }
      default:
        throw new ApiError(400, 'METHOD_UNKNOWN', 'Unknown method');
    }

    const card = await this.createCard({
      method: storedMethod,
      deviceKey,
      nullifierHash: NullifierStore.hashFor(storedMethod, result.rawNullifier),
      assuranceLevel: result.assuranceLevel,
      minAgeCertified: result.minAgeCertified,
      validUntilMs: result.validUntilMs,
    });
    const out: CardResponse & { attestation?: unknown } = { ...card, method };
    if (attestation) out.attestation = this.d.attestation.summary(attestation);
    return out;
  }

  /** The issue-card proof of possession: `v18-card-issue\n<challenge>\n<thumbprint>`. */
  requireProofOfPossession(deviceKey: DeviceKey, rawSignature: unknown, challenge: string): void {
    const sig = parseDeviceSignature(rawSignature);
    if (!verifyDeviceSignature(deviceKey, sig, signingStrings.cardIssue(challenge, deviceKey.thumbprint))) {
      throw new ApiError(
        401,
        'BAD_DEVICE_SIGNATURE',
        'deviceSignature does not verify over "v18-card-issue\\n<challenge>\\n<deviceKeyThumbprint>"'
      );
    }
  }

  /**
   * Stores a new card, enforcing the nullifier cap and one active card per
   * device key, in one transaction. On PostgreSQL the nullifier row and the
   * thumbprint are locked, so two server copies cannot both pass the cap.
   */
  async createCard(input: {
    method: CardMethod;
    deviceKey: Pick<DeviceKey, 'alg' | 'jwk' | 'thumbprint'>;
    nullifierHash: string;
    assuranceLevel: string;
    minAgeCertified: number;
    validUntilMs: number;
  }): Promise<CardResponse> {
    const now = this.d.clock();
    const nowIso = iso(now);
    if (input.validUntilMs <= now) {
      throw new ApiError(400, 'ID_EXPIRED', 'The card would already be expired');
    }
    const card: CardRecord = {
      cardId: randomId('card'),
      method: input.method,
      assuranceLevel: input.assuranceLevel,
      minAgeCertified: input.minAgeCertified,
      deviceKeyAlg: input.deviceKey.alg,
      deviceKeyJwk: input.deviceKey.jwk,
      deviceKeyThumbprint: input.deviceKey.thumbprint,
      nullifierHash: input.nullifierHash,
      status: 'active',
      issuedAt: nowIso,
      validUntil: iso(input.validUntilMs),
      revokedAt: null,
    };

    await this.d.db.tx(async (tx) => {
      await this.d.cards.lockThumbprint(card.deviceKeyThumbprint, tx);
      if (await this.d.cards.thumbprintInUse(card.deviceKeyThumbprint, nowIso, tx)) {
        throw new ApiError(409, 'DEVICE_KEY_IN_USE', 'This device key already has an active card. Make a new key per card.');
      }
      await this.d.nullifiers.record(card.nullifierHash, card.method, tx);
      await this.d.nullifiers.lock(card.nullifierHash, tx);
      const active = await this.d.cards.countActive(card.nullifierHash, nowIso, tx);
      if (active >= this.d.config.maxCardsPerId) {
        throw new ApiError(
          409,
          'NULLIFIER_OVERUSED',
          `This ID already has ${active} active age cards (the limit is ${this.d.config.maxCardsPerId}). Delete one first.`
        );
      }
      await this.d.cards.insert(card, tx);
    });
    this.d.onIssued?.(card.method);
    return toCardResponse(card);
  }

  /**
   * Finds an active card and checks the device signature over `signingString`.
   * Any failure is 401 CARD_REQUIRED (protocol 3.6).
   */
  async requireActiveCard(cardId: unknown, rawSignature: unknown, signingString: (cardId: string) => string): Promise<CardRecord> {
    if (typeof cardId !== 'string' || cardId.length === 0) throw cardRequired('missing_card');
    if (!CARD_ID_PATTERN.test(cardId)) throw cardRequired('unknown_card');
    const card = await this.d.cards.get(cardId);
    if (!card) throw cardRequired('unknown_card');
    const sig = parseDeviceSignature(rawSignature);
    if (!sig) throw cardRequired('missing_signature');
    let keyObject;
    try {
      keyObject = keyFromStoredJwk(card.deviceKeyAlg, card.deviceKeyJwk);
    } catch {
      throw cardRequired('unknown_card');
    }
    if (!verifyDeviceSignature({ alg: card.deviceKeyAlg, keyObject }, sig, signingString(cardId))) {
      throw cardRequired('bad_signature');
    }
    const state = this.stateOf(card);
    if (state !== 'active') throw cardRequired(state === 'revoked' ? 'card_revoked' : 'card_expired');
    return card;
  }

  /** GET /v1/card/:cardId/status. Reveals only status and validUntil. */
  async status(cardId: string): Promise<{ status: CardState; validUntil: string }> {
    const card = CARD_ID_PATTERN.test(cardId) ? await this.d.cards.get(cardId) : null;
    if (!card) throw new ApiError(404, 'CARD_NOT_FOUND', 'No such card');
    return { status: this.stateOf(card), validUntil: card.validUntil };
  }

  /** DELETE /v1/card/:cardId with {challenge, deviceSignature}. Frees the nullifier slot. */
  async revoke(cardId: string, rawBody: unknown): Promise<{ cardId: string; status: 'revoked' }> {
    const body = isPlainObject(rawBody) ? rawBody : {};
    const challenge = await this.d.challenges.consumeOrThrow(body.challenge);
    const card = CARD_ID_PATTERN.test(cardId) ? await this.d.cards.get(cardId) : null;
    if (!card) throw new ApiError(404, 'CARD_NOT_FOUND', 'No such card');
    const sig = parseDeviceSignature(body.deviceSignature);
    if (!sig) throw badRequest('Missing field: deviceSignature');
    const keyObject = keyFromStoredJwk(card.deviceKeyAlg, card.deviceKeyJwk);
    if (!verifyDeviceSignature({ alg: card.deviceKeyAlg, keyObject }, sig, signingStrings.cardDelete(cardId, challenge))) {
      throw new ApiError(
        401,
        'BAD_DEVICE_SIGNATURE',
        'deviceSignature does not verify over "v18-card-delete\\n<cardId>\\n<challenge>"'
      );
    }
    await this.d.cards.revoke(cardId, iso(this.d.clock()));
    return { cardId, status: 'revoked' };
  }
}
