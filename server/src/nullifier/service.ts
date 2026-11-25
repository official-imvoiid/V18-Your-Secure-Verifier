import { AttestationGate } from '../attestation/gate.js';
import { ChallengeService } from '../challenge/service.js';
import { parseDevicePublicKey, parseDeviceSignature, verifyDeviceSignature } from '../device/device-keys.js';
import { ApiError, badRequest } from '../errors.js';
import { KeyStore, TicketKeyInfo } from '../keys/keystore.js';
import { RateLimiter } from '../tickets/rate-limit.js';
import { decodeBase64url, isBase64url, isPlainObject, toBase64url } from '../util.js';

/**
 * Nullifier service (PROTOCOL.md 4c.2): an oblivious PRF made from a
 * DETERMINISTIC RSA blind signature (RFC 9474 RSABSSA-SHA384-PSSZERO-Deterministic).
 *
 * The phone blinds `v18-doc-v1|<state>|<document number>` (or the PhilSys /
 * JPKI message), the server signs the blinded value without ever seeing it,
 * and the phone unblinds. The same document always gives the same signature,
 * so nullifier = base64url(SHA-256(signature)) is stable per document, but
 * the server cannot compute it for any document on its own.
 *
 * The key `v18-nullifier-1` is long-lived and is never rotated: rotating it
 * would give every document a new nullifier and reset the card cap.
 */
export const NULLIFIER_KEY_ID = 'v18-nullifier-1';
export const NULLIFIER_ALGORITHM = 'RSABSSA-SHA384-PSSZERO-Deterministic';

export const nullifierSigningString = (challenge: string, thumbprint: string, blindedMessage: string) =>
  ['v18-nullifier', challenge, thumbprint, blindedMessage].join('\n');

export class NullifierKeyService {
  private key: TicketKeyInfo | null = null;

  constructor(
    private readonly store: KeyStore,
    private readonly modulusBits: number
  ) {}

  /** Loads the key, or makes it the very first time. */
  async init(): Promise<void> {
    const existing = (await this.store.list()).find((k) => k.kid === NULLIFIER_KEY_ID);
    this.key =
      existing ??
      (await this.store.generate({
        kid: NULLIFIER_KEY_ID,
        purpose: 'nullifier',
        minAge: 0,
        nbf: 0,
        exp: 0,
        modulusBits: this.modulusBits,
      }));
  }

  get info(): TicketKeyInfo {
    if (!this.key) throw new Error('Nullifier key not loaded');
    return this.key;
  }

  /** GET /v1/keys/nullifier. Clients import only {kty, n, e}. */
  jwks() {
    const k = this.info;
    return {
      keys: [
        {
          kty: 'RSA' as const,
          kid: k.kid,
          use: 'sig' as const,
          alg: NULLIFIER_ALGORITHM,
          n: k.publicJwk.n,
          e: k.publicJwk.e,
          v18_purpose: 'nullifier',
        },
      ],
    };
  }

  async blindSign(blinded: Uint8Array): Promise<Uint8Array> {
    const k = this.info;
    const kLen = Math.ceil(k.modulusBits / 8);
    if (blinded.length !== kLen) throw new ApiError(400, 'BAD_BLINDED_MESSAGE', `blindedMessage must be ${kLen} bytes`);
    const m = BigInt('0x' + Buffer.from(blinded).toString('hex'));
    const n = BigInt('0x' + Buffer.from(k.publicJwk.n, 'base64url').toString('hex'));
    if (m === 0n || m >= n) throw new ApiError(400, 'BAD_BLINDED_MESSAGE', 'blindedMessage is out of range for this key');
    return this.store.blindSign(k.kid, blinded);
  }
}

export class NullifierSignService {
  constructor(
    private readonly keys: NullifierKeyService,
    private readonly challenges: ChallengeService,
    private readonly gate: AttestationGate,
    private readonly perDevice: RateLimiter,
    private readonly perIp: RateLimiter,
    private readonly hashIp: (ip: string | undefined) => string
  ) {}

  /** POST /v1/nullifier/blind-sign {challenge, blindedMessage, devicePublicKey, deviceSignature, keyAttestation} */
  async blindSign(rawBody: unknown, clientIp: string | undefined) {
    const body = isPlainObject(rawBody) ? rawBody : {};
    // Per-IP limit first, so floods cost nothing else.
    await this.perIp.takeOrThrow(this.hashIp(clientIp), 'Too many nullifier requests from this network in the last hour.');
    const challenge = await this.challenges.consumeOrThrow(body.challenge);
    const blindedMessage = body.blindedMessage;
    if (!isBase64url(blindedMessage)) throw badRequest('blindedMessage must be base64url without padding');
    const blinded = decodeBase64url(blindedMessage, 'blindedMessage', 1024);

    const deviceKey = await parseDevicePublicKey(body.devicePublicKey);
    const sig = parseDeviceSignature(body.deviceSignature);
    if (!verifyDeviceSignature(deviceKey, sig, nullifierSigningString(challenge, deviceKey.thumbprint, blindedMessage))) {
      throw new ApiError(
        401,
        'BAD_DEVICE_SIGNATURE',
        'deviceSignature does not verify over "v18-nullifier\\n<challenge>\\n<deviceKeyThumbprint>\\n<blindedMessage>"'
      );
    }

    // Production: a hardware-attested key made by the V18 app, for this challenge.
    const attestation = await this.gate.check(body.keyAttestation, challenge, deviceKey.keyObject);

    await this.perDevice.takeOrThrow(deviceKey.thumbprint, 'This device key asked for too many nullifiers today.');
    const signature = await this.keys.blindSign(blinded);
    return {
      blindSignature: toBase64url(signature),
      keyId: NULLIFIER_KEY_ID,
      algorithm: NULLIFIER_ALGORITHM,
      attestation: this.gate.summary(attestation),
    };
  }
}
