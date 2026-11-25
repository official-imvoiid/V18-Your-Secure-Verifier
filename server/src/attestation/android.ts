import 'reflect-metadata';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as x509 from '@peculiar/x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import {
  AttestationApplicationId,
  id_ce_keyDescription,
  NonStandardKeyDescription,
  RootOfTrust,
  SecurityLevel,
  VerifiedBootState,
} from '@peculiar/asn1-android';
import { normalizeCertDigest, serverRoot } from '../config.js';
import { ApiError } from '../errors.js';

/**
 * Android key attestation (PROTOCOL.md 4c.3).
 *
 * The phone makes its Keystore key with
 * `setAttestationChallenge(UTF-8 bytes of the server challenge)` and sends
 * the certificate chain (base64 DER, leaf first). This module checks, with
 * vetted libraries (@peculiar/x509 for X.509 and signatures,
 * @peculiar/asn1-android for Google's KeyDescription schema):
 *
 *   1. every certificate is signed by the next one and is in its validity period;
 *   2. the chain ends at a Google hardware attestation root (bundled in
 *      assets/android/google-attestation-roots.pem, compared by public key as
 *      Google recommends);
 *   3. no certificate is on Google's attestation revocation list;
 *   4. the leaf's public key is the device public key;
 *   5. the attestation challenge is the server challenge;
 *   6. attestation and KeyMint security level are TrustedEnvironment or StrongBox;
 *   7. the key was generated inside the secure hardware (origin GENERATED);
 *   8. attestationApplicationId is package com.v18.app with a signing
 *      certificate SHA-256 from V18_ANDROID_CERT_DIGESTS;
 *   9. production: verified boot state Verified and a locked bootloader.
 *
 * Dev mode may accept emulator or software attestation and a missing
 * digest list. Every check it lets through is named in `devModeExceptions`,
 * which goes back to the app in the response.
 */

export const GOOGLE_ROOTS_PATH = path.join(serverRoot, 'assets', 'android', 'google-attestation-roots.pem');
export const REVOCATION_SNAPSHOT_PATH = path.join(serverRoot, 'assets', 'android', 'attestation-status.snapshot.json');
export const REVOCATION_URL = 'https://android.googleapis.com/attestation/status';
/** KeyMint `origin` tag value for a key made inside the secure hardware. */
const KM_ORIGIN_GENERATED = 0;

export type SecurityLevelName = 'Software' | 'TrustedEnvironment' | 'StrongBox';
export type BootStateName = 'Verified' | 'SelfSigned' | 'Unverified' | 'Failed';

export interface AttestationResult {
  /** True only when every production check passed. */
  hardwareVerified: boolean;
  /** Present: "chain", or "none" for a dev-mode request without attestation. */
  kind: 'chain' | 'none';
  chainTrusted: boolean;
  securityLevel: SecurityLevelName | null;
  attestationVersion: number | null;
  verifiedBootState: BootStateName | null;
  deviceLocked: boolean | null;
  packageName: string | null;
  /** Production checks that dev mode let through. Empty in production. */
  devModeExceptions: string[];
}

export interface AttestationPolicy {
  devMode: boolean;
  packageName: string;
  /** Lowercase hex SHA-256 of the app signing certificates. */
  certDigests: string[];
  trustedRoots: x509.X509Certificate[];
  revocation: RevocationSource;
}

export interface AttestationInput {
  chain: unknown;
  /** The challenges this attestation may carry (strings are compared as UTF-8). */
  allowedChallenges: (string | Uint8Array)[];
  /** The device public key as a Node KeyObject. */
  devicePublicKey: crypto.KeyObject;
  nowMs: number;
}

const bad = (reason: string, message: string) => new ApiError(400, 'ATTESTATION_INVALID', message, { reason });

export function loadGoogleRoots(file = GOOGLE_ROOTS_PATH): x509.X509Certificate[] {
  const pem = fs.readFileSync(file, 'utf8');
  return x509.PemConverter.decode(pem).map((der) => new x509.X509Certificate(der));
}

function spkiHex(cert: x509.X509Certificate): string {
  return Buffer.from(cert.publicKey.rawData).toString('hex');
}

/** The schema gives OCTET STRINGs as ArrayBuffer or as an OctetString wrapper. */
function bytesOf(v: unknown): Buffer {
  if (v instanceof ArrayBuffer) return Buffer.from(v);
  if (ArrayBuffer.isView(v)) return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
  const inner = (v as { buffer?: ArrayBuffer } | null)?.buffer;
  if (inner instanceof ArrayBuffer) return Buffer.from(inner);
  throw bad('bad_key_description', 'Unexpected value in the attestation extension');
}

/** Compares the certificate's key with the device key by their JWK members (encoding-independent). */
function sameKey(spki: Buffer, device: crypto.KeyObject): boolean {
  let a: crypto.JsonWebKey;
  try {
    a = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' }).export({ format: 'jwk' });
  } catch {
    return false;
  }
  const b = device.export({ format: 'jwk' });
  const fields = a.kty === 'EC' ? ['kty', 'crv', 'x', 'y'] : ['kty', 'n', 'e'];
  return fields.every((f) => (a as Record<string, unknown>)[f] === (b as Record<string, unknown>)[f]);
}

/** Hex serial, lower case, no leading zeros (the revocation list's format). */
export function serialKey(cert: x509.X509Certificate): string {
  return cert.serialNumber.toLowerCase().replace(/^0+(?=.)/, '');
}

function decodeChain(raw: unknown): x509.X509Certificate[] {
  if (!Array.isArray(raw) || raw.length < 2 || raw.length > 10) {
    throw bad('malformed', 'keyAttestation must be an array of 2 to 10 base64 DER certificates, leaf first');
  }
  return raw.map((item, i) => {
    if (typeof item !== 'string' || item.length > 16_384 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(item)) {
      throw bad('malformed', `keyAttestation[${i}] is not base64`);
    }
    try {
      return new x509.X509Certificate(Buffer.from(item.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
    } catch {
      throw bad('malformed', `keyAttestation[${i}] is not a DER certificate`);
    }
  });
}

const LEVEL: Record<number, SecurityLevelName> = {
  [SecurityLevel.software]: 'Software',
  [SecurityLevel.trustedEnvironment]: 'TrustedEnvironment',
  [SecurityLevel.strongBox]: 'StrongBox',
};
const BOOT: Record<number, BootStateName> = {
  [VerifiedBootState.verified]: 'Verified',
  [VerifiedBootState.selfSigned]: 'SelfSigned',
  [VerifiedBootState.unverified]: 'Unverified',
  [VerifiedBootState.failed]: 'Failed',
};

/** Normalizes V18_ANDROID_CERT_DIGESTS entries: hex (colons allowed) or base64. */
export const normalizeDigest = normalizeCertDigest;

/**
 * Checks one attestation chain. Throws ApiError 400 ATTESTATION_INVALID with
 * a `reason` on any failure that dev mode does not allow.
 */
export async function verifyKeyAttestation(input: AttestationInput, policy: AttestationPolicy): Promise<AttestationResult> {
  const certs = decodeChain(input.chain);
  const exceptions: string[] = [];
  const allow = (reason: string, message: string) => {
    if (!policy.devMode) throw bad(reason, message);
    exceptions.push(reason);
  };

  // 1. Signatures and names along the chain, and validity periods, following
  // Google's own verifier (github.com/android/keyattestation, BasicChecker):
  //  - a trusted root is a trust anchor matched by its key (RFC 5280 6.1.1),
  //    so its dates are not checked (Google's 2016 root certificate ran out
  //    in May 2026 but still anchors older phones);
  //  - the leaf's dates are set by the phone itself, so they are not checked;
  //  - "not yet valid" always fails; "expired" fails for remotely provisioned
  //    (RKP) chains but not for factory-provisioned ones, whose keys cannot be
  //    rotated (Pixel 2 and Sony chains from 2026 have batch certificates that
  //    ran out on 2026-05-24). Google's revocation list covers leaked factory keys.
  const rootKeys = new Set(policy.trustedRoots.map(spkiHex));
  const lastBelowRoot = certs[certs.length - 2];
  const factoryProvisioned = lastBelowRoot ? /(^|,\s*)(2\.5\.4\.5|SERIALNUMBER|serialNumber)=/.test(lastBelowRoot.subject) : false;
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    const issuer = certs[i + 1] ?? cert;
    const ok = await cert.verify({ publicKey: issuer.publicKey, signatureOnly: true }).catch(() => false);
    if (!ok) {
      throw bad('bad_chain_signature', `keyAttestation[${i}] is not signed by keyAttestation[${Math.min(i + 1, certs.length - 1)}]`);
    }
    if (i + 1 < certs.length && cert.issuer !== issuer.subject) {
      throw bad('bad_chain_name', `keyAttestation[${i}] names a different issuer than keyAttestation[${i + 1}]`);
    }
    const isAnchor = i === certs.length - 1 && rootKeys.has(spkiHex(cert));
    if (isAnchor || i === 0) continue;
    const now = input.nowMs;
    if (now < cert.notBefore.getTime() - 5 * 60_000) {
      throw bad('certificate_not_yet_valid', `keyAttestation[${i}] is not valid yet`);
    }
    if (now > cert.notAfter.getTime() && !factoryProvisioned) {
      throw bad('certificate_expired', `keyAttestation[${i}] has expired`);
    }
  }

  // 2. The root must be a Google hardware attestation root (by public key).
  const root = certs[certs.length - 1];
  const chainTrusted = rootKeys.has(spkiHex(root));
  if (!chainTrusted) allow('untrusted_root', 'The attestation chain does not end at a Google hardware attestation root');

  // 3. Revocation list.
  const revoked = await policy.revocation.revokedSerials();
  for (let i = 0; i < certs.length; i++) {
    if (revoked.has(serialKey(certs[i]))) {
      throw bad('revoked', `keyAttestation[${i}] is on Google's attestation revocation list`);
    }
  }

  // 4. The attested key is the device key.
  const leaf = certs[0];
  if (!sameKey(Buffer.from(leaf.publicKey.rawData), input.devicePublicKey)) {
    throw bad('key_mismatch', 'The attested key is not devicePublicKey');
  }

  // 5. Parse Google's KeyDescription extension.
  const ext = leaf.getExtension(id_ce_keyDescription);
  if (!ext) throw bad('no_key_description', 'The leaf certificate has no Android key attestation extension');
  let kd: NonStandardKeyDescription;
  try {
    kd = AsnConvert.parse(ext.value, NonStandardKeyDescription);
  } catch {
    throw bad('bad_key_description', 'The Android key attestation extension could not be read');
  }

  // 6. Challenge.
  const got = bytesOf(kd.attestationChallenge);
  const challengeOk = input.allowedChallenges.some((c) => {
    const want = typeof c === 'string' ? Buffer.from(c, 'utf8') : Buffer.from(c);
    return want.length === got.length && crypto.timingSafeEqual(want, got);
  });
  if (!challengeOk) throw bad('challenge_mismatch', 'The attestation challenge is not the server challenge');

  // 7. Security levels.
  const attLevel = LEVEL[kd.attestationSecurityLevel] ?? 'Software';
  const kmLevel = LEVEL[kd.keyMintSecurityLevel] ?? 'Software';
  if (attLevel === 'Software' || kmLevel === 'Software') {
    allow('software_security_level', 'The key is not protected by a TrustedEnvironment or StrongBox');
  }

  const hw = kd.hardwareEnforced;
  const sw = kd.softwareEnforced;

  // 8. Made inside the secure hardware, not imported.
  const origin = hw.findProperty('origin') ?? sw.findProperty('origin');
  if (origin !== KM_ORIGIN_GENERATED) allow('key_not_generated', 'The key was not generated inside the secure hardware');

  // 9. Which app made the key.
  const appIdOctets = sw.findProperty('attestationApplicationId') ?? hw.findProperty('attestationApplicationId');
  let packageName: string | null = null;
  if (!appIdOctets) {
    throw bad('no_application_id', 'The attestation has no attestationApplicationId');
  }
  let appId: AttestationApplicationId;
  try {
    appId = AsnConvert.parse(bytesOf(appIdOctets), AttestationApplicationId);
  } catch {
    throw bad('bad_application_id', 'attestationApplicationId could not be read');
  }
  const names = appId.packageInfos.map((p) => bytesOf(p.packageName).toString('utf8'));
  packageName = names.length === 1 ? names[0] : null;
  if (names.length !== 1 || names[0] !== policy.packageName) {
    throw bad('wrong_package', `The key was not made by ${policy.packageName}`);
  }
  const digests = appId.signatureDigests.map((d) => bytesOf(d).toString('hex'));
  if (policy.certDigests.length === 0) {
    allow('cert_digest_not_checked', 'V18_ANDROID_CERT_DIGESTS is not set');
  } else if (!digests.some((d) => policy.certDigests.includes(d))) {
    throw bad('wrong_signing_certificate', 'The app is not signed with a V18 signing certificate');
  }

  // 10. Verified boot and a locked bootloader.
  const rot = (hw.findProperty('rootOfTrust') ?? sw.findProperty('rootOfTrust')) as RootOfTrust | undefined;
  const bootState = rot ? (BOOT[rot.verifiedBootState] ?? null) : null;
  const deviceLocked = rot ? rot.deviceLocked === true : null;
  if (bootState !== 'Verified' || deviceLocked !== true) {
    allow('boot_not_verified', 'The phone does not have verified boot with a locked bootloader');
  }

  return {
    hardwareVerified: exceptions.length === 0,
    kind: 'chain',
    chainTrusted,
    securityLevel: attLevel === 'Software' ? 'Software' : kmLevel,
    attestationVersion: Number(kd.attestationVersion),
    verifiedBootState: bootState,
    deviceLocked,
    packageName,
    devModeExceptions: exceptions,
  };
}

// ---- Revocation list --------------------------------------------------------------

export interface RevocationSource {
  revokedSerials(): Promise<Set<string>>;
}

/** A fixed list (tests). */
export class StaticRevocationList implements RevocationSource {
  constructor(private readonly serials: Iterable<string> = []) {}
  async revokedSerials(): Promise<Set<string>> {
    return new Set([...this.serials].map((s) => s.toLowerCase()));
  }
}

interface StatusFile {
  fetchedAt: string;
  entries: Record<string, { status: string; reason?: string }>;
}

/**
 * Google's attestation status list (https://android.googleapis.com/attestation/status),
 * fetched and cached: in memory, and on disk in the data folder so a restart
 * does not need the network. It starts from the bundled snapshot. Google asks
 * verifiers to refresh at least daily; this refreshes every 6 hours. If the
 * copy gets older than `maxAgeMs` (default 3 days) because Google cannot be
 * reached, production attestation fails closed with 503.
 */
export class GoogleRevocationList implements RevocationSource {
  private data: StatusFile | null = null;
  private set = new Set<string>();
  private refreshing: Promise<void> | null = null;
  private lastTry = 0;
  private readonly timer: NodeJS.Timeout;

  constructor(
    private readonly opts: {
      cacheFile: string;
      devMode: boolean;
      fetchFn?: typeof fetch;
      url?: string;
      maxAgeMs?: number;
      refreshMs?: number;
      clock?: () => number;
    }
  ) {
    for (const f of [opts.cacheFile, REVOCATION_SNAPSHOT_PATH]) {
      try {
        const d = JSON.parse(fs.readFileSync(f, 'utf8')) as StatusFile;
        if (!this.data || Date.parse(d.fetchedAt) > Date.parse(this.data.fetchedAt)) this.use(d);
      } catch {
        /* missing or unreadable: try the next one */
      }
    }
    this.timer = setInterval(() => void this.refresh().catch(() => undefined), this.opts.refreshMs ?? 6 * 3_600_000);
    this.timer.unref();
  }

  private now(): number {
    return (this.opts.clock ?? Date.now)();
  }

  private use(d: StatusFile): void {
    this.data = d;
    this.set = new Set(
      Object.entries(d.entries)
        .filter(([, v]) => v.status === 'REVOKED' || v.status === 'SUSPENDED')
        .map(([k]) => k.toLowerCase().replace(/^0+(?=.)/, ''))
    );
  }

  get fetchedAt(): string | null {
    return this.data?.fetchedAt ?? null;
  }

  get size(): number {
    return this.set.size;
  }

  /** Fetches a fresh copy. Errors are reported to the caller. */
  async refresh(): Promise<void> {
    if (!this.refreshing) {
      this.lastTry = this.now();
      this.refreshing = (async () => {
        const res = await (this.opts.fetchFn ?? fetch)(this.opts.url ?? REVOCATION_URL, { headers: { 'Cache-Control': 'no-cache' } });
        if (!res.ok) throw new Error(`attestation status list: HTTP ${res.status}`);
        const body = (await res.json()) as { entries?: StatusFile['entries'] };
        if (!body || typeof body.entries !== 'object' || body.entries === null) throw new Error('attestation status list has no entries');
        const d: StatusFile = { fetchedAt: new Date(this.now()).toISOString(), entries: body.entries };
        this.use(d);
        fs.mkdirSync(path.dirname(this.opts.cacheFile), { recursive: true });
        fs.writeFileSync(`${this.opts.cacheFile}.tmp`, JSON.stringify(d));
        fs.renameSync(`${this.opts.cacheFile}.tmp`, this.opts.cacheFile);
      })().finally(() => {
        this.refreshing = null;
      });
    }
    await this.refreshing;
  }

  async revokedSerials(): Promise<Set<string>> {
    const age = this.data ? this.now() - Date.parse(this.data.fetchedAt) : Infinity;
    if (age > 24 * 3_600_000 && this.now() - this.lastTry > 10 * 60_000) {
      try {
        await this.refresh();
      } catch (err) {
        console.error('[v18] could not refresh the Android attestation revocation list:', (err as Error).message);
      }
    }
    const fresh = this.data ? this.now() - Date.parse(this.data.fetchedAt) : Infinity;
    if (fresh > (this.opts.maxAgeMs ?? 3 * 86_400_000) && !this.opts.devMode) {
      throw new ApiError(503, 'ATTESTATION_UNAVAILABLE', "Google's attestation revocation list could not be refreshed. Try again later.");
    }
    return this.set;
  }

  close(): void {
    clearInterval(this.timer);
  }
}

/** A dev-mode stand-in when the app sends no attestation at all. */
export function noAttestationResult(): AttestationResult {
  return {
    hardwareVerified: false,
    kind: 'none',
    chainTrusted: false,
    securityLevel: null,
    attestationVersion: null,
    verifiedBootState: null,
    deviceLocked: null,
    packageName: null,
    devModeExceptions: ['no_attestation'],
  };
}

/** What the app is told about its attestation (no device identifiers). */
export function attestationSummary(r: AttestationResult) {
  return {
    hardwareVerified: r.hardwareVerified,
    kind: r.kind,
    securityLevel: r.securityLevel,
    verifiedBootState: r.verifiedBootState,
    deviceLocked: r.deviceLocked,
    devModeExceptions: r.devModeExceptions,
    ...(r.devModeExceptions.length > 0 ? { note: 'TEST MODE: a production server would refuse this attestation' } : {}),
  };
}
