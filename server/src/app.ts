import 'reflect-metadata';
import * as path from 'node:path';
import express, { Express } from 'express';
import helmet from 'helmet';
import type * as x509 from '@peculiar/x509';
import { ArtifactService } from './artifacts/service.js';
import { AttestationPolicy, GoogleRevocationList, loadGoogleRoots, RevocationSource } from './attestation/android.js';
import { AttestationGate } from './attestation/gate.js';
import { AppWalletVerifier, CardService } from './cards/service.js';
import { CardStore } from './cards/store.js';
import { CatalogService } from './catalog/service.js';
import { ChallengeService } from './challenge/service.js';
import { Config, DEV_DEMO_ORIGINS, loadConfig } from './config.js';
import { ConnectService, loadConnectorRegistry, RegistryLike } from './connect/service.js';
import { openSql, SqlDb } from './db/sql.js';
import { ChallengeRepo, DocRepo, ipHasher, MetaRepo, RateLimitRepo } from './db/state.js';
import { Metrics } from './http/metrics.js';
import { cors, errorHandler, noStore, notFound } from './http/middleware.js';
import { AnonAadhaarProofVerifier, loadUidaiKeys, PinnedVkeyVerifier, UidaiKey } from './issuers/anon-aadhaar.js';
import { FileKeyStore, KeyStore, SqlKeyStore } from './keys/keystore.js';
import { TicketKeyService } from './keys/ticket-keys.js';
import { KeyWrapper, LocalKekWrapper } from './keys/wrap.js';
import { LinkService } from './links/service.js';
import { NullifierKeyService, NullifierSignService } from './nullifier/service.js';
import { NullifierStore } from './nullifier/store.js';
import { PairingService } from './pairing/service.js';
import { createRouter } from './routes/routes.js';
import { RateLimiter } from './tickets/rate-limit.js';
import { TicketService } from './tickets/service.js';
import { Clock, iso, systemClock } from './util.js';
import { loadIacaTrust } from './wallet/mdoc.js';
import { WalletService } from './wallet/service.js';
import { loadOrCreateDevIaca } from './wallet/test-wallet.js';

const HOUR = 3_600_000;
const limiters: RateLimiter[] = [];
function limiter(...args: ConstructorParameters<typeof RateLimiter>): RateLimiter {
  const l = new RateLimiter(...args);
  limiters.push(l);
  return l;
}

export interface V18Services {
  config: Config;
  clock: Clock;
  db: SqlDb;
  challenges: ChallengeService;
  keys: TicketKeyService;
  nullifierKey: NullifierKeyService;
  nullifierSign: NullifierSignService;
  nullifiers: NullifierStore;
  cardStore: CardStore;
  cards: CardService;
  tickets: TicketService;
  pairing: PairingService;
  links: LinkService;
  wallet: WalletService;
  connect: ConnectService;
  catalog: CatalogService;
  artifacts: ArtifactService;
  attestation: AttestationGate;
  metrics: Metrics;
  docs: DocRepo;
  uidaiKeys: UidaiKey[];
  aadhaarVerifier: AnonAadhaarProofVerifier | null;
  aadhaarReady: boolean;
  trustedIacaFiles: string[];
  /** Is this card or ticket method usable on this server right now? */
  methodEnabled(method: string): boolean;
  methodStatus(): Record<string, string>;
  connectorError: string | null;
}

export interface CreateOptions {
  /** Settings that win over environment variables. */
  config?: Partial<Config>;
  /** Environment to read (default: process.env). */
  env?: NodeJS.ProcessEnv;
  clock?: Clock;
  /** Default: FileKeyStore (dev) or the encrypted SqlKeyStore. */
  keyStore?: KeyStore;
  /** Encrypts private keys in the SqlKeyStore. Default: V18_KEK. */
  keyWrapper?: KeyWrapper;
  /** Default: the pinned vkey.json verifier. Pass null to switch Anon Aadhaar off. */
  aadhaarVerifier?: AnonAadhaarProofVerifier | null;
  /** Extra attestation roots to trust (TESTS ONLY: a test root). */
  extraAttestationRoots?: x509.X509Certificate[];
  /** Default: Google's list, fetched and cached. */
  revocation?: RevocationSource;
  /** IACA PEMs to trust instead of assets/iaca (tests). */
  trustedIacas?: string[];
  /** Default: @v18/connectors with this environment. */
  connectorRegistry?: RegistryLike | null;
  /** Node process metrics on /metrics (off in tests). */
  processMetrics?: boolean;
}

export interface V18Server {
  app: Express;
  services: V18Services;
  close(): Promise<void>;
}

async function openKeyStore(config: Config, db: SqlDb, opts: CreateOptions): Promise<KeyStore> {
  if (opts.keyStore) return opts.keyStore;
  if (config.keyStore === 'file') {
    if (!config.devMode) {
      throw new Error('Production needs the encrypted key store: set V18_KEK and leave V18_KEY_STORE unset (or "db"). File keys are dev only.');
    }
    return FileKeyStore.open(config.keyDir);
  }
  const wrapper = opts.keyWrapper ?? (config.kek ? new LocalKekWrapper(config.kek) : null);
  if (!wrapper) throw new Error('The database key store needs V18_KEK (32 bytes, base64 or hex) or a KMS key wrapper');
  const store = new SqlKeyStore(db, wrapper);
  await store.checkAll();
  return store;
}

/** Builds the whole server. Nothing is a global singleton, so tests can run many. */
export async function createV18(opts: CreateOptions = {}): Promise<V18Server> {
  const env = opts.env ?? process.env;
  const config = loadConfig(env, opts.config ?? {});
  const clock = opts.clock ?? systemClock;

  // Login connectors first: a bad setup must fail before anything is opened.
  let registry: RegistryLike | null;
  let connectorError: string | null = null;
  if (opts.connectorRegistry !== undefined) registry = opts.connectorRegistry;
  else {
    const loaded = loadConnectorRegistry(env);
    registry = loaded.registry;
    connectorError = loaded.error;
  }
  if (registry && registry.list().length > 0 && !config.nullifierSecret) {
    throw new Error('Login connectors are configured, so V18_NULLIFIER_SECRET (at least 32 characters) is required');
  }

  const db = await openSql({ databaseUrl: config.databaseUrl, dbPath: config.dbPath });
  const docs = new DocRepo(db);
  const rates = new RateLimitRepo(db);
  const hashIp = await ipHasher(new MetaRepo(db));
  const challenges = new ChallengeService(new ChallengeRepo(db), config.challengeTtlSeconds, clock);
  const nullifiers = new NullifierStore(db);
  const cardStore = new CardStore(db);

  let keyStore: KeyStore;
  try {
    keyStore = await openKeyStore(config, db, opts);
  } catch (err) {
    await db.close();
    throw err;
  }
  const keys = new TicketKeyService(
    keyStore,
    { thresholds: config.ageThresholds, rotationDays: config.keyRotationDays, modulusBits: config.keyBits },
    clock
  );
  await keys.refresh();
  const nullifierKey = new NullifierKeyService(keyStore, config.nullifierKeyBits);
  await nullifierKey.init();

  // Anon Aadhaar: bundled UIDAI keys and the pinned verification key.
  const uidaiKeys = await loadUidaiKeys();
  let aadhaarVerifier: AnonAadhaarProofVerifier | null;
  if (opts.aadhaarVerifier !== undefined) aadhaarVerifier = opts.aadhaarVerifier;
  else {
    const loaded = await PinnedVkeyVerifier.load();
    aadhaarVerifier = loaded.verifier;
    if (!loaded.verifier) console.error(`[v18] Anon Aadhaar is off: ${loaded.reason}`);
  }
  const aadhaarReady = aadhaarVerifier !== null && config.aadhaarNullifierSeed !== null && uidaiKeys.some((k) => !k.test || config.devMode);

  // Android key attestation.
  const revocation =
    opts.revocation ?? new GoogleRevocationList({ cacheFile: path.join(config.dataDir, 'attestation-status.json'), devMode: config.devMode, clock });
  const policy: AttestationPolicy = {
    devMode: config.devMode,
    packageName: config.androidPackage,
    certDigests: config.androidCertDigests,
    trustedRoots: [...loadGoogleRoots(), ...(opts.extraAttestationRoots ?? [])],
    revocation,
  };
  const attestation = new AttestationGate(policy, clock);

  // Wallet trust list (TEST IACA only in dev mode).
  let trustedIacas: string[];
  let trustedIacaFiles: string[] = [];
  if (opts.trustedIacas) trustedIacas = opts.trustedIacas;
  else {
    if (config.devMode) await loadOrCreateDevIaca(config.iacaDir);
    const t = loadIacaTrust({ iacaDir: config.iacaDir, devMode: config.devMode, devIacaPems: config.devIacaPems });
    trustedIacas = t.pems;
    trustedIacaFiles = t.files;
  }

  const metrics = new Metrics(
    [
      { name: 'v18_cards_active', help: 'Active, unexpired age cards', read: async () => (await cardStore.countByStatus(iso(clock()))).active },
      { name: 'v18_challenges_open', help: 'Open challenges', read: () => challenges.openCount() },
      { name: 'v18_pairing_sessions', help: 'Stored pairing sessions', read: () => docs.count('pairing') },
    ],
    opts.processMetrics ?? false
  );

  // The mdoc_app hook is filled in once the wallet service exists.
  let walletRef: WalletService | null = null;
  const appWallet: AppWalletVerifier = {
    get ready() {
      return !!walletRef?.ready && (config.androidCertDigests.length > 0 || config.devMode);
    },
    verifyForCard: (challenge, proof) => walletRef!.verifyForCard(challenge, proof),
  };

  const cards = new CardService({
    db,
    cards: cardStore,
    nullifiers,
    challenges,
    config,
    clock,
    aadhaar: { verifier: aadhaarReady ? aadhaarVerifier : null, uidaiKeys },
    attestation,
    appWallet,
    onIssued: (m) => metrics.cardsIssued.inc({ method: m.startsWith('connector:') ? 'connector' : m }),
  });
  const tickets = new TicketService(
    cards,
    keys,
    challenges,
    limiter(rates, 'ticket', config.ticketsPerHour, HOUR, clock),
    clock,
    () => metrics.ticketsSigned.inc()
  );
  const pairing = new PairingService(
    docs,
    limiter(rates, 'pair-ip', config.pairingSessionsPerMinute, 60_000, clock),
    hashIp,
    { publicUrl: config.publicUrl, maxMinAge: Math.max(...config.ageThresholds) },
    clock
  );
  const links = new LinkService(cards, challenges, docs, { publicUrl: config.publicUrl, ttlSeconds: config.linkTtlSeconds }, clock);
  const nullifierLimitDevice = limiter(rates, 'null-dev', config.nullifierPerDevicePerDay, 24 * HOUR, clock);
  const nullifierLimitIp = limiter(rates, 'null-ip', config.nullifierPerIpPerHour, HOUR, clock);
  const nullifierSign = new NullifierSignService(nullifierKey, challenges, attestation, nullifierLimitDevice, nullifierLimitIp, hashIp);
  const wallet = new WalletService(
    pairing,
    tickets,
    challenges,
    docs,
    trustedIacas,
    { devMode: config.devMode, androidCertDigests: config.androidCertDigests },
    limiter(rates, 'wallet-ip', config.walletPerIpPerMinute, 60_000, clock),
    hashIp,
    clock,
    (r) => metrics.walletResults.inc({ result: r })
  );
  walletRef = wallet;

  const connect = new ConnectService(
    registry,
    cards,
    challenges,
    attestation,
    docs,
    { publicUrl: config.publicUrl, nullifierSecret: config.nullifierSecret },
    clock
  );

  const methodStatus = (): Record<string, string> => {
    const attested = attestation.configured ? 'ready' : 'not_configured';
    const out: Record<string, string> = {
      test_dev: config.devMode ? 'ready' : 'disabled',
      anon_aadhaar: aadhaarReady ? 'ready' : 'not_configured',
      emrtd_attested: attested,
      passport_attested: attested,
      philsys_qr_attested: attested,
      // Not in v1 (PROTOCOL.md 4d.4b) unless V18_ENABLE_MYNUMBER=1.
      mynumber_attested: config.enableMyNumber ? attested : 'disabled',
      face_estimate: config.faceModels.length > 0 && attestation.configured ? 'ready' : 'disabled',
      mdoc_wallet: wallet.ready ? 'ready' : 'not_configured',
      mdoc_app: appWallet.ready ? 'ready' : 'not_configured',
      passport_zk: 'not_ready',
    };
    for (const c of connect.enabled()) out[`connector:${c.id}`] = 'ready';
    return out;
  };
  const methodEnabled = (method: string) => methodStatus()[method] === 'ready';

  const catalog = new CatalogService(config.catalogPath, methodEnabled);
  const artifacts = new ArtifactService({ publicUrl: config.publicUrl, cacheFile: path.join(config.dataDir, 'artifacts-verified.json') });

  const services: V18Services = {
    config,
    clock,
    db,
    challenges,
    keys,
    nullifierKey,
    nullifierSign,
    nullifiers,
    cardStore,
    cards,
    tickets,
    pairing,
    links,
    wallet,
    connect,
    catalog,
    artifacts,
    attestation,
    metrics,
    docs,
    uidaiKeys,
    aadhaarVerifier,
    aadhaarReady,
    trustedIacaFiles,
    methodEnabled,
    methodStatus,
    connectorError,
  };

  const app = express();
  app.disable('x-powered-by');
  app.disable('etag');
  app.set('trust proxy', config.trustProxy);
  app.locals.v18 = services;

  // Security headers (an API: nothing may be framed or run scripts). Widget
  // and artifact endpoints are read cross-origin, so CORP is cross-origin.
  app.use(
    helmet({
      contentSecurityPolicy: { useDefaults: false, directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'none'"] } },
      crossOriginResourcePolicy: { policy: 'cross-origin' },
      referrerPolicy: { policy: 'no-referrer' },
      strictTransportSecurity: config.devMode ? false : { maxAge: 31_536_000, includeSubDomains: true },
    })
  );
  app.use(metrics.middleware());
  // No request logging at all, and never the body (PROTOCOL.md section 2).
  app.use(cors([...(config.devMode ? DEV_DEMO_ORIGINS : []), ...config.corsOrigins]));
  // Body limits: 64 KB everywhere, more only where proofs and wallet answers need it.
  const big = express.json({ limit: '256kb', strict: true });
  app.use(['/v1/card/issue', '/v1/wallet', '/v1/nullifier', '/v1/connect'], big);
  app.use('/v1/connect', express.urlencoded({ extended: false, limit: '512kb', parameterLimit: 50 }));
  app.use(express.json({ limit: '64kb', strict: true }));
  app.use(noStore);
  app.use('/v1', createRouter(services));
  app.get('/metrics', metrics.handler(config.metricsToken));
  app.use(notFound);
  app.use(errorHandler);

  return {
    app,
    services,
    async close() {
      challenges.close();
      for (const l of limiters) l.close();
      keys.close();
      pairing.close();
      links.close();
      if (revocation instanceof GoogleRevocationList) revocation.close();
      await aadhaarVerifier?.close?.();
      await db.close();
    },
  };
}

/** Same as createV18, returning only the Express app. */
export async function createApp(opts: CreateOptions = {}): Promise<Express> {
  return (await createV18(opts)).app;
}
