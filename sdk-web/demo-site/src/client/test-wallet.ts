/**
 * Browser entry for the BROWSER TEST WALLET (DEV ONLY). Bundled to /dev/test-wallet.js.
 * Keeps the test card in IndexedDB (the private key is stored as a non-extractable CryptoKey),
 * and registers itself with the V18 widget so its "Simulate … with the test wallet" button
 * runs the real flow. The widget shows that button only when the V18 server is in dev mode.
 */
import { MemoryStorage, StoredCard, TestWalletCore, WalletStorage, LogKind, ADULT_TEST_BIRTH_DATE, CHILD_TEST_BIRTH_DATE } from './wallet-core.js';

const DB = 'v18-demo-test-wallet';
const STORE = 'card';

class IdbStorage implements WalletStorage {
  private db(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  private async tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const db = await this.db();
    return new Promise<T>((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const r = fn(t.objectStore(STORE));
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
      t.oncomplete = () => db.close();
    });
  }
  async load(): Promise<StoredCard | null> {
    return ((await this.tx('readonly', (s) => s.get('current'))) as StoredCard | undefined) ?? null;
  }
  async save(card: StoredCard): Promise<void> {
    await this.tx('readwrite', (s) => s.put(card, 'current'));
  }
  async clear(): Promise<void> {
    await this.tx('readwrite', (s) => s.delete('current'));
  }
}

function pickStorage(): WalletStorage {
  try {
    if (typeof indexedDB !== 'undefined') return new IdbStorage();
  } catch {
    /* private mode etc. */
  }
  return new MemoryStorage();
}

type Listener = (kind: LogKind, text: string) => void;
const listeners = new Set<Listener>();
const emit: Listener = (kind, text) => listeners.forEach((l) => l(kind, text));

const wallets = new Map<string, TestWalletCore>();
const storage = pickStorage();
let birthDate = ADULT_TEST_BIRTH_DATE;

function wallet(serverUrl: string): TestWalletCore {
  let w = wallets.get(serverUrl);
  if (!w) {
    w = new TestWalletCore({ serverUrl, storage, log: emit, birthDate });
    wallets.set(serverUrl, w);
  }
  w.birthDate = birthDate;
  return w;
}

const api = {
  label: 'Browser test wallet (dev only)',
  ADULT_TEST_BIRTH_DATE,
  CHILD_TEST_BIRTH_DATE,
  onLog(fn: Listener): () => void {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },
  setBirthDate(d: string): void {
    birthDate = d;
  },
  wallet,
  /** Called by the V18 widget's dev-only button. */
  async simulatePhone(s: { serverUrl: string; sessionId: string; origin: string; challenge: string; minAge: number; onProgress?: (m: string) => void }) {
    const w = wallet(s.serverUrl);
    const { devMode } = await w.health();
    if (!devMode) throw new Error('The V18 server is not in dev mode, so the test wallet will not run');
    await w.simulatePhone(s);
  },
};

(window as any).V18DemoTestWallet = api;
// The widget looks for window.V18TestWallet if it loads after us, or we register directly.
(window as any).V18TestWallet = api;
(window as any).V18?.registerTestWallet?.(api);
