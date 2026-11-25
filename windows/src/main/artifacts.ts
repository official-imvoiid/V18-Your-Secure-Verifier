// Anon Aadhaar circuit files (PROTOCOL.md 4c.1): download on first use, check, cache.
//
// - The list comes from the V18 server: GET /v1/artifacts/manifest -> [{name, sha256, bytes, url}].
// - Each file must ALSO match the SHA-256 pinned in this app (src/shared/artifact-pins.ts), so a
//   changed or broken server can never make the app run different circuit files.
// - Files are downloaded from GET /v1/artifacts/<name> on the same (allowlisted) server, hashed
//   while they stream in, and only renamed into place when the hash matches. A broken download
//   resumes where it stopped (HTTP Range), and is checked again from the first byte.
// - Cache: <app data>\artifacts\anon-aadhaar-v2\<name>. Cached files are re-hashed the first time
//   they are used in each run of the app.
// Main process only. Nothing personal is involved here.

import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync, renameSync, rmSync, statSync, statfsSync } from 'node:fs';
import path from 'node:path';
import { ApiError, OfflineError } from '../shared/api.js';
import { ARTIFACT_PINS, type ArtifactRole } from '../shared/artifact-pins.js';

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ManifestEntry {
  name: string;
  sha256: string;
  bytes: number;
  role: ArtifactRole;
}

export type ArtifactPaths = Record<ArtifactRole, string>;

export interface ArtifactProgress {
  phase: 'manifest' | 'download' | 'check';
  /** Bytes done and total, over all files of this phase. */
  done: number;
  total: number;
}

export class ArtifactError extends Error {
  constructor(
    public readonly code: 'NO_ARTIFACTS' | 'MANIFEST_BAD' | 'NOT_PINNED' | 'BAD_HASH' | 'DISK_FULL' | 'DOWNLOAD_FAILED' | 'CANCELLED',
    message: string,
  ) {
    super(message);
    this.name = 'ArtifactError';
  }
}

const NAME_RE = /^[A-Za-z0-9._-]{1,100}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const IDLE_MS = 60_000;

function roleOf(name: string): ArtifactRole | null {
  const n = name.toLowerCase();
  if (n.endsWith('.wasm')) return 'wasm';
  if (n.endsWith('.zkey')) return 'zkey';
  if (n.endsWith('.json') && /vkey|verification_key/.test(n)) return 'vkey';
  return null;
}

export function parseManifest(data: unknown): ManifestEntry[] {
  const list = Array.isArray(data) ? data : data && typeof data === 'object' && Array.isArray((data as { artifacts?: unknown }).artifacts) ? (data as { artifacts: unknown[] }).artifacts : null;
  if (!list) throw new ArtifactError('MANIFEST_BAD', "The V18 server's list of proof files isn't in the expected shape.");
  const out = new Map<ArtifactRole, ManifestEntry>();
  for (const raw of list) {
    if (!raw || typeof raw !== 'object') continue;
    const e = raw as Record<string, unknown>;
    if (typeof e.name !== 'string' || !NAME_RE.test(e.name) || e.name.startsWith('.')) continue;
    if (typeof e.sha256 !== 'string' || !HEX64.test(e.sha256.toLowerCase())) continue;
    const bytes = typeof e.bytes === 'number' ? e.bytes : Number(e.bytes);
    if (!Number.isSafeInteger(bytes) || bytes <= 0) continue;
    const role = roleOf(e.name);
    if (!role || out.has(role)) continue;
    out.set(role, { name: e.name, sha256: e.sha256.toLowerCase(), bytes, role });
  }
  for (const role of ['wasm', 'zkey', 'vkey'] as const) {
    if (!out.has(role)) throw new ArtifactError('MANIFEST_BAD', `The V18 server's list of proof files has no ${role} file.`);
  }
  return [...out.values()];
}

/** Each file must be the exact file this app was built for. */
export function checkPins(entries: ManifestEntry[], pins = ARTIFACT_PINS): void {
  for (const e of entries) {
    const pin = pins[e.role];
    if (e.sha256 !== pin.sha256 || e.bytes !== pin.bytes) {
      throw new ArtifactError(
        'NOT_PINNED',
        `The V18 server offers a different ${e.role} proof file from the one this version of V18 was built for. Update V18, or ask the server's owner.`,
      );
    }
  }
}

async function hashFile(file: string, onBytes?: (n: number) => void, signal?: AbortSignal): Promise<string> {
  const h = createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const s = createReadStream(file, { highWaterMark: 4 * 1024 * 1024 });
    const abort = () => s.destroy(new ArtifactError('CANCELLED', 'Cancelled.'));
    signal?.addEventListener('abort', abort, { once: true });
    s.on('data', (c) => {
      h.update(c);
      onBytes?.(c.length);
    });
    s.on('error', (e) => (signal?.removeEventListener('abort', abort), reject(e)));
    s.on('end', () => (signal?.removeEventListener('abort', abort), resolve()));
  });
  return h.digest('hex');
}

export class ArtifactStore {
  /** Files already hashed in this run of the app: path -> "size:mtime". */
  private readonly verified = new Map<string, string>();

  constructor(
    private readonly dir: string,
    private readonly fetchImpl: FetchLike = (u, i) => fetch(u, i),
    private readonly pins = ARTIFACT_PINS,
  ) {}

  private fileFor(e: { name: string }): string {
    return path.join(this.dir, e.name);
  }

  /** Delete every cached proof file (Settings > Aadhaar proof files). */
  clear(): void {
    rmSync(this.dir, { recursive: true, force: true });
    this.verified.clear();
  }

  /** All pinned files are here with the right size (their hashes are checked before use). */
  isCached(): boolean {
    return (Object.values(this.pins) as { name: string; bytes: number }[]).every((p) => {
      try {
        return statSync(this.fileFor(p)).size === p.bytes;
      } catch {
        return false;
      }
    });
  }

  async manifest(apiBase: string, signal?: AbortSignal): Promise<ManifestEntry[]> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${apiBase.replace(/\/+$/, '')}/artifacts/manifest`, { headers: { accept: 'application/json' }, signal, redirect: 'error' });
    } catch {
      if (signal?.aborted) throw new ArtifactError('CANCELLED', 'Cancelled.');
      throw new OfflineError('could not reach the server');
    }
    if (res.status === 404 || res.status === 501 || res.status === 503) {
      throw new ArtifactError('NO_ARTIFACTS', "This V18 server doesn't offer the Aadhaar proof files yet.");
    }
    if (!res.ok) throw new ApiError(res.status, `HTTP_${res.status}`, `server answered ${res.status}`);
    let data: unknown;
    try {
      data = await res.json();
    } catch {
      throw new ArtifactError('MANIFEST_BAD', "The V18 server's list of proof files isn't valid.");
    }
    const entries = parseManifest(data);
    checkPins(entries, this.pins);
    return entries;
  }

  /** Bytes still to download for these files (0 when all are cached). */
  missingBytes(entries: ManifestEntry[]): number {
    return entries.reduce((sum, e) => {
      const f = this.fileFor(e);
      if (existsSync(f) && statSync(f).size === e.bytes) return sum;
      const part = f + '.part';
      const have = existsSync(part) ? Math.min(statSync(part).size, e.bytes) : 0;
      return sum + e.bytes - have;
    }, 0);
  }

  /**
   * Make sure every file is here and correct. Downloads what is missing, then checks every file's
   * SHA-256 (once per app run). Returns the local paths.
   */
  async ensure(apiBase: string, entries: ManifestEntry[], onProgress?: (p: ArtifactProgress) => void, signal?: AbortSignal): Promise<ArtifactPaths> {
    mkdirSync(this.dir, { recursive: true });
    const toFetch = entries.filter((e) => {
      const f = this.fileFor(e);
      return !(existsSync(f) && statSync(f).size === e.bytes);
    });
    const need = this.missingBytes(toFetch);
    if (need > 0) {
      let free = Number.POSITIVE_INFINITY;
      try {
        const s = statfsSync(this.dir);
        free = Number(s.bavail) * Number(s.bsize);
      } catch {
        /* unknown: try anyway */
      }
      if (free < need + 200 * 1024 * 1024) {
        throw new ArtifactError('DISK_FULL', `V18 needs about ${Math.ceil((need + 200 * 1024 * 1024) / 1e6)} MB of free disk space for the proof files.`);
      }
    }
    let done = 0;
    const total = toFetch.reduce((s, e) => s + e.bytes, 0);
    for (const e of toFetch) {
      await this.download(apiBase, e, (n) => {
        done += n;
        onProgress?.({ phase: 'download', done, total });
      }, signal);
    }

    const toCheck = entries.filter((e) => this.verified.get(this.fileFor(e)) !== this.stamp(this.fileFor(e)));
    const checkTotal = toCheck.reduce((s, e) => s + e.bytes, 0);
    let checked = 0;
    for (const e of toCheck) {
      const f = this.fileFor(e);
      const got = await hashFile(f, (n) => {
        checked += n;
        onProgress?.({ phase: 'check', done: checked, total: checkTotal });
      }, signal);
      if (got !== e.sha256) {
        rmSync(f, { force: true });
        this.verified.delete(f);
        throw new ArtifactError('BAD_HASH', `The saved ${e.role} proof file was damaged, so it was deleted. Try again to download it again.`);
      }
      this.verified.set(f, this.stamp(f));
    }
    const out = {} as ArtifactPaths;
    for (const e of entries) out[e.role] = this.fileFor(e);
    return out;
  }

  private stamp(file: string): string {
    try {
      const s = statSync(file);
      return `${s.size}:${s.mtimeMs}`;
    } catch {
      return '';
    }
  }

  private async download(apiBase: string, e: ManifestEntry, onBytes: (n: number) => void, signal?: AbortSignal): Promise<void> {
    const final = this.fileFor(e);
    const part = final + '.part';
    let have = existsSync(part) ? statSync(part).size : 0;
    if (have > e.bytes) {
      rmSync(part, { force: true });
      have = 0;
    }
    const hash = createHash('sha256');
    if (have > 0) {
      // Resume: hash what is already here first (it is checked again from the first byte).
      await new Promise<void>((resolve, reject) => {
        const s = createReadStream(part);
        s.on('data', (c) => hash.update(c));
        s.on('error', reject);
        s.on('end', () => resolve());
      });
      onBytes(have);
    }
    const ctl = new AbortController();
    const abortOuter = () => ctl.abort();
    signal?.addEventListener('abort', abortOuter, { once: true });
    let idle: ReturnType<typeof setTimeout> | null = null;
    const kick = () => {
      if (idle) clearTimeout(idle);
      idle = setTimeout(() => ctl.abort(), IDLE_MS);
    };
    try {
      kick();
      let res: Response | null = null;
      if (have < e.bytes) try {
        res = await this.fetchImpl(`${apiBase.replace(/\/+$/, '')}/artifacts/${encodeURIComponent(e.name)}`, {
          headers: have > 0 && have < e.bytes ? { range: `bytes=${have}-` } : {},
          signal: ctl.signal,
          // The SHA-256 pin decides, so a redirect (for example to a file host) is fine.
          redirect: 'follow',
        });
      } catch {
        if (signal?.aborted) throw new ArtifactError('CANCELLED', 'Cancelled.');
        throw new OfflineError('could not reach the server');
      }
      if (!res) {
        // Nothing left to fetch (the part file is complete).
      } else if (res.status === 206 && have > 0) {
        // Resuming.
      } else if (res.status === 200) {
        if (have > 0) {
          // The server sent the whole file again: start over.
          rmSync(part, { force: true });
          onBytes(-have);
          have = 0;
          hash.destroy();
          return this.download(apiBase, e, onBytes, signal);
        }
      } else if (res.status === 404) {
        throw new ArtifactError('NO_ARTIFACTS', `This V18 server doesn't offer the proof file ${e.name}.`);
      } else {
        throw new ArtifactError('DOWNLOAD_FAILED', `Downloading the proof files failed (the server answered ${res.status}).`);
      }
      if (res?.body && have < e.bytes) {
        const out = createWriteStream(part, { flags: have > 0 ? 'a' : 'w' });
        const reader = res.body.getReader();
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            kick();
            have += value.length;
            if (have > e.bytes) throw new ArtifactError('BAD_HASH', `The proof file ${e.name} is bigger than expected.`);
            hash.update(value);
            if (!out.write(value)) await new Promise<void>((r) => out.once('drain', () => r()));
            onBytes(value.length);
          }
        } catch (err) {
          if (err instanceof ArtifactError) throw err;
          if (signal?.aborted) throw new ArtifactError('CANCELLED', 'Cancelled.');
          throw new ArtifactError('DOWNLOAD_FAILED', 'The download of the proof files stopped. Try again: V18 carries on where it stopped.');
        } finally {
          await new Promise<void>((r) => out.end(() => r()));
        }
      }
      if (have !== e.bytes) throw new ArtifactError('DOWNLOAD_FAILED', 'The download of the proof files stopped. Try again: V18 carries on where it stopped.');
      const got = hash.digest('hex');
      if (got !== e.sha256) {
        rmSync(part, { force: true });
        throw new ArtifactError('BAD_HASH', `The downloaded proof file ${e.name} didn't match its SHA-256, so it was deleted. Try again.`);
      }
      renameSync(part, final);
      this.verified.set(final, this.stamp(final));
    } finally {
      if (idle) clearTimeout(idle);
      signal?.removeEventListener('abort', abortOuter);
    }
  }
}
