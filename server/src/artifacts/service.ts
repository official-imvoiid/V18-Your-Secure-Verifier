import * as fs from 'node:fs';
import * as path from 'node:path';
import { ARTIFACTS_DIR, ArtifactEntry, ArtifactManifest, hashFile, loadManifest, sourceUrl } from './manifest.js';

/**
 * Serves the pinned Anon Aadhaar circuit files (PROTOCOL.md 4c.1).
 *
 * At start-up every file on disk is hashed in the background (the 612 MB
 * zkey takes a few seconds); a file is served only after its SHA-256 matched
 * the pin. The result is cached by size and modification time in the data
 * folder, so a restart does not hash everything again.
 */
export class ArtifactService {
  private readonly manifest: ArtifactManifest;
  private readonly verified = new Set<string>();
  private readonly failed = new Map<string, string>();
  readonly ready: Promise<void>;

  constructor(
    private readonly opts: { publicUrl: string; dir?: string; cacheFile: string }
  ) {
    this.manifest = loadManifest();
    this.ready = this.verifyAll().catch((err) => {
      console.error('[v18] artifact check failed:', (err as Error).message);
    });
  }

  private get dir(): string {
    return this.opts.dir ?? ARTIFACTS_DIR;
  }

  private async verifyAll(): Promise<void> {
    let cache: Record<string, { size: number; mtimeMs: number; sha256: string }> = {};
    try {
      cache = JSON.parse(fs.readFileSync(this.opts.cacheFile, 'utf8'));
    } catch {
      /* no cache yet */
    }
    for (const f of this.manifest.files) {
      if (!f.sha256) continue;
      const file = path.join(this.dir, f.name);
      if (!fs.existsSync(file)) continue;
      const st = fs.statSync(file);
      const c = cache[f.name];
      let sha = c && c.size === st.size && c.mtimeMs === st.mtimeMs ? c.sha256 : null;
      if (!sha) {
        sha = (await hashFile(file)).sha256;
        cache[f.name] = { size: st.size, mtimeMs: st.mtimeMs, sha256: sha };
      }
      if (sha === f.sha256 && st.size === f.bytes) this.verified.add(f.name);
      else this.failed.set(f.name, `SHA-256 mismatch (got ${sha})`);
    }
    try {
      fs.mkdirSync(path.dirname(this.opts.cacheFile), { recursive: true });
      fs.writeFileSync(this.opts.cacheFile, JSON.stringify(cache, null, 2));
    } catch {
      /* cache is only an optimisation */
    }
  }

  /** GET /v1/artifacts/manifest: [{name, sha256, bytes, url, ...}] for every pinned file. */
  list() {
    return this.manifest.files
      .filter((f): f is ArtifactEntry & { sha256: string; bytes: number } => f.sha256 !== null && f.bytes !== null)
      .map((f) => ({
        name: f.name,
        sha256: f.sha256,
        bytes: f.bytes,
        url: `${this.opts.publicUrl}/v1/artifacts/${f.name}`,
        role: f.role,
        optional: f.optional,
        available: this.verified.has(f.name),
        sourceUrl: sourceUrl(this.manifest, f),
      }));
  }

  get set(): string {
    return this.manifest.set;
  }

  /** The verified file for a name, or why not. */
  lookup(name: string): { file: string; entry: ArtifactEntry } | { error: 'unknown' | 'not_ready' } {
    const entry = this.manifest.files.find((f) => f.name === name);
    if (!entry || !entry.sha256) return { error: 'unknown' };
    if (!this.verified.has(name)) return { error: 'not_ready' };
    return { file: path.join(this.dir, name), entry };
  }

  /** True when the three required files are present and verified. */
  get complete(): boolean {
    return this.manifest.files.filter((f) => !f.optional).every((f) => this.verified.has(f.name));
  }
}

export function contentTypeFor(name: string): string {
  if (name.endsWith('.wasm')) return 'application/wasm';
  if (name.endsWith('.json')) return 'application/json';
  if (name.endsWith('.gz')) return 'application/gzip';
  return 'application/octet-stream';
}
