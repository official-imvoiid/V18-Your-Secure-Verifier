import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { serverRoot } from '../config.js';

/**
 * Anon Aadhaar circuit files (PROTOCOL.md 4c.1).
 *
 * `server/assets/artifacts/manifest.json` pins the SHA-256 of every official
 * file. `npm run fetch-artifacts` downloads them into the same folder and
 * refuses anything that does not match. The server serves them to the apps
 * and verifies Aadhaar proofs with the pinned `vkey.json`.
 */

export const ARTIFACTS_DIR = path.join(serverRoot, 'assets', 'artifacts');
export const MANIFEST_PATH = path.join(ARTIFACTS_DIR, 'manifest.json');

export interface ArtifactEntry {
  /** File name on disk and in `GET /v1/artifacts/:name`. */
  name: string;
  role: 'verification_key' | 'witness_wasm' | 'proving_key' | 'proving_key_chunk';
  /** Path below `sourceBase`. */
  source: string;
  sha256: string | null;
  bytes: number | null;
  /** Optional files (the gzip zkey chunks) are fetched only with --chunks. */
  optional: boolean;
}

export interface ArtifactManifest {
  version: 1;
  set: string;
  about: string;
  sourceBase: string;
  files: ArtifactEntry[];
}

/** Only plain file names: no folders, no dots at the start. */
export const ARTIFACT_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;

export function loadManifest(file = MANIFEST_PATH): ArtifactManifest {
  const m = JSON.parse(fs.readFileSync(file, 'utf8')) as ArtifactManifest;
  if (m.version !== 1 || !Array.isArray(m.files)) throw new Error(`${file} is not a V18 artifact manifest`);
  for (const f of m.files) {
    if (!ARTIFACT_NAME.test(f.name)) throw new Error(`Bad artifact name in manifest: ${f.name}`);
    if (f.sha256 !== null && !/^[0-9a-f]{64}$/.test(f.sha256)) throw new Error(`Bad sha256 for ${f.name}`);
  }
  return m;
}

export function sourceUrl(m: ArtifactManifest, f: ArtifactEntry): string {
  return new URL(f.source, m.sourceBase).toString();
}

/** Streams a file through SHA-256 (and MD5, which S3 uses as the ETag of single-part uploads). */
export async function hashFile(file: string): Promise<{ sha256: string; md5: string; bytes: number }> {
  const sha = crypto.createHash('sha256');
  const md5 = crypto.createHash('md5');
  let bytes = 0;
  await new Promise<void>((resolve, reject) => {
    fs.createReadStream(file, { highWaterMark: 1 << 20 })
      .on('data', (chunk) => {
        const b = chunk as Buffer;
        sha.update(b);
        md5.update(b);
        bytes += b.length;
      })
      .on('error', reject)
      .on('end', () => resolve());
  });
  return { sha256: sha.digest('hex'), md5: md5.digest('hex'), bytes };
}
