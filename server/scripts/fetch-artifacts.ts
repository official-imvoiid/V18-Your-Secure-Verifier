/**
 * npm run fetch-artifacts            downloads the required Anon Aadhaar files
 * npm run fetch-artifacts -- --chunks  also the 10 gzip zkey chunks (about 296 MB, optional)
 * npm run fetch-artifacts -- --check   only checks the files already on disk
 *
 * PROTOCOL.md 4c.1. Files come from the official Anon Aadhaar bucket named in
 * `@anon-aadhaar/core` (src/constants.ts, artifactUrls.v2). Every file must
 * match the SHA-256 pinned in server/assets/artifacts/manifest.json. A file
 * that does not match is deleted and the script fails.
 *
 * `--pin` (maintainers only) writes the downloaded hashes into the manifest.
 * It is how the pins were made the first time; it also cross-checks the S3
 * ETag (the MD5 of single-part uploads) and that vkey.json really belongs to
 * circuit_final.zkey.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import {
  ARTIFACTS_DIR,
  ArtifactEntry,
  ArtifactManifest,
  hashFile,
  loadManifest,
  MANIFEST_PATH,
  sourceUrl,
} from '../src/artifacts/manifest.js';

const args = new Set(process.argv.slice(2));
const PIN = args.has('--pin');
const CHUNKS = args.has('--chunks') || PIN;
const CHECK_ONLY = args.has('--check');

function mb(n: number): string {
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

async function headEtag(url: string): Promise<{ etag: string | null; length: number | null }> {
  const res = await fetch(url, { method: 'HEAD' });
  if (!res.ok) throw new Error(`HEAD ${url} gave HTTP ${res.status}`);
  const len = res.headers.get('content-length');
  return { etag: (res.headers.get('etag') ?? '').replace(/"/g, '') || null, length: len ? Number(len) : null };
}

/** Downloads to <name>.part, resuming a broken download with a Range request. */
async function download(url: string, target: string, expectedBytes: number | null): Promise<void> {
  const part = `${target}.part`;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const have = fs.existsSync(part) ? fs.statSync(part).size : 0;
      const headers: Record<string, string> = have > 0 ? { Range: `bytes=${have}-` } : {};
      const res = await fetch(url, { headers });
      if (res.status === 416 && expectedBytes !== null && have === expectedBytes) break;
      if (!(res.ok || res.status === 206) || !res.body) throw new Error(`GET ${url} gave HTTP ${res.status}`);
      const append = res.status === 206 && have > 0;
      if (have > 0 && !append) process.stderr.write(`  server ignored the resume request, starting again\n`);
      const total = expectedBytes ?? (Number(res.headers.get('content-length')) || 0) + (append ? have : 0);
      let done = append ? have : 0;
      let lastShown = 0;
      const body = Readable.fromWeb(res.body as never);
      body.on('data', (c: Buffer) => {
        done += c.length;
        if (process.stderr.isTTY && Date.now() - lastShown > 500) {
          lastShown = Date.now();
          process.stderr.write(`\r  ${mb(done)} of ${mb(total)}   `);
        }
      });
      await pipeline(body, fs.createWriteStream(part, { flags: append ? 'a' : 'w' }));
      if (process.stderr.isTTY) process.stderr.write('\n');
      break;
    } catch (err) {
      if (attempt === 4) throw err;
      process.stderr.write(`  download broke (${(err as Error).message}); retry ${attempt} of 3\n`);
      await new Promise((r) => setTimeout(r, 2000 * attempt));
    }
  }
  fs.renameSync(part, target);
}

async function crossCheckVkey(dir: string): Promise<void> {
  const zkey = path.join(dir, 'circuit_final.zkey');
  const vkeyFile = path.join(dir, 'vkey.json');
  if (!fs.existsSync(zkey) || !fs.existsSync(vkeyFile)) return;
  process.stderr.write('Cross-check: exporting the verification key from circuit_final.zkey (takes a while)...\n');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const snarkjs = require('snarkjs') as { zKey: { exportVerificationKey(f: string): Promise<unknown> } };
  const fromZkey = await snarkjs.zKey.exportVerificationKey(zkey);
  const published = JSON.parse(fs.readFileSync(vkeyFile, 'utf8'));
  const norm = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x));
  const strip = (v: Record<string, unknown>) => {
    const { vk_alphabeta_12: _drop, ...rest } = v;
    return rest;
  };
  if (norm(strip(fromZkey as Record<string, unknown>)) !== norm(strip(published))) {
    throw new Error('vkey.json does NOT match circuit_final.zkey');
  }
  process.stderr.write('Cross-check passed: vkey.json matches circuit_final.zkey.\n');
  const curve = (globalThis as { curve_bn128?: { terminate(): Promise<void> } }).curve_bn128;
  if (curve) await curve.terminate();
}

async function main(): Promise<void> {
  const manifest: ArtifactManifest = loadManifest();
  fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  const wanted = manifest.files.filter((f) => !f.optional || CHUNKS);
  let failed = 0;

  for (const f of wanted) {
    const target = path.join(ARTIFACTS_DIR, f.name);
    const url = sourceUrl(manifest, f);
    process.stderr.write(`${f.name}\n`);

    if (!PIN && !f.sha256) {
      process.stderr.write(`  no SHA-256 pinned in the manifest. Refusing to download an unpinned file.\n`);
      failed++;
      continue;
    }

    if (fs.existsSync(target)) {
      const h = await hashFile(target);
      if (f.sha256 && h.sha256 === f.sha256) {
        process.stderr.write(`  already here and the SHA-256 matches (${mb(h.bytes)})\n`);
        continue;
      }
      if (CHECK_ONLY) {
        process.stderr.write(`  SHA-256 MISMATCH (got ${h.sha256})\n`);
        failed++;
        continue;
      }
      if (!PIN) {
        process.stderr.write(`  on disk but the SHA-256 does not match, downloading again\n`);
        fs.rmSync(target);
      }
    } else if (CHECK_ONLY) {
      process.stderr.write(f.optional ? `  not downloaded (optional)\n` : `  MISSING\n`);
      if (!f.optional) failed++;
      continue;
    }

    if (!fs.existsSync(target)) {
      const head = await headEtag(url);
      process.stderr.write(`  downloading ${url} (${head.length ? mb(head.length) : 'size unknown'})\n`);
      await download(url, target, head.length ?? f.bytes);
      const h = await hashFile(target);
      if (PIN && head.etag && !head.etag.includes('-') && head.etag !== h.md5) {
        fs.rmSync(target);
        throw new Error(`${f.name}: MD5 ${h.md5} does not match the S3 ETag ${head.etag}`);
      }
    }

    const h = await hashFile(target);
    if (PIN) {
      f.sha256 = h.sha256;
      f.bytes = h.bytes;
      process.stderr.write(`  pinned sha256 ${h.sha256}, ${h.bytes} bytes\n`);
    } else if (h.sha256 !== f.sha256 || (f.bytes !== null && h.bytes !== f.bytes)) {
      fs.rmSync(target);
      process.stderr.write(`  SHA-256 MISMATCH: got ${h.sha256}, pinned ${f.sha256}. File deleted.\n`);
      failed++;
    } else {
      process.stderr.write(`  OK, SHA-256 matches the pin (${mb(h.bytes)})\n`);
    }
  }

  if (PIN) {
    await crossCheckVkey(ARTIFACTS_DIR);
    fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n');
    process.stderr.write(`Wrote pins to ${MANIFEST_PATH}\n`);
  }
  if (failed > 0) {
    process.stderr.write(`${failed} file(s) failed. Nothing unverified was kept.\n`);
    process.exit(1);
  }
  process.stderr.write('All artifact files are present and match their pinned SHA-256.\n');
}

main().catch((err: unknown) => {
  process.stderr.write(`fetch-artifacts failed: ${(err as Error).message}\n`);
  process.exit(1);
});

export type { ArtifactEntry };
