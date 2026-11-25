// Builds V18 for Windows into dist/ with esbuild.
//   node scripts/build.mjs            debug build (server allowlist includes localhost)
//   node scripts/build.mjs --release  release build (production server placeholder only)
import { build } from 'esbuild';
import { copyFileSync, cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');
const release = process.argv.includes('--release') || process.env.V18_RELEASE === '1';

// The production server (PROTOCOL 4c.7). Release builds trust ONLY this server.
// Set it with:  set V18_PRODUCTION_SERVER=https://api.your-domain.example   (before npm run dist:release)
const productionServer = process.env.V18_PRODUCTION_SERVER || 'https://api.v18.example';
{
  let u;
  try {
    u = new URL(productionServer);
  } catch {
    u = null;
  }
  if (!u || u.protocol !== 'https:' || u.origin !== productionServer.replace(/\/+$/, '') || u.username || u.password) {
    console.error(`V18_PRODUCTION_SERVER must be a plain https origin like https://api.example.com (got "${productionServer}")`);
    process.exit(1);
  }
}

rmSync(dist, { recursive: true, force: true });
mkdirSync(path.join(dist, 'renderer'), { recursive: true });
mkdirSync(path.join(dist, 'native'), { recursive: true });
mkdirSync(path.join(dist, 'assets'), { recursive: true });

const common = { bundle: true, sourcemap: false, logLevel: 'warning', define: { __V18_DEBUG__: JSON.stringify(!release), __V18_PRODUCTION_SERVER__: JSON.stringify(new URL(productionServer).origin) }, legalComments: 'none' };

await build({ ...common, entryPoints: [path.join(root, 'src/main/main.ts')], outfile: path.join(dist, 'main.cjs'), platform: 'node', format: 'cjs', target: 'node22', external: ['electron'] });
await build({ ...common, entryPoints: [path.join(root, 'src/preload/preload.ts')], outfile: path.join(dist, 'preload.cjs'), platform: 'node', format: 'cjs', target: 'node22', external: ['electron'] });
await build({ ...common, entryPoints: [path.join(root, 'src/renderer/app.ts')], outfile: path.join(dist, 'renderer/app.js'), platform: 'browser', format: 'iife', target: 'chrome130' });
// The proof builder (Anon Aadhaar + snarkjs), run in its own process. snarkjs's thread helper
// (web-worker) starts worker threads from this same file, so it must stay one self-contained CJS file.
await build({ ...common, entryPoints: [path.join(root, 'src/prover/worker.ts')], outfile: path.join(dist, 'prover.cjs'), platform: 'node', format: 'cjs', target: 'node22' });

for (const f of ['index.html', 'v18.css', 'app.css']) copyFileSync(path.join(root, 'src/renderer', f), path.join(dist, 'renderer', f));
cpSync(path.join(root, 'assets'), path.join(dist, 'assets'), { recursive: true });

const addon = path.join(root, 'native/v18-hello/v18_hello.node');
if (existsSync(addon)) copyFileSync(addon, path.join(dist, 'native', 'v18_hello.node'));
else console.warn('WARNING: native/v18-hello/v18_hello.node is missing. Run "npm run build:native". Without it V18 shows the PC security error.');

console.log(`Built dist/ (${release ? 'release' : 'debug'} build, production server ${new URL(productionServer).origin}${release ? ' only' : ' + http://localhost:8080'})`);
