// Builds the Windows Hello helper (Rust, napi-rs) and copies it to native/v18-hello/v18_hello.node.
// The same .node file works in Node (tests) and Electron, because it uses Node-API.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const crate = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'native', 'v18-hello');
const out = path.join(crate, 'v18_hello.node');

if (process.platform !== 'win32') {
  console.log('Skipping the Windows Hello helper: it only builds on Windows.');
  process.exit(0);
}
const cargo = spawnSync('cargo', ['--version'], { encoding: 'utf8', shell: true });
if (cargo.status !== 0) {
  if (existsSync(out)) {
    console.warn('cargo not found; keeping the existing v18_hello.node');
    process.exit(0);
  }
  console.error('cargo (Rust) is needed to build the Windows Hello helper. Install Rust from https://rustup.rs');
  process.exit(1);
}
const r = spawnSync('cargo', ['build', '--release'], { cwd: crate, stdio: 'inherit', shell: true });
if (r.status !== 0) process.exit(r.status ?? 1);
copyFileSync(path.join(crate, 'target', 'release', 'v18_hello.dll'), out);
console.log('Built native/v18-hello/v18_hello.node');
