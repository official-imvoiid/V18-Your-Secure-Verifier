// Runs every V18 test suite, one after another, and prints one summary table.
//   node tests/run-all.mjs          (or: npm run test:all in the project folder)
// Build first (npm run build). The Android app's tests run only when Flutter is installed.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const win = process.platform === 'win32';
const npm = win ? 'npm.cmd' : 'npm';
const py = win ? 'python' : 'python3';
const flutter = win ? 'flutter.bat' : 'flutter';

const suites = [
  { name: 'Server (unit and API)', cwd: 'server', cmd: npm, args: ['test'] },
  { name: 'Login connectors', cwd: 'connectors', cmd: npm, args: ['test'] },
  { name: 'Website verify library (Node)', cwd: 'sdk-web/verify-node', cmd: npm, args: ['test'] },
  { name: 'Website verify library (Python)', cwd: '.', cmd: py, args: ['-m', 'pytest', 'sdk-web/verify-python/tests', '-q'] },
  { name: 'Website widget', cwd: 'sdk-web/widget', cmd: npm, args: ['test'] },
  { name: 'Demo website', cwd: 'sdk-web/demo-site', cmd: npm, args: ['test'] },
  { name: 'Country catalog', cwd: '.', cmd: py, args: ['-m', 'pytest', 'catalog', '-q'] },
  { name: 'Windows app', cwd: 'windows', cmd: npm, args: ['test'] },
  { name: 'Android app', cwd: 'mobile', cmd: flutter, args: ['test'], optional: true },
  { name: 'Product tests (end to end)', cwd: 'tests', cmd: npm, args: ['test'] },
];

function counts(out) {
  let m = out.match(/[ℹ#] pass (\d+)[\s\S]*?[ℹ#] fail (\d+)/);
  if (m) return { pass: +m[1], fail: +m[2] };
  m = out.match(/(\d+) passed(?:, (\d+) failed)?/);
  if (m) return { pass: +m[1], fail: +(m[2] ?? 0) };
  m = out.match(/\+(\d+)(?: ~\d+)?(?: -(\d+))?: (?:All tests passed|Some tests failed)/);
  if (m) return { pass: +m[1], fail: +(m[2] ?? 0) };
  return null;
}

const rows = [];
let failed = false;
for (const s of suites) {
  process.stdout.write(`Running: ${s.name} ... `);
  const started = Date.now();
  const r = spawnSync(s.cmd, s.args, { cwd: path.join(ROOT, s.cwd), encoding: 'utf8', shell: win, maxBuffer: 64 * 1024 * 1024 });
  const secs = ((Date.now() - started) / 1000).toFixed(0);
  if (r.error && s.optional) {
    rows.push([s.name, 'skipped', '-', '-', `${s.cmd} not installed`]);
    console.log('skipped');
    continue;
  }
  const out = `${r.stdout ?? ''}\n${r.stderr ?? ''}`;
  const c = counts(out);
  const okRun = r.status === 0;
  if (!okRun) failed = true;
  rows.push([s.name, okRun ? 'PASS' : 'FAIL', c ? String(c.pass) : '?', c ? String(c.fail) : '?', `${secs} s`]);
  console.log(okRun ? 'pass' : 'FAIL');
  if (!okRun) console.log(out.split('\n').slice(-40).join('\n'));
}

const head = ['Suite', 'Result', 'Passed', 'Failed', 'Time'];
const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
const line = (cells) => cells.map((c, i) => c.padEnd(widths[i])).join('  ');
console.log('\n' + line(head));
console.log(widths.map((w) => '-'.repeat(w)).join('  '));
for (const r of rows) console.log(line(r));
const total = rows.reduce((n, r) => n + (Number(r[2]) || 0), 0);
console.log(`\n${total} tests passed in total. ${failed ? 'Some suites FAILED.' : 'Every suite passed.'}`);
process.exit(failed ? 1 : 0);
