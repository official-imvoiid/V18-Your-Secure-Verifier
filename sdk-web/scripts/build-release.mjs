// Builds the V18 web kit release into sdk-web/release/ and checks it.
//
//   npm run release --prefix sdk-web
//
// Makes:
//   v18-<version>.min.js          the widget bundle a website loads
//   SRI.txt, sri.json             its Subresource Integrity hash (sha384)
//   embed.html                    the 2-line embed with integrity
//   v18-verify-<version>.tgz      npm pack of @v18/verify
//   v18-widget-<version>.tgz      npm pack of @v18/widget
//   v18_verify-<version>-py3-none-any.whl and v18_verify-<version>.tar.gz   (python -m build)
//   CHANGELOG.md, LICENSE, README.md, SHA256SUMS.txt
//
// Python: set PYTHON to an interpreter that has the `build` package. By default it uses
// sdk-web/.venv-release if it exists, otherwise `python`.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'release');
const win = process.platform === 'win32';
const npm = win ? 'npm.cmd' : 'npm';
const venvPython = join(ROOT, '.venv-release', win ? 'Scripts/python.exe' : 'bin/python');
const PYTHON = process.env.PYTHON || (existsSync(venvPython) ? venvPython : 'python');

const step = (t) => console.log(`\n== ${t}`);
const run = (cmd, args, cwd, opts = {}) =>
  execFileSync(cmd, args, { cwd, stdio: opts.quiet ? 'pipe' : 'inherit', shell: win && cmd.endsWith('.cmd'), encoding: 'utf8', ...opts });
const sha = (alg, file, enc = 'hex') => createHash(alg).update(readFileSync(file)).digest(enc);
const json = (f) => JSON.parse(readFileSync(f, 'utf8'));

const version = json(join(ROOT, 'widget', 'package.json')).version;
const others = {
  verify: json(join(ROOT, 'verify-node', 'package.json')).version,
  python: /version\s*=\s*"([^"]+)"/.exec(readFileSync(join(ROOT, 'verify-python', 'pyproject.toml'), 'utf8'))[1],
  changelog: /^## (\S+)/m.exec(readFileSync(join(ROOT, 'CHANGELOG.md'), 'utf8'))[1],
};
for (const [what, v] of Object.entries(others)) {
  if (v !== version) throw new Error(`Version mismatch: widget ${version}, ${what} ${v}`);
}

step(`V18 web kit ${version}: cleaning ${OUT}`);
rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

step('Building @v18/verify and @v18/widget');
run(npm, ['run', 'build'], join(ROOT, 'verify-node'));
run(npm, ['run', 'build'], join(ROOT, 'widget'));

step('Widget bundle and SRI hash');
const bundleName = `v18-${version}.min.js`;
const bundle = join(OUT, bundleName);
copyFileSync(join(ROOT, 'widget', 'dist', 'v18.min.js'), bundle);
const integrity = `sha384-${sha('sha384', bundle, 'base64')}`;
const src = `https://cdn.v18.example/${bundleName}`;
writeFileSync(join(OUT, 'SRI.txt'), `${bundleName} ${integrity}\n`);
writeFileSync(join(OUT, 'sri.json'), JSON.stringify({ file: bundleName, version, integrity, bytes: readFileSync(bundle).length }, null, 2) + '\n');
writeFileSync(
  join(OUT, 'embed.html'),
  `<script src="${src}" integrity="${integrity}" crossorigin="anonymous" data-v18-server="https://api.v18.example"></script>\n` +
    `<button data-v18-min-age="18">Verify age</button>\n`
);
console.log(`${bundleName}  ${integrity}`);

step('npm pack');
for (const pkg of ['verify-node', 'widget']) {
  const out = run(npm, ['pack', '--json', '--pack-destination', OUT], join(ROOT, pkg), { quiet: true });
  const info = JSON.parse(out.slice(out.indexOf('[')))[0];
  console.log(`${info.filename}  (${info.entryCount} files, ${info.size} bytes)`);
  if (info.files.some((f) => /tests?\//.test(f.path))) throw new Error(`${pkg}: tests ended up in the package`);
}

step('Python wheel and sdist (python -m build)');
run(PYTHON, ['-m', 'build', '--outdir', OUT, join(ROOT, 'verify-python')], ROOT);
// setuptools leaves these next to the source; they are build leftovers, not source.
for (const junk of ['build', 'v18_verify.egg-info']) rmSync(join(ROOT, 'verify-python', junk), { recursive: true, force: true });

step('Copying CHANGELOG, LICENSE and README');
copyFileSync(join(ROOT, 'CHANGELOG.md'), join(OUT, 'CHANGELOG.md'));
copyFileSync(join(ROOT, 'LICENSE'), join(OUT, 'LICENSE'));
writeFileSync(
  join(OUT, 'README.md'),
  `# V18 web kit ${version}: release files\n\n` +
    `| File | What it is |\n|------|------------|\n` +
    `| \`${bundleName}\` | The widget a website loads. Host it as is (do not change a byte, or the hash stops matching) |\n` +
    `| \`SRI.txt\`, \`sri.json\` | Its integrity hash: \`${integrity}\` |\n` +
    `| \`embed.html\` | The 2-line embed with \`integrity\` (change the CDN URL and \`data-v18-server\` to yours) |\n` +
    `| \`v18-verify-${version}.tgz\` | \`@v18/verify\` for Node.js servers: \`npm install ./v18-verify-${version}.tgz\` |\n` +
    `| \`v18-widget-${version}.tgz\` | \`@v18/widget\` for sites that bundle their own JavaScript |\n` +
    `| \`v18_verify-${version}-py3-none-any.whl\`, \`v18_verify-${version}.tar.gz\` | \`v18_verify\` for Python servers: \`pip install v18_verify-${version}-py3-none-any.whl\` |\n` +
    `| \`CHANGELOG.md\`, \`LICENSE\` | What changed; the licence (UNLICENSED: none chosen yet) |\n` +
    `| \`SHA256SUMS.txt\` | SHA-256 of every file here |\n\n` +
    `Nothing here is published to npm, PyPI or a CDN. The guide is docs/web/INTEGRATION.md.\n`
);

step('Checking the release');
// 1. The npm tarball installs and loads.
const tmp = mkdtempSync(join(tmpdir(), 'v18-release-check-'));
try {
  writeFileSync(join(tmp, 'package.json'), '{"name":"check","version":"1.0.0","private":true}');
  run(npm, ['install', '--no-audit', '--no-fund', '--silent', join(OUT, `v18-verify-${version}.tgz`), join(OUT, `v18-widget-${version}.tgz`)], tmp, { quiet: true });
  const loaded = run(
    process.execPath,
    ['-e', "const v=require('@v18/verify');const w=require('@v18/widget');console.log(typeof v.V18Verifier, typeof v.ChallengeStore, w.VERSION, require.resolve('@v18/widget/v18.min.js').length>0)"],
    tmp,
    { quiet: true }
  ).trim();
  if (loaded !== `function function ${version} true`) throw new Error(`npm packages did not load: ${loaded}`);
  console.log(`npm packages install and load: ${loaded}`);
  // 2. The wheel installs (without its dependency, which this Python already has) and imports.
  const target = join(tmp, 'py');
  run(PYTHON, ['-m', 'pip', 'install', '--quiet', '--no-deps', '--target', target, join(OUT, `v18_verify-${version}-py3-none-any.whl`)], ROOT, { quiet: true });
  const py = run('python', ['-I', '-c', `import sys; sys.path.insert(0, r"${target}"); import v18_verify; print(v18_verify.__version__, v18_verify.V18Verifier.__name__)`], tmp, { quiet: true }).trim();
  if (py !== `${version} V18Verifier`) throw new Error(`wheel did not import: ${py}`);
  console.log(`Python wheel installs and imports: ${py}`);
  // 3. The bundle's hash is what the embed says, and the bundle knows its version.
  if (!readFileSync(bundle, 'utf8').includes(`V18 widget ${version}`)) throw new Error('bundle has no version banner');
  if (`sha384-${sha('sha384', bundle, 'base64')}` !== integrity) throw new Error('SRI mismatch');
  console.log('SRI hash matches the bundle');
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

step('SHA256SUMS.txt');
const files = readdirSync(OUT).filter((f) => f !== 'SHA256SUMS.txt').sort();
writeFileSync(join(OUT, 'SHA256SUMS.txt'), files.map((f) => `${sha('sha256', join(OUT, f))}  ${f}`).join('\n') + '\n');
for (const f of files) console.log(`  ${f}`);
console.log(`\nRelease ${version} is in ${OUT}`);
