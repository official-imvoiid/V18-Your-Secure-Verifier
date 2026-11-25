// Builds the browser bundle (one file, no dependencies at run time) with the package version in it.
//   dist/v18.min.js  the file a website loads (release/ copies it as v18-<version>.min.js)
//   dist/v18.js      the same bytes, under the name the demo site and older embeds use
import { build } from 'esbuild';
import { copyFileSync, readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

await build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  minify: true,
  format: 'iife',
  globalName: 'V18Global',
  target: 'es2020',
  platform: 'browser',
  legalComments: 'none',
  banner: { js: `/*! V18 widget ${pkg.version} (${pkg.license}) */` },
  define: { __V18_VERSION__: JSON.stringify(pkg.version) },
  outfile: 'dist/v18.min.js',
  logLevel: 'info',
});
copyFileSync('dist/v18.min.js', 'dist/v18.js');
