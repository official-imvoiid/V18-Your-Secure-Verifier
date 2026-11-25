// Writes the "Which IDs work in which country" tables into docs/web/INTEGRATION.md from the
// country catalog (catalog/countries.json, PROTOCOL.md 4d.2). The catalog is the only source:
// nothing about countries is typed by hand in the guide.
//
//   npm run countries --prefix sdk-web            update the guide
//   npm run countries --prefix sdk-web -- --check exit 1 if the guide is out of date
//   node scripts/country-table.mjs --catalog <file> --out <file>
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');
export const START = '<!-- COUNTRIES:START (made by sdk-web/scripts/country-table.mjs from catalog/countries.json; do not edit by hand) -->';
export const END = '<!-- COUNTRIES:END -->';

/** PROTOCOL.md 4d.1: the order of privacy, most private first. */
const PRIVACY = {
  zero_knowledge: { rank: 1, text: 'Zero-knowledge proof: nothing about you leaves your device' },
  on_device: { rank: 2, text: 'Checked on your phone: only "18+" leaves it' },
  wallet: { rank: 3, text: 'Wallet shares only "over 18"' },
  login: { rank: 4, text: 'Login: V18 sees your birth date for a moment and keeps nothing' },
  estimate: { rank: 5, text: 'Face estimate on your phone' },
};
const NEEDS = { camera: 'camera', nfc: 'NFC (tap the ID on the phone)', wallet: 'a wallet app', password: 'your login password' };
const PLATFORMS = { android: 'Android phone', windows: 'Windows PC', web: 'Website (browser)', ios: 'iPhone' };
const REGIONS = { europe: 'Europe', asia: 'Asia', middle_east: 'Middle East', africa: 'Africa', americas: 'Americas', oceania: 'Oceania' };

export class CatalogError extends Error {}

/** Checks the parts of the 4d.2 schema the tables use. Throws CatalogError with every problem found. */
export function validateCatalog(cat) {
  const problems = [];
  if (!cat || typeof cat !== 'object') throw new CatalogError('The catalog is not a JSON object');
  if (cat.version !== 1) problems.push(`version must be 1 (got ${JSON.stringify(cat.version)})`);
  if (!Array.isArray(cat.countries) || cat.countries.length === 0) problems.push('countries must be a non-empty list');
  const seen = new Set();
  for (const [i, c] of (cat.countries ?? []).entries()) {
    const at = `countries[${i}]${c?.code ? ` (${c.code})` : ''}`;
    if (typeof c?.code !== 'string' || !/^[A-Z]{2}$/.test(c.code)) problems.push(`${at}: code must be two capital letters`);
    else if (seen.has(c.code)) problems.push(`${at}: listed twice`);
    else seen.add(c.code);
    if (typeof c?.name !== 'string' || !c.name) problems.push(`${at}: name is missing`);
    if (typeof c?.region !== 'string' || !c.region) problems.push(`${at}: region is missing`);
    if (!Array.isArray(c?.methods)) {
      problems.push(`${at}: methods must be a list`);
      continue;
    }
    for (const [j, m] of c.methods.entries()) {
      const mat = `${at}.methods[${j}]`;
      if (typeof m?.method !== 'string' || !m.method) problems.push(`${mat}: method is missing`);
      if (typeof m?.label !== 'string' || !m.label) problems.push(`${mat}: label is missing`);
      if (!(m?.privacy in PRIVACY)) problems.push(`${mat}: privacy must be one of ${Object.keys(PRIVACY).join(', ')}`);
      if (!Array.isArray(m?.platforms) || m.platforms.length === 0) problems.push(`${mat}: platforms must be a non-empty list`);
      for (const n of m?.needs ?? []) if (!(n in NEEDS)) problems.push(`${mat}: unknown need "${n}"`);
      if (m?.documents !== undefined && !Array.isArray(m.documents)) problems.push(`${mat}: documents must be a list`);
    }
  }
  if (problems.length) throw new CatalogError(`The catalog does not follow PROTOCOL.md 4d.2:\n  - ${problems.join('\n  - ')}`);
}

/** Markdown cells must not break the table. */
const cell = (s) => String(s ?? '').replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim();
const list = (items, map) => (items ?? []).map((x) => cell(map?.[x] ?? x)).join(', ');

/** Renders the tables (Markdown) for every region, countries A to Z, ways most private first. */
export function renderCountryTables(cat) {
  validateCatalog(cat);
  const byRegion = new Map();
  for (const c of cat.countries) {
    if (!byRegion.has(c.region)) byRegion.set(c.region, []);
    byRegion.get(c.region).push(c);
  }
  const regionOrder = [...byRegion.keys()].sort((a, b) => {
    const ia = Object.keys(REGIONS).indexOf(a);
    const ib = Object.keys(REGIONS).indexOf(b);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
  });
  const totalWays = cat.countries.reduce((n, c) => n + c.methods.length, 0);
  const out = [
    `${cat.countries.length} countries and ${totalWays} ways to prove age, from catalog version ${cat.version}` +
      (cat.updated || cat.status
        ? ` (${[cat.updated ? `updated ${cell(cat.updated)}` : '', cat.status ? `status: ${cell(cat.status)}` : ''].filter(Boolean).join(', ')})`
        : '') + '.',
    '',
  ];
  for (const region of regionOrder) {
    out.push(`### ${REGIONS[region] ?? cell(region)}`, '');
    out.push('| Country | Way to prove age | IDs it accepts | How private | Works on | Needs |');
    out.push('|---------|------------------|----------------|-------------|----------|-------|');
    const countries = byRegion.get(region).sort((a, b) => a.name.localeCompare(b.name));
    for (const c of countries) {
      const ways = [...c.methods].sort((a, b) => PRIVACY[a.privacy].rank - PRIVACY[b.privacy].rank || a.label.localeCompare(b.label));
      if (ways.length === 0) {
        out.push(`| ${cell(c.name)} (${c.code}) | no ways listed in the catalog | | | | |`);
        continue;
      }
      ways.forEach((m, i) => {
        out.push(
          `| ${i === 0 ? `${cell(c.name)} (${c.code})` : ''} | ${cell(m.label)} | ${list(m.documents)} | ${cell(PRIVACY[m.privacy].text)} | ${list(m.platforms, PLATFORMS)} | ${list(m.needs, NEEDS) || 'nothing extra'} |`
        );
      });
    }
    out.push('');
  }
  return out.join('\n').trimEnd();
}

/** Puts `body` between the markers in `doc` (adds the markers at the end if they are missing). */
export function replaceBetweenMarkers(doc, body) {
  const s = doc.indexOf(START);
  const e = doc.indexOf(END);
  const block = `${START}\n\n${body}\n\n${END}`;
  if (s < 0 || e < 0 || e < s) return `${doc.trimEnd()}\n\n${block}\n`;
  return doc.slice(0, s) + block + doc.slice(e + END.length);
}

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : fallback;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const catalogFile = resolve(arg('--catalog', resolve(REPO, 'catalog', 'countries.json')));
  const outFile = resolve(arg('--out', resolve(REPO, 'docs', 'web', 'INTEGRATION.md')));
  const check = process.argv.includes('--check');
  let body;
  if (!existsSync(catalogFile)) {
    console.error(`No catalog at ${catalogFile} yet. The guide keeps its note; run this again once the catalog exists.`);
    body =
      'The country list comes from `catalog/countries.json` (PROTOCOL.md 4d.2). That file did not exist yet ' +
      'when this guide was last generated, so the list is not here. Run `npm run countries --prefix sdk-web` ' +
      'to fill it in. Until then, `GET /v1/catalog` on your V18 server lists what it supports.';
    if (check) process.exit(1);
  } else {
    try {
      body = renderCountryTables(JSON.parse(readFileSync(catalogFile, 'utf8')));
    } catch (e) {
      console.error(e instanceof CatalogError ? e.message : `Could not read ${catalogFile}: ${e.message}`);
      process.exit(2);
    }
  }
  const before = readFileSync(outFile, 'utf8');
  const after = replaceBetweenMarkers(before, body);
  if (check) {
    if (before !== after) {
      console.error(`${outFile} is out of date. Run: npm run countries --prefix sdk-web`);
      process.exit(1);
    }
    console.log('The country tables are up to date.');
  } else {
    writeFileSync(outFile, after);
    console.log(before === after ? 'The country tables were already up to date.' : `Updated the country tables in ${outFile}`);
  }
}
