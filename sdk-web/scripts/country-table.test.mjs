// Tests for scripts/country-table.mjs (the "Which IDs work in which country" tables).
//   node --test scripts/
import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { END, START, CatalogError, renderCountryTables, replaceBetweenMarkers, validateCatalog } from './country-table.mjs';

/** A small catalog in the PROTOCOL.md 4d.2 shape (test data, not the real catalog). */
const sample = () => ({
  version: 1,
  countries: [
    {
      code: 'IN', name: 'India', region: 'asia',
      methods: [
        { method: 'emrtd_attested', label: 'Passport (chip)', documents: ['Indian e-passport'], docTypes: ['P'], needs: ['nfc'], privacy: 'on_device', platforms: ['android'] },
        { method: 'connector:digilocker', label: 'DigiLocker login', documents: ['DigiLocker account'], needs: ['password'], privacy: 'login', platforms: ['android', 'windows'] },
        { method: 'anon_aadhaar', label: 'Aadhaar QR', documents: ['Aadhaar letter', 'e-Aadhaar PDF'], needs: ['camera'], privacy: 'zero_knowledge', platforms: ['android', 'windows'] },
      ],
    },
    {
      code: 'DE', name: 'Germany', region: 'europe',
      methods: [
        { method: 'mdoc_wallet', label: 'EU wallet | mDL', documents: ['EU PID'], needs: ['wallet'], privacy: 'wallet', platforms: ['web'] },
        { method: 'emrtd_attested', label: 'ID card (chip)', documents: ['Personalausweis'], needs: ['nfc'], privacy: 'on_device', platforms: ['android'] },
      ],
    },
    { code: 'AT', name: 'Austria', region: 'europe', methods: [] },
  ],
});

describe('country table', () => {
  it('renders one table per region, Europe first, countries A to Z, most private way first', () => {
    const md = renderCountryTables(sample());
    assert.ok(md.startsWith('3 countries and 5 ways to prove age, from catalog version 1.'));
    assert.ok(renderCountryTables({ ...sample(), updated: '2026-11-23', status: 'draft' }).startsWith('3 countries and 5 ways to prove age, from catalog version 1 (updated 2026-11-23, status: draft).'));
    assert.ok(md.indexOf('### Europe') < md.indexOf('### Asia'));
    assert.ok(md.indexOf('Austria (AT)') < md.indexOf('Germany (DE)'));
    const india = md.slice(md.indexOf('India (IN)'));
    assert.ok(india.indexOf('Aadhaar QR') < india.indexOf('Passport (chip)'));
    assert.ok(india.indexOf('Passport (chip)') < india.indexOf('DigiLocker login'));
    assert.match(md, /\| India \(IN\) \| Aadhaar QR \| Aadhaar letter, e-Aadhaar PDF \| Zero-knowledge proof[^|]*\| Android phone, Windows PC \| camera \|/);
    assert.match(md, /\|\s+\| Passport \(chip\) \| Indian e-passport \| Checked on your phone[^|]*\| Android phone \| NFC \(tap the ID on the phone\) \|/);
    assert.ok(md.includes('Website (browser)'));
    assert.ok(md.includes('| Austria (AT) | no ways listed in the catalog |'));
  });

  it('escapes "|" so a label cannot break the table', () => {
    const md = renderCountryTables(sample());
    assert.ok(md.includes('EU wallet \\| mDL'));
    for (const line of md.split('\n').filter((l) => l.startsWith('| ') && !l.startsWith('| Country'))) {
      assert.equal(line.replace(/\\\|/g, '').split('|').length, 8, line);
    }
  });

  it('refuses a catalog that does not follow PROTOCOL.md 4d.2, listing every problem', () => {
    const bad = sample();
    bad.version = 2;
    bad.countries[0].methods[0].privacy = 'secret';
    bad.countries[1].code = 'IN';
    bad.countries[2].methods = 'none';
    try {
      validateCatalog(bad);
      assert.fail('should have thrown');
    } catch (e) {
      assert.ok(e instanceof CatalogError);
      for (const text of ['version must be 1', 'privacy must be one of', 'listed twice', 'methods must be a list']) assert.ok(e.message.includes(text), text);
    }
    assert.throws(() => validateCatalog(null), CatalogError);
  });

  it('replaces only the text between the markers, and adds them if missing', () => {
    const doc = `# Guide\n\nBefore\n\n${START}\n\nold table\n\n${END}\n\nAfter\n`;
    const out = replaceBetweenMarkers(doc, 'new table');
    assert.equal(out, `# Guide\n\nBefore\n\n${START}\n\nnew table\n\n${END}\n\nAfter\n`);
    assert.equal(replaceBetweenMarkers(out, 'new table'), out, 'running twice changes nothing');
    assert.ok(replaceBetweenMarkers('# Guide\n', 'x').endsWith(`${START}\n\nx\n\n${END}\n`));
  });
});
