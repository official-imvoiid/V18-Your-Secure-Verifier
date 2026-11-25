// End-to-end with the REAL Electron app (dist/, run "npm run build" first) and the REAL server
// (npm run dev --prefix server). Uses the TEST key flag, because this PC has no Windows Hello,
// a separate profile folder, and --v18-no-protocol. The site request arrives the way a browser
// sends it: a second launch of the app with the v18://verify link.

import electronPath from 'electron';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { _electron as electron } from 'playwright-core';
import { V18Api } from '../../src/shared/api.js';
import { verifyTicketString } from '../../src/shared/ticket.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BASE = 'http://localhost:8080/v1';
const SITE = 'http://localhost:3000';
const api = new V18Api(BASE);

let skip: string | false = false;
try {
  if (!(await api.health()).devMode) skip = 'the server on :8080 is not in dev mode';
} catch {
  skip = 'no V18 server on http://localhost:8080 (start it with "npm run dev --prefix server")';
}

describe('Real Electron app + real server', { skip }, () => {
  it('TEST card, then a site asks through a v18:// link, and the ticket verifies', async () => {
    const profile = mkdtempSync(path.join(tmpdir(), 'v18-e2e-'));
    const args = [root, '--v18-no-protocol', `--v18-profile=${profile}`, '--v18-test-software-key'];
    const app = await electron.launch({ executablePath: electronPath as unknown as string, args, cwd: root });
    try {
      const page = await app.firstWindow();
      await page.click('button:has-text("Continue")');
      await page.waitForSelector('text=TEST MODE.');
      await page.click('nav >> text=Get age card');
      await page.waitForSelector('text=Where is your ID from?');
      // With the server's catalog: pick a country. Without it: the TEST card button is still there.
      await page.waitForFunction(() => !document.body.innerText.includes('Getting the list of IDs'), undefined, { timeout: 15000 });
      if (await page.isVisible('button.cbtn:has-text("India")')) {
        await page.click('button.cbtn:has-text("India")');
        await page.click('button:has-text("Continue")');
      }
      await page.click('button:has-text("TEST card")');
      await page.click('button:has-text("Make TEST card")');
      await page.waitForSelector('text=Your age card is saved', { timeout: 20000 });
      const view: any = await page.evaluate(() => (window as any).v18.invoke('v18:get-view'));
      assert.equal(view.serverUrl, BASE);
      assert.equal(view.card.method, 'test_dev');
      // The card ID is only in the app's state file (the window never gets it).
      const cardId = JSON.parse(readFileSync(path.join(profile, 'v18-state.json'), 'utf8')).card.cardId as string;
      assert.equal((await api.cardStatus(cardId)).status, 'active');

      const challenge = 'app-e2e-' + Date.now();
      const res = await fetch(`${BASE}/pairing/session`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: SITE },
        body: JSON.stringify({ origin: SITE, challenge, minAge: 18, ttlSeconds: 120 }),
      });
      const session = (await res.json()) as { sessionId: string; deepLink: string };
      const askWindow = app.waitForEvent('window');
      spawn(electronPath as unknown as string, [...args, session.deepLink], { cwd: root, stdio: 'ignore' });
      const ask = await askWindow;
      await ask.waitForSelector('text=Are you 18+?', { timeout: 20000 });
      await ask.click('button:has-text("Send 18+ ticket")');
      await ask.waitForSelector('text=Ticket sent', { timeout: 20000 });

      const poll = (await (await fetch(`${BASE}/pairing/${session.sessionId}`)).json()) as { status: string; ticket: string };
      assert.equal(poll.status, 'approved');
      const key = (await api.keys()).find((k) => k.kid === poll.ticket.split('.')[0])!;
      const v = await verifyTicketString(poll.ticket, key);
      assert.equal(v.ok, true);
      assert.equal(v.payload?.origin, SITE);
      assert.equal(v.payload?.challenge, challenge);

      // Clean up: delete the TEST card through the app (signed DELETE).
      await page.click('nav >> text=Settings');
      await page.click('button:has-text("Delete age card")');
      await page.click('.dlg button:has-text("Delete")');
      await page.waitForSelector("text=You don't have an age card yet", { timeout: 20000 });
      assert.equal((await api.cardStatus(cardId)).status, 'revoked');
    } finally {
      await app.evaluate(({ app: a }) => a.exit(0)).catch(() => undefined);
      await app.close().catch(() => undefined);
      await new Promise((r) => setTimeout(r, 1000));
      try {
        rmSync(profile, { recursive: true, force: true });
      } catch {
        /* Chromium may still hold a file for a moment */
      }
    }
  });
});
