import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import {
  api,
  FakeClock,
  getJwks,
  issueTestCard,
  makeTicket,
  referenceVerifyTicket,
  startServer,
  TestDevice,
} from './helpers.js';

describe('End to end', () => {
  it('website -> QR session -> phone card + ticket -> widget poll -> website check', async () => {
    const srv = await startServer();
    try {
      // The website makes its own challenge for this visit.
      const site = { origin: 'http://localhost:3000', challenge: crypto.randomBytes(16).toString('hex') };

      // The widget (in the browser) opens a QR session.
      const session = await api(
        srv.url,
        'POST',
        '/v1/pairing/session',
        { origin: site.origin, challenge: site.challenge, minAge: 18, ttlSeconds: 120 },
        { Origin: site.origin }
      );
      assert.equal(session.status, 201);

      // The phone scans the QR and reads the deep link.
      const link = new URL(session.body.deepLink.replace('v18://', 'https://v18.invalid/'));
      assert.equal(link.searchParams.get('server'), 'http://localhost:8080');
      const sessionId = link.searchParams.get('session')!;
      assert.equal((await api(srv.url, 'POST', `/v1/pairing/${sessionId}/connect`)).status, 200);

      // The phone already holds an age card; it makes a ticket for this site.
      const phone = await TestDevice.es256();
      const card = (await issueTestCard(srv.url, phone)).body;
      const ticket = await makeTicket(srv, card.cardId, phone, {
        origin: link.searchParams.get('origin')!,
        challenge: link.searchParams.get('challenge')!,
      });
      assert.equal((await api(srv.url, 'POST', `/v1/pairing/${sessionId}/submit`, { ticket })).status, 200);

      // The widget polls and gets the ticket once.
      const poll = await api(srv.url, 'GET', `/v1/pairing/${sessionId}`, undefined, { Origin: site.origin });
      assert.equal(poll.body.status, 'approved');
      assert.equal(poll.body.ticket, ticket);

      // The website's SERVER checks the ticket offline with the JWKS.
      const jwks = await getJwks(srv.url);
      const nowSec = Math.floor(srv.clock.now() / 1000);
      const seen = new Set<string>();
      const result = referenceVerifyTicket(poll.body.ticket, jwks, { ...site, minAge: 18 }, nowSec, seen);
      assert.equal(result.ok, true, JSON.stringify(result));
      // Tickets run out after 5 minutes (+60 s leeway).
      const late = referenceVerifyTicket(ticket, jwks, { ...site, minAge: 18 }, nowSec + 361, new Set());
      assert.equal((late as any).rule, 7);
    } finally {
      await srv.close();
    }
  });

  it('npm run dev-client prints a ticket that passes the website checks', { timeout: 60_000 }, async () => {
    // Real time here: the script uses the real clock to pick the current key.
    const srv = await startServer({ clock: new FakeClock(Date.now()) });
    try {
      const serverRoot = path.resolve(__dirname, '..', '..');
      const tsxCli = path.join(serverRoot, 'node_modules', 'tsx', 'dist', 'cli.mjs');
      const script = path.join(serverRoot, 'scripts', 'dev-client.ts');
      const challenge = 'dev-client-test-challenge';
      const out = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
        const child = spawn(
          process.execPath,
          [tsxCli, script, '--server', `${srv.url}/v1`, '--origin', 'https://site.test', '--challenge', challenge, '--quiet'],
          { cwd: serverRoot }
        );
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (d) => (stdout += d));
        child.stderr.on('data', (d) => (stderr += d));
        child.on('close', (code) => resolve({ code, stdout, stderr }));
      });
      assert.equal(out.code, 0, out.stderr);
      const ticket = out.stdout.trim();
      assert.match(ticket, /^v18-age18-\d{8}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
      const r = referenceVerifyTicket(
        ticket,
        await getJwks(srv.url),
        { origin: 'https://site.test', challenge, minAge: 18 },
        Math.floor(Date.now() / 1000),
        new Set()
      );
      assert.equal(r.ok, true, JSON.stringify(r));
    } finally {
      await srv.close();
    }
  });
});
