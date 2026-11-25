// The real product end to end: phone or PC, V18 server and website, with real cryptography and the
// real website verify libraries (Node and Python). The server runs in dev mode only so that a test
// identity (test_dev) can stand in for an ID document; everything after the card is the real path.
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { V18Verifier } from '@v18/verify';
import {
  api,
  challenge,
  makeDevice,
  ok,
  requestTestCard,
  requestTicket,
  siteChallenge,
  startServer,
  testCard,
  verifyWithPython,
} from '../helpers.mjs';

const SHOP = 'https://wine-shop.example';

describe('V18 user journeys', () => {
  let server;
  let website;
  before(async () => {
    server = await startServer({ dev: true });
    website = new V18Verifier({ serverUrl: server.base, origin: SHOP });
  });
  after(async () => {
    await server?.stop();
  });

  it('adult with a phone: age card, one-time ticket, the website lets them in once', async () => {
    const phone = await makeDevice();
    const card = await testCard(server.base, phone);
    assert.equal(card.minAgeCertified, 18);

    const visit = siteChallenge();
    const { ticket } = await requestTicket(server.base, card, phone, { origin: SHOP, challenge: visit });
    const first = await website.verifyTicket(ticket, { expectedChallenge: visit });
    assert.equal(first.valid, true, JSON.stringify(first));
    assert.equal(first.ticket.minAge, 18);

    const replay = await website.verifyTicket(ticket, { expectedChallenge: visit });
    assert.equal(replay.valid, false);
    assert.equal(replay.code, 'REPLAY_DETECTED');
  });

  it('a ticket is useless on another website, for another visit, or for a 21+ site', async () => {
    const phone = await makeDevice();
    const card = await testCard(server.base, phone);
    const visit = siteChallenge();
    const { ticket } = await requestTicket(server.base, card, phone, { origin: SHOP, challenge: visit });

    const otherSite = new V18Verifier({ serverUrl: server.base, origin: 'https://other-shop.example' });
    assert.equal((await otherSite.verifyTicket(ticket, { expectedChallenge: visit })).code, 'ORIGIN_MISMATCH');
    assert.equal((await website.verifyTicket(ticket, { expectedChallenge: siteChallenge() })).code, 'CHALLENGE_MISMATCH');
    const over21 = await website.verifyTicket(ticket, { expectedChallenge: visit, minAge: 21 });
    assert.equal(over21.valid, false);
  });

  it('a changed ticket is refused', async () => {
    const phone = await makeDevice();
    const card = await testCard(server.base, phone);
    const visit = siteChallenge();
    const { ticket } = await requestTicket(server.base, card, phone, { origin: SHOP, challenge: visit });
    const [kid, msg, sig] = ticket.split('.');
    const bytes = Buffer.from(sig, 'base64url');
    bytes[10] ^= 0xff;
    const forged = `${kid}.${msg}.${bytes.toString('base64url')}`;
    const r = await website.verifyTicket(forged, { expectedChallenge: visit });
    assert.equal(r.valid, false);
    assert.equal(r.code, 'INVALID_SIGNATURE');
  });

  it('the Python website library accepts the same kind of ticket once', async () => {
    const phone = await makeDevice();
    const card = await testCard(server.base, phone);
    const visit = siteChallenge();
    const { ticket } = await requestTicket(server.base, card, phone, { origin: SHOP, challenge: visit });
    const args = { base: server.base, origin: SHOP, challenge: visit };
    assert.deepEqual(verifyWithPython(ticket, args).valid, true);
  });

  it('someone under 18 gets no age card', async () => {
    const phone = await makeDevice();
    const year = new Date().getFullYear() - 15;
    const r = await requestTestCard(server.base, phone, `${year}-06-01`);
    assert.equal(r.status, 403);
    assert.equal(r.data.code, 'UNDER_AGE');
  });

  it('QR hand-off: the website shows a QR, the phone approves, the website gets the ticket once', async () => {
    const visit = siteChallenge();
    const session = await ok(server.base, 'POST', '/pairing/session', { origin: SHOP, challenge: visit, minAge: 18 }, { Origin: SHOP });
    assert.match(session.deepLink, /^v18:\/\/verify\?/);

    const phone = await makeDevice();
    const card = await testCard(server.base, phone);
    await ok(server.base, 'POST', `/pairing/${session.sessionId}/connect`);
    const { ticket } = await requestTicket(server.base, card, phone, { origin: SHOP, challenge: visit });
    await ok(server.base, 'POST', `/pairing/${session.sessionId}/submit`, { ticket });

    const poll = await ok(server.base, 'GET', `/pairing/${session.sessionId}`);
    assert.equal(poll.status, 'approved');
    assert.equal(poll.ticket, ticket);
    const again = await ok(server.base, 'GET', `/pairing/${session.sessionId}`);
    assert.equal(again.ticket ?? null, null, 'the ticket must be handed out only once');
    assert.equal((await website.verifyTicket(poll.ticket, { expectedChallenge: visit })).valid, true);

    const second = await api(server.base, 'POST', `/pairing/${session.sessionId}/submit`, { ticket });
    assert.equal(second.status, 409);
  });

  it('device link: the PC (Windows Hello style key) gets its own card from the phone', async () => {
    const phone = await makeDevice();
    const phoneCard = await testCard(server.base, phone);
    const pc = await makeDevice({ rsa: true });

    const c1 = await challenge(server.base);
    const link = await ok(server.base, 'POST', '/card/link/start', {
      devicePublicKey: pc.jwk,
      challenge: c1,
      deviceSignature: pc.sign(`v18-card-issue\n${c1}\n${pc.thumbprint}`),
    });
    assert.equal((await ok(server.base, 'GET', `/card/link/${link.linkId}`)).status, 'waiting');

    const c2 = await challenge(server.base);
    await ok(server.base, 'POST', `/card/link/${link.linkId}/approve`, {
      cardId: phoneCard.cardId,
      challenge: c2,
      deviceSignature: phone.sign(`v18-link-approve\n${phoneCard.cardId}\n${c2}\n${link.linkId}`),
    });
    const done = await ok(server.base, 'GET', `/card/link/${link.linkId}`);
    assert.equal(done.status, 'approved');
    const pcCard = done.card;
    assert.ok(pcCard?.cardId && pcCard.cardId !== phoneCard.cardId);

    const visit = siteChallenge();
    const { ticket } = await requestTicket(server.base, pcCard, pc, { origin: SHOP, challenge: visit });
    assert.equal((await website.verifyTicket(ticket, { expectedChallenge: visit })).valid, true);
  });

  it('another device cannot use someone else\'s card', async () => {
    const phone = await makeDevice();
    const card = await testCard(server.base, phone);
    const thief = await makeDevice();
    const r = await requestTicket(server.base, card, thief, { origin: SHOP, challenge: siteChallenge() });
    assert.equal(r.status, 401);
    assert.equal(r.data.code, 'CARD_REQUIRED');
  });

  it('after the user deletes the card, it can never make another ticket', async () => {
    const phone = await makeDevice();
    const card = await testCard(server.base, phone);
    const c = await challenge(server.base);
    const del = await api(server.base, 'DELETE', `/card/${card.cardId}`, {
      challenge: c,
      deviceSignature: phone.sign(`v18-card-delete\n${card.cardId}\n${c}`),
    });
    assert.equal(del.status, 200);
    assert.equal((await ok(server.base, 'GET', `/card/${card.cardId}/status`)).status, 'revoked');
    const r = await requestTicket(server.base, card, phone, { origin: SHOP, challenge: siteChallenge() });
    assert.equal(r.status, 401);
  });

  it('stores nothing that identifies the person', async () => {
    const phone = await makeDevice();
    const name = `Person-${crypto.randomBytes(4).toString('hex')}`;
    const c = await challenge(server.base);
    await api(server.base, 'POST', '/card/issue', {
      method: 'test_dev',
      challenge: c,
      devicePublicKey: phone.jwk,
      deviceSignature: phone.sign(`v18-card-issue\n${c}\n${phone.thumbprint}`),
      proof: { testSubjectId: name, birthDate: '1985-03-14' },
    });
    const { default: fs } = await import('node:fs');
    const { default: path } = await import('node:path');
    const files = fs.readdirSync(server.dataDir, { recursive: true }).map((f) => path.join(server.dataDir, f));
    for (const f of files) {
      if (!fs.statSync(f).isFile()) continue;
      const bytes = fs.readFileSync(f).toString('latin1');
      assert.ok(!bytes.includes(name), `the test person's ID appears in ${f}`);
      assert.ok(!bytes.includes('1985-03-14'), `the birth date appears in ${f}`);
    }
  });
});
