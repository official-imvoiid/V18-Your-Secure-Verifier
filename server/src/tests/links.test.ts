import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { api, issueTestCard, makeTicket, newChallenge, ss, startServer, TestDevice, TestServer } from './helpers.js';

/** The PC starts a link with its new device key. */
async function startLink(srv: TestServer, pc: TestDevice) {
  const challenge = await newChallenge(srv.url);
  return api(srv.url, 'POST', '/v1/card/link/start', {
    devicePublicKey: pc.jwkWithAlg,
    challenge,
    deviceSignature: pc.sign(ss.cardIssue(challenge, pc.thumbprint)),
  });
}

/** The phone approves with its own card. */
async function approve(srv: TestServer, linkId: string, cardId: string, phone: TestDevice) {
  const challenge = await newChallenge(srv.url);
  return api(srv.url, 'POST', `/v1/card/link/${linkId}/approve`, {
    cardId,
    challenge,
    deviceSignature: phone.sign(ss.linkApprove(cardId, challenge, linkId)),
  });
}

describe('Device link (protocol 3.9)', () => {
  it('copies a card to the PC: new key, same nullifier, no later end date, card returned once', async () => {
    const srv = await startServer();
    try {
      const phone = await TestDevice.es256();
      const phoneCard = (await issueTestCard(srv.url, phone)).body;
      const pc = await TestDevice.rs256(); // Windows Hello style key

      const start = await startLink(srv, pc);
      assert.equal(start.status, 201, JSON.stringify(start.body));
      assert.match(start.body.linkId, /^link_[A-Za-z0-9_-]{22}$/);
      assert.equal(start.body.deepLink, `v18://link?id=${start.body.linkId}&server=http%3A%2F%2Flocalhost%3A8080`);
      assert.equal(start.body.expiresIn, 120);

      assert.equal((await api(srv.url, 'GET', `/v1/card/link/${start.body.linkId}`)).body.status, 'waiting');

      srv.clock.advance(60_000);
      const ok = await approve(srv, start.body.linkId, phoneCard.cardId, phone);
      assert.equal(ok.status, 200, JSON.stringify(ok.body));
      assert.equal(ok.body.status, 'approved');

      const poll1 = await api(srv.url, 'GET', `/v1/card/link/${start.body.linkId}`);
      assert.equal(poll1.body.status, 'approved');
      const pcCard = poll1.body.card;
      assert.ok(pcCard.cardId && pcCard.cardId !== phoneCard.cardId);
      assert.equal(pcCard.method, 'test_dev');
      assert.equal(pcCard.minAgeCertified, 18);
      assert.equal(pcCard.validUntil, phoneCard.validUntil, 'ends when the phone card ends');

      const poll2 = await api(srv.url, 'GET', `/v1/card/link/${start.body.linkId}`);
      assert.equal(poll2.body.status, 'approved');
      assert.equal(poll2.body.card, undefined, 'the card is returned once');

      // Same nullifier as the phone card.
      const rows = await srv.services.db.all<{ nullifier_hash: string }>('SELECT nullifier_hash FROM cards WHERE card_id IN (?, ?)', [
        phoneCard.cardId,
        pcCard.cardId,
      ]);
      assert.equal(rows.length, 2);
      assert.equal(rows[0].nullifier_hash, rows[1].nullifier_hash);

      // The PC card works with the PC key, not with the phone key.
      assert.ok(await makeTicket(srv, pcCard.cardId, pc, { origin: 'https://site.test', challenge: 'x' }));
      await assert.rejects(makeTicket(srv, pcCard.cardId, phone, { origin: 'https://site.test', challenge: 'x' }), /401/);
    } finally {
      await srv.close();
    }
  });

  it('works once: a second approval gets 409 LINK_USED', async () => {
    const srv = await startServer();
    try {
      const phone = await TestDevice.es256();
      const card = (await issueTestCard(srv.url, phone)).body;
      const link = (await startLink(srv, await TestDevice.es256())).body;
      assert.equal((await approve(srv, link.linkId, card.cardId, phone)).status, 200);
      const again = await approve(srv, link.linkId, card.cardId, phone);
      assert.equal(again.status, 409);
      assert.equal(again.body.code, 'LINK_USED');
    } finally {
      await srv.close();
    }
  });

  it('lasts 120 seconds: then poll says "expired" and approval gets 410 LINK_EXPIRED', async () => {
    const srv = await startServer();
    try {
      const phone = await TestDevice.es256();
      const card = (await issueTestCard(srv.url, phone)).body;
      const link = (await startLink(srv, await TestDevice.es256())).body;
      srv.clock.advance(121_000);
      assert.equal((await api(srv.url, 'GET', `/v1/card/link/${link.linkId}`)).body.status, 'expired');
      const r = await approve(srv, link.linkId, card.cardId, phone);
      assert.equal(r.status, 410);
      assert.equal(r.body.code, 'LINK_EXPIRED');
    } finally {
      await srv.close();
    }
  });

  it('the linked card counts toward the nullifier cap', async () => {
    const srv = await startServer({ config: { maxCardsPerId: 2 } });
    try {
      const phone = await TestDevice.es256();
      const card = (await issueTestCard(srv.url, phone)).body;
      const l1 = (await startLink(srv, await TestDevice.es256())).body;
      assert.equal((await approve(srv, l1.linkId, card.cardId, phone)).status, 200);
      const l2 = (await startLink(srv, await TestDevice.es256())).body;
      const r = await approve(srv, l2.linkId, card.cardId, phone);
      assert.equal(r.status, 409);
      assert.equal(r.body.code, 'NULLIFIER_OVERUSED');
      assert.equal((await api(srv.url, 'GET', `/v1/card/link/${l2.linkId}`)).body.status, 'waiting');
    } finally {
      await srv.close();
    }
  });

  it('refuses a bad phone signature (401 CARD_REQUIRED) and a bad PC proof of possession (401)', async () => {
    const srv = await startServer();
    try {
      const phone = await TestDevice.es256();
      const card = (await issueTestCard(srv.url, phone)).body;
      const link = (await startLink(srv, await TestDevice.es256())).body;
      const r = await approve(srv, link.linkId, card.cardId, await TestDevice.es256());
      assert.equal(r.status, 401);
      assert.equal(r.body.code, 'CARD_REQUIRED');
      assert.equal((await api(srv.url, 'GET', `/v1/card/link/${link.linkId}`)).body.status, 'waiting');

      const pc = await TestDevice.es256();
      const challenge = await newChallenge(srv.url);
      const bad = await api(srv.url, 'POST', '/v1/card/link/start', {
        devicePublicKey: pc.jwkWithAlg,
        challenge,
        deviceSignature: phone.sign(ss.cardIssue(challenge, pc.thumbprint)),
      });
      assert.equal(bad.status, 401);
      assert.equal(bad.body.code, 'BAD_DEVICE_SIGNATURE');
    } finally {
      await srv.close();
    }
  });

  it('unknown links answer 404 LINK_NOT_FOUND', async () => {
    const srv = await startServer();
    try {
      const r = await api(srv.url, 'GET', '/v1/card/link/link_AAAAAAAAAAAAAAAAAAAAAA');
      assert.equal(r.status, 404);
      assert.equal(r.body.code, 'LINK_NOT_FOUND');
    } finally {
      await srv.close();
    }
  });
});
