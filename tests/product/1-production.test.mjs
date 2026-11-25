// The real product in PRODUCTION mode: what a live V18 server must refuse and protect.
// Nothing here uses test identities; the server runs exactly as it would when deployed.
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { api, makeDevice, siteChallenge, startServer } from '../helpers.mjs';

describe('V18 server in production mode', () => {
  let server;
  before(async () => {
    server = await startServer({ dev: false });
  });
  after(async () => {
    await server?.stop();
  });

  it('starts in production mode and turns test identities off', async () => {
    const { status, data } = await api(server.base, 'GET', '/health');
    assert.equal(status, 200);
    assert.equal(data.devMode, false, 'a deployed server must not be in TEST MODE');
    assert.notEqual(data.methods.test_dev, 'ready', 'test_dev must not be available in production');
  });

  it('refuses a test_dev age card', async () => {
    const device = await makeDevice();
    const c = (await api(server.base, 'POST', '/challenge')).data.challenge;
    const r = await api(server.base, 'POST', '/card/issue', {
      method: 'test_dev',
      challenge: c,
      devicePublicKey: device.jwk,
      deviceSignature: device.sign(`v18-card-issue\n${c}\n${device.thumbprint}`),
      proof: { testSubjectId: 'someone', birthDate: '1990-01-01' },
    });
    assert.equal(r.status, 501);
    assert.equal(r.data.code, 'METHOD_DISABLED');
  });

  it('never signs a ticket without an age card and its device signature', async () => {
    const r = await api(server.base, 'POST', '/ticket/blind-sign', { blindedMessage: 'AAAA' });
    assert.equal(r.status, 401);
    assert.equal(r.data.code, 'CARD_REQUIRED');
  });

  it('refuses a ticket request for a card that does not exist', async () => {
    const device = await makeDevice();
    const c = (await api(server.base, 'POST', '/challenge')).data.challenge;
    const r = await api(server.base, 'POST', '/ticket/blind-sign', {
      cardId: 'card_doesNotExist0000000',
      challenge: c,
      keyId: 'v18-age18-20260101',
      blindedMessage: 'AAAA',
      deviceSignature: device.sign('anything'),
    });
    assert.equal(r.status, 401);
    assert.equal(r.data.code, 'CARD_REQUIRED');
  });

  it('a challenge works only once', async () => {
    const device = await makeDevice();
    const c = (await api(server.base, 'POST', '/challenge')).data.challenge;
    const body = {
      method: 'anon_aadhaar',
      challenge: c,
      devicePublicKey: device.jwk,
      deviceSignature: device.sign(`v18-card-issue\n${c}\n${device.thumbprint}`),
      proof: {},
    };
    await api(server.base, 'POST', '/card/issue', body);
    const again = await api(server.base, 'POST', '/card/issue', body);
    assert.equal(again.status, 401);
    assert.equal(again.data.code, 'CHALLENGE_INVALID');
  });

  it('sends security headers and hides the server software', async () => {
    const { headers } = await api(server.base, 'GET', '/health');
    assert.equal(headers.get('x-content-type-options'), 'nosniff');
    assert.equal(headers.get('x-powered-by'), null);
  });

  it('lets any website use the widget endpoints, but not the app endpoints', async () => {
    const origin = 'https://any-shop.example';
    const widget = await api(server.base, 'GET', '/health', undefined, { Origin: origin });
    assert.equal(widget.headers.get('access-control-allow-origin'), origin);
    const app = await api(server.base, 'POST', '/card/issue', {}, { Origin: origin });
    assert.equal(app.headers.get('access-control-allow-origin'), null);
  });

  it('a website can only start a QR hand-off for itself', async () => {
    const r = await api(
      server.base,
      'POST',
      '/pairing/session',
      { origin: 'https://real-shop.example', challenge: siteChallenge(), minAge: 18 },
      { Origin: 'https://evil.example' }
    );
    assert.ok(r.status >= 400 && r.status < 500, `expected a refusal, got ${r.status}`);
    assert.equal(r.data.code, 'ORIGIN_MISMATCH');
  });

  it('publishes only public keys, and keeps signing keys out of plain files', async () => {
    const { data } = await api(server.base, 'GET', '/keys');
    assert.ok(data.keys.length > 0);
    for (const k of data.keys) {
      assert.equal(k.d, undefined, 'a private key part was published');
      assert.equal(k.p, undefined);
    }
    const keyDir = path.join(server.dataDir, 'keys');
    const plainKeyFiles = fs.existsSync(keyDir) ? fs.readdirSync(keyDir) : [];
    assert.deepEqual(plainKeyFiles, [], 'production must keep keys encrypted in the database, not in files');
  });

  it('does not log what people send', async () => {
    const marker = `PRIVATE-${Date.now()}`;
    await api(server.base, 'POST', '/card/issue', { method: 'anon_aadhaar', proof: { name: marker, birthDate: marker } });
    await api(server.base, 'POST', '/pairing/session', { origin: 'https://shop.example', challenge: marker });
    assert.ok(!server.log().includes(marker), 'request contents appeared in the server log');
  });
});
