import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, it } from 'node:test';
import { b64urlDecode, b64urlEncode, isB64url } from '../src/shared/b64url.js';
import { algForJwk, devicePublicKeyBody, jwkThumbprint, spkiToJwk, verifyDeviceSignature, type RsaJwk } from '../src/shared/jwk.js';
import { cardDeleteString, cardIssueString, linkApproveString, signingBytes, ticketRequestString } from '../src/shared/signing.js';

describe('signing strings (PROTOCOL 3.4)', () => {
  it('issue card', () => {
    assert.equal(cardIssueString('c'.repeat(64), 'thumb'), `v18-card-issue\n${'c'.repeat(64)}\nthumb`);
  });
  it('request ticket', () => {
    assert.equal(ticketRequestString('card_x', 'ch', 'v18-age18-20261109', 'blind'), 'v18-ticket-request\ncard_x\nch\nv18-age18-20261109\nblind');
  });
  it('approve device link', () => {
    assert.equal(linkApproveString('card_x', 'ch', 'lnk'), 'v18-link-approve\ncard_x\nch\nlnk');
  });
  it('delete card', () => {
    assert.equal(cardDeleteString('card_x', 'ch'), 'v18-card-delete\ncard_x\nch');
  });
  it('has no trailing newline and signs UTF-8 bytes', () => {
    const s = cardDeleteString('card_x', 'ch');
    assert.ok(!s.endsWith('\n'));
    assert.deepEqual([...signingBytes(s)], [...Buffer.from(s, 'utf8')]);
  });
  it('refuses empty fields and line breaks inside fields', () => {
    assert.throws(() => cardDeleteString('', 'ch'));
    assert.throws(() => cardDeleteString('card_x\nextra', 'ch'));
    assert.throws(() => ticketRequestString('card_x', 'ch\r', 'k', 'b'));
  });
});

describe('base64url', () => {
  it('round-trips without padding', () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0x00, 0x01]);
    const s = b64urlEncode(bytes);
    assert.equal(s, '-_8AAQ');
    assert.deepEqual([...b64urlDecode(s)], [...bytes]);
  });
  it('rejects padding and standard base64 letters', () => {
    assert.throws(() => b64urlDecode('-_8AAQ=='));
    assert.throws(() => b64urlDecode('+/8AAQ'));
    assert.equal(isB64url('abc d'), false);
  });
});

describe('JWK thumbprint (RFC 7638)', () => {
  it('matches the RFC 7638 section 3.1 example', () => {
    const jwk: RsaJwk = {
      kty: 'RSA',
      e: 'AQAB',
      n:
        '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs' +
        'tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5h' +
        'ajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
    };
    assert.equal(jwkThumbprint(jwk), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });
  it('ignores alg and other members', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = spkiToJwk(publicKey.export({ format: 'der', type: 'spki' }));
    assert.equal(jwkThumbprint({ ...jwk, alg: 'ES256' } as never), jwkThumbprint(jwk));
  });
});

describe('device keys', () => {
  it('reads an RSA-2048 SPKI (what Windows Hello returns) as an RS256 JWK', () => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = spkiToJwk(publicKey.export({ format: 'der', type: 'spki' }));
    assert.equal(jwk.kty, 'RSA');
    assert.equal(algForJwk(jwk), 'RS256');
    assert.deepEqual(Object.keys(devicePublicKeyBody(jwk)).sort(), ['alg', 'e', 'kty', 'n']);
    const data = signingBytes(cardIssueString('a'.repeat(64), jwkThumbprint(jwk)));
    const sig = sign('sha256', data, privateKey); // RSASSA-PKCS1-v1_5 SHA-256, like KeyCredential.RequestSignAsync
    assert.ok(verifyDeviceSignature(jwk, data, sig));
    assert.ok(!verifyDeviceSignature(jwk, signingBytes('other'), sig));
  });
  it('refuses RSA keys that are not 2048 bits', () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
    assert.throws(() => spkiToJwk(publicKey.export({ format: 'der', type: 'spki' })), /RSA-1024/);
  });
  it('checks ES256 signatures in raw and DER form', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = spkiToJwk(publicKey.export({ format: 'der', type: 'spki' }));
    assert.equal(algForJwk(jwk), 'ES256');
    const data = signingBytes('v18-card-delete\ncard_x\nch');
    assert.ok(verifyDeviceSignature(jwk, data, sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })));
    assert.ok(verifyDeviceSignature(jwk, data, sign('sha256', data, privateKey)));
  });
});
