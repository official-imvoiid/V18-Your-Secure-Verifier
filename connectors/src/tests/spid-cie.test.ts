/**
 * SPID and CIE (SAML 2.0) against local SAML identity provider mocks in the SPID/CIE format.
 */
import assert from 'node:assert/strict';
import { before, describe, test } from 'node:test';
import { DOMParser } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { parseIdpMetadata } from '../saml.js';
import { createConnector } from '../registry.js';
import type { Connector, ConnectorId, Env } from '../types.js';
import { newStart, randomToken } from './helpers/browser.js';
import { assertConnectorError, assertOnlyAgeAndSubject } from './helpers/checks.js';
import { birthDateForAge, selfSignedRsa, type CertAndKey } from './helpers/keys.js';
import { createSamlIdp, type SamlIdp } from './helpers/saml-idp.js';

const minor = birthDateForAge(17);

function samlSuite(id: ConnectorId, idpEntityIds: string[], requestedLevel: string, responseLevel: string, extraAttrs: Record<string, string>) {
  describe(`${id} (local SAML IdP mock)`, () => {
    const REDIRECT = `https://api.v18.test/v1/connect/${id}/callback`;
    const SP_ENTITY = 'https://api.v18.test/saml/sp';
    let sp: CertAndKey;
    let idps: SamlIdp[];
    let env: Env;
    let c: Connector;
    const P = id.toUpperCase();

    before(async () => {
      sp = await selfSignedRsa('V18 TEST SP');
      idps = await Promise.all(idpEntityIds.map((e, i) => createSamlIdp(e, `Test IdP ${i + 1}`)));
      env = {
        [`V18_CONNECTOR_${P}_ENTITY_ID`]: SP_ENTITY,
        [`V18_CONNECTOR_${P}_PRIVATE_KEY`]: sp.keyPem,
        [`V18_CONNECTOR_${P}_CERT`]: sp.certPem,
        [`V18_CONNECTOR_${P}_IDP_METADATA`]: idps.map((i) => i.metadataXml).join('\n'),
      };
      c = createConnector(id, env);
    });

    async function start(idp: SamlIdp) {
      const s = newStart(REDIRECT);
      const { authUrl, session } = await c.buildAuthUrl({ ...s, idp: idp.entityId });
      const req = idp.readRequest(authUrl, sp.certPem);
      return { s, session, req };
    }
    const person = (dob?: string) => ({
      ...(dob ? { dateOfBirth: dob } : {}),
      fiscalNumber: 'TINIT-RSSMRA80A01H501U',
      name: 'Mario',
      familyName: 'Rossi',
      ...extraAttrs,
    });
    async function callback(idp: SamlIdp, attrs: Record<string, string>, tweak: Partial<Parameters<SamlIdp['response']>[0]> = {}) {
      const { s, session, req } = await start(idp);
      const SAMLResponse = idp.response({ inResponseTo: req.id, acsUrl: req.acsUrl, audience: SP_ENTITY, attributes: attrs, level: responseLevel, ...tweak });
      return { ...s, session, params: { SAMLResponse, RelayState: req.relayState } };
    }

    test('is configured only with entity ID, key, certificate and IdP metadata; callback is POST', () => {
      assert.equal(c.isConfigured(env), true);
      assert.equal(c.isConfigured({ [`V18_CONNECTOR_${P}_ENTITY_ID`]: SP_ENTITY }), false);
      assert.equal(c.callbackMethod, 'POST');
      assert.deepEqual(c.identityProviders!().map((i) => i.entityId), idpEntityIds);
    });

    test('AuthnRequest follows the rules: signed, Issuer NameQualifier, requested level, our ACS URL', async () => {
      const { s, req } = await start(idps[0]);
      assert.equal(req.issuer, SP_ENTITY);
      assert.equal(req.nameQualifier, SP_ENTITY);
      assert.equal(req.level, requestedLevel);
      assert.equal(req.acsUrl, REDIRECT);
      assert.equal(req.relayState, s.state);
    });

    test('over 18: only over18 and the fiscal number come back (name, surname dropped)', async () => {
      const cb = await callback(idps[0], person('1980-01-01'));
      assertOnlyAgeAndSubject(await c.handleCallback(cb), { over18: true, subject: 'TINIT-RSSMRA80A01H501U' });
    });

    test('under 18: over18 false', async () => {
      const cb = await callback(idps[0], person(minor.iso));
      assert.equal((await c.handleCallback(cb)).over18, false);
    });

    test('missing dateOfBirth: MISSING_BIRTHDATE, nothing leaks', async () => {
      const cb = await callback(idps[0], person());
      await assertConnectorError(c.handleCallback(cb), 'MISSING_BIRTHDATE', { mustNotContain: ['Mario', 'Rossi', 'RSSMRA80A01H501U'] });
    });

    test('bad signature (assertion signed by another key): INVALID_RESPONSE', async () => {
      const intruder = await selfSignedRsa('Intruder');
      const cb = await callback(idps[0], person('1980-01-01'), { signWith: intruder });
      await assertConnectorError(c.handleCallback(cb), 'INVALID_RESPONSE', { mustNotContain: ['1980-01-01', 'Mario'] });
    });

    test('answer for another login (InResponseTo does not match): INVALID_RESPONSE', async () => {
      const cb = await callback(idps[0], person('1980-01-01'), { inResponseTo: `_${randomToken(8)}` });
      await assertConnectorError(c.handleCallback(cb), 'INVALID_RESPONSE');
    });

    test('bad RelayState: STATE_MISMATCH', async () => {
      const cb = await callback(idps[0], person('1980-01-01'));
      await assertConnectorError(c.handleCallback({ ...cb, params: { ...cb.params, RelayState: randomToken() } }), 'STATE_MISMATCH');
    });

    test('wrong audience: INVALID_RESPONSE', async () => {
      const cb = await callback(idps[0], person('1980-01-01'), { audience: 'https://someone-else.example/sp' });
      await assertConnectorError(c.handleCallback(cb), 'INVALID_RESPONSE');
    });

    test('wrong Recipient (sent to another address): INVALID_RESPONSE', async () => {
      const cb = await callback(idps[0], person('1980-01-01'), { acsUrl: 'https://evil.example/acs' });
      await assertConnectorError(c.handleCallback(cb), 'INVALID_RESPONSE');
    });

    test('replayed response: the second use is refused', async () => {
      const cb = await callback(idps[0], person('1980-01-01'));
      assert.equal((await c.handleCallback(cb)).over18, true);
      await assertConnectorError(c.handleCallback(cb), 'INVALID_RESPONSE');
    });

    test('user cancelled at the IdP (ErrorCode nr22): PROVIDER_ERROR', async () => {
      const cb = await callback(idps[0], {}, { statusError: 'ErrorCode nr22' });
      await assertConnectorError(c.handleCallback(cb), 'PROVIDER_ERROR');
    });

    if (requestedLevel.endsWith('L2')) {
      test('lower level than asked (SpidL1): INVALID_RESPONSE', async () => {
        const cb = await callback(idps[0], person('1980-01-01'), { level: 'https://www.spid.gov.it/SpidL1' });
        await assertConnectorError(c.handleCallback(cb), 'INVALID_RESPONSE');
      });
    }

    test('signed SP metadata lists the ACS URL and the requested attributes, and its signature verifies', async () => {
      const xml = await c.metadata!(REDIRECT);
      const doc = new DOMParser().parseFromString(xml, 'text/xml');
      const signature = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature').item(0)!;
      const verifier = new SignedXml({ publicCert: sp.certPem });
      verifier.loadSignature(signature as unknown as Node);
      assert.equal(verifier.checkSignature(xml), true);
      assert.ok(xml.includes(`Location="${REDIRECT}"`));
      assert.ok(xml.includes('Name="dateOfBirth"') && xml.includes('Name="fiscalNumber"'));
    });
  });
}

samlSuite('spid', ['https://idp-one.spid.test', 'https://idp-two.spid.test'], 'https://www.spid.gov.it/SpidL2', 'https://www.spid.gov.it/SpidL2', {
  spidCode: 'ABCD123456789A',
});
samlSuite('cie', ['https://preproduzione.idserver.cie.test/idp/profile/SAML2/POST/SSO'], 'https://www.spid.gov.it/SpidL2', 'https://www.spid.gov.it/SpidL3', {});

test('spid: with several IdPs, the person must pick one (idp)', async () => {
  const sp = await selfSignedRsa('SP');
  const a = await createSamlIdp('https://a.spid.test', 'A');
  const b = await createSamlIdp('https://b.spid.test', 'B');
  const env = {
    V18_CONNECTOR_SPID_ENTITY_ID: 'https://api.v18.test/saml/sp',
    V18_CONNECTOR_SPID_PRIVATE_KEY: sp.keyPem,
    V18_CONNECTOR_SPID_CERT: sp.certPem,
    V18_CONNECTOR_SPID_IDP_METADATA: `${a.metadataXml}\n${b.metadataXml}`,
  };
  const c = createConnector('spid', env);
  await assert.rejects(c.buildAuthUrl(newStart('https://api.v18.test/cb')), { code: 'BAD_REQUEST' });
  const { authUrl } = await c.buildAuthUrl({ ...newStart('https://api.v18.test/cb'), idp: 'https://b.spid.test' });
  assert.ok(authUrl.startsWith(b.ssoUrl));
});

test('parseIdpMetadata reads entityID, the Redirect SSO URL and signing certificates', async () => {
  const idp = await createSamlIdp('https://idp.example.test', 'Example');
  const [parsed] = parseIdpMetadata(idp.metadataXml);
  assert.equal(parsed.entityId, 'https://idp.example.test');
  assert.equal(parsed.ssoUrl, idp.ssoUrl);
  assert.equal(parsed.certs.length, 1);
  assert.equal(parsed.name, 'Example');
});
