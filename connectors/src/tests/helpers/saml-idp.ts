/**
 * TEST ONLY: a SPID / CIE identity provider in a box. It publishes IdP metadata, checks the
 * AuthnRequest that V18 sends over the HTTP-Redirect binding (signature, ID, level, ACS URL),
 * and builds a SAML Response with a signed assertion in the SPID/CIE format
 * (dateOfBirth as YYYY-MM-DD, fiscalNumber as "TINIT-<codice fiscale>").
 */
import assert from 'node:assert/strict';
import { createVerify, randomUUID } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { DOMParser } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { selfSignedRsa, type CertAndKey } from './keys.js';

const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

export interface SamlIdp {
  entityId: string;
  ssoUrl: string;
  metadataXml: string;
  cert: CertAndKey;
  /** Reads and checks V18's AuthnRequest from the redirect URL. Returns its ID and fields. */
  readRequest(authUrl: string, spCertPem: string): { id: string; relayState: string; acsUrl: string; level: string; issuer: string; nameQualifier: string };
  /** A base64 SAMLResponse. */
  response(opts: ResponseOptions): string;
}

export interface ResponseOptions {
  inResponseTo: string;
  acsUrl: string;
  audience: string;
  attributes?: Record<string, string>;
  level?: string;
  /** Sign with this key instead (bad signature test). */
  signWith?: CertAndKey;
  /** A refusal status instead of an assertion (for example the user cancelled: ErrorCode nr22). */
  statusError?: string;
  assertionId?: string;
}

function iso(ms: number) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function esc(v: string) {
  return v.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export async function createSamlIdp(entityId: string, name: string): Promise<SamlIdp> {
  const cert = await selfSignedRsa(name);
  const ssoUrl = `${entityId.replace(/\/$/, '')}/sso`;
  const certB64 = cert.certPem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
  const metadataXml =
    `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="${entityId}">` +
    `<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">` +
    `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certB64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
    `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${ssoUrl}"/>` +
    `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${ssoUrl}"/>` +
    `</md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang="it">${name}</md:OrganizationName>` +
    `<md:OrganizationDisplayName xml:lang="it">${name}</md:OrganizationDisplayName><md:OrganizationURL xml:lang="it">${entityId}</md:OrganizationURL></md:Organization>` +
    `</md:EntityDescriptor>`;

  return {
    entityId,
    ssoUrl,
    metadataXml,
    cert,

    readRequest(authUrl, spCertPem) {
      const u = new URL(authUrl);
      assert.equal(`${u.origin}${u.pathname}`, ssoUrl);
      // Check the HTTP-Redirect binding signature exactly as an IdP would.
      const raw = u.search.slice(1);
      const part = (name: string) => raw.split('&').find((p) => p.startsWith(`${name}=`))!;
      const signed = [part('SAMLRequest'), part('RelayState'), part('SigAlg')].join('&');
      assert.equal(u.searchParams.get('SigAlg'), 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
      const ok = createVerify('RSA-SHA256').update(signed).verify(spCertPem, u.searchParams.get('Signature')!, 'base64');
      assert.ok(ok, 'AuthnRequest signature must verify with the SP certificate');
      const xml = inflateRawSync(Buffer.from(u.searchParams.get('SAMLRequest')!, 'base64')).toString('utf8');
      const doc = new DOMParser().parseFromString(xml, 'text/xml');
      const req = doc.documentElement!;
      const issuer = doc.getElementsByTagNameNS(NS_SAML, 'Issuer').item(0)!;
      return {
        id: req.getAttribute('ID')!,
        relayState: u.searchParams.get('RelayState')!,
        acsUrl: req.getAttribute('AssertionConsumerServiceURL')!,
        level: doc.getElementsByTagNameNS(NS_SAML, 'AuthnContextClassRef').item(0)!.textContent!,
        issuer: issuer.textContent!,
        nameQualifier: issuer.getAttribute('NameQualifier')!,
      };
    },

    response(o) {
      const now = Date.now();
      const rid = `_${randomUUID()}`;
      const aid = o.assertionId ?? `_${randomUUID()}`;
      const issuer = `<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">${esc(entityId)}</saml:Issuer>`;
      if (o.statusError) {
        const xml =
          `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="${NS_SAML}" ID="${rid}" Version="2.0" IssueInstant="${iso(now)}" Destination="${esc(o.acsUrl)}" InResponseTo="${o.inResponseTo}">` +
          issuer +
          `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/></samlp:StatusCode>` +
          `<samlp:StatusMessage>${esc(o.statusError)}</samlp:StatusMessage></samlp:Status></samlp:Response>`;
        return Buffer.from(xml).toString('base64');
      }
      const attrs = Object.entries(o.attributes ?? {})
        .map(
          ([k, v]) =>
            `<saml:Attribute Name="${k}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="${k === 'dateOfBirth' ? 'xs:date' : 'xs:string'}">${esc(v)}</saml:AttributeValue></saml:Attribute>`,
        )
        .join('');
      const assertion =
        `<saml:Assertion xmlns:saml="${NS_SAML}" ID="${aid}" Version="2.0" IssueInstant="${iso(now)}">` +
        issuer +
        `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="${esc(entityId)}">_${randomUUID()}</saml:NameID>` +
        `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${o.inResponseTo}" NotOnOrAfter="${iso(now + 5 * 60000)}" Recipient="${esc(o.acsUrl)}"/></saml:SubjectConfirmation></saml:Subject>` +
        `<saml:Conditions NotBefore="${iso(now - 60000)}" NotOnOrAfter="${iso(now + 5 * 60000)}"><saml:AudienceRestriction><saml:Audience>${esc(o.audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
        `<saml:AuthnStatement AuthnInstant="${iso(now)}" SessionIndex="_${randomUUID()}"><saml:AuthnContext><saml:AuthnContextClassRef>${o.level ?? 'https://www.spid.gov.it/SpidL2'}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
        `<saml:AttributeStatement>${attrs}</saml:AttributeStatement></saml:Assertion>`;
      const signer = o.signWith ?? cert;
      const sig = new SignedXml({
        privateKey: signer.keyPem,
        publicCert: signer.certPem,
        signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
      });
      sig.addReference({
        xpath: `//*[local-name(.)='Assertion']`,
        transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
        digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      });
      sig.computeSignature(assertion, { prefix: 'ds', location: { reference: `//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']`, action: 'after' } });
      const xml =
        `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="${NS_SAML}" ID="${rid}" Version="2.0" IssueInstant="${iso(now)}" Destination="${esc(o.acsUrl)}" InResponseTo="${o.inResponseTo}">` +
        issuer +
        `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
        sig.getSignedXml() +
        `</samlp:Response>`;
      return Buffer.from(xml).toString('base64');
    },
  };
}
