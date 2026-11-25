/**
 * SAML 2.0 connectors for Italy: SPID and CIE ("Entra con CIE").
 *
 * - The AuthnRequest follows the SPID technical rules (also accepted by CIE): Issuer with
 *   NameQualifier and Format=entity, NameIDPolicy transient, RequestedAuthnContext SpidL2 or
 *   higher, ForceAuthn, HTTP-POST response to our ACS URL. It goes out over the HTTP-Redirect
 *   binding, signed with RSA-SHA256 as the SAML bindings spec says (Node's crypto).
 * - The response (HTTP-POST) is checked by `@node-saml/node-saml`: assertion signature against
 *   the IdP's certificate from its metadata, InResponseTo, audience, time limits. On top of that
 *   we check Recipient, the IdP's issuer, the authentication level, and refuse replays.
 * - Only `dateOfBirth` (YYYY-MM-DD) and `fiscalNumber` ("TINIT-<codice fiscale>", the same
 *   person across all SPID providers and CIE) are read. The other attributes are dropped.
 */
import { createSign, randomUUID } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import { SAML, ValidateInResponseTo, type CacheProvider } from '@node-saml/node-saml';
import { DOMParser } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { parseIsoDate } from './age.js';
import { envValue, hasAll, inlineOrFile } from './config.js';
import { decide } from './oidc.js';
import {
  ConnectorError,
  type Assurance,
  type AuthStart,
  type AuthStartParams,
  type CallbackParams,
  type Connector,
  type ConnectorOptions,
  type ConnectorResult,
  type Env,
} from './types.js';

const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
const POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const LEVELS = ['https://www.spid.gov.it/SpidL1', 'https://www.spid.gov.it/SpidL2', 'https://www.spid.gov.it/SpidL3'];

export interface IdentityProvider {
  entityId: string;
  /** The HTTP-Redirect SingleSignOnService location. */
  ssoUrl: string;
  /** Signing certificates (base64 DER, as in the metadata). */
  certs: string[];
  /** Organization display name from the metadata, when present. */
  name?: string;
}

/** Reads IdP entries from SAML metadata (an EntityDescriptor or an EntitiesDescriptor). */
export function parseIdpMetadata(xml: string): IdentityProvider[] {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const out: IdentityProvider[] = [];
  const entities = doc.getElementsByTagNameNS(NS_MD, 'EntityDescriptor');
  for (let i = 0; i < entities.length; i++) {
    const e = entities.item(i)!;
    const idp = e.getElementsByTagNameNS(NS_MD, 'IDPSSODescriptor').item(0);
    if (!idp) continue;
    let ssoUrl: string | undefined;
    const sso = idp.getElementsByTagNameNS(NS_MD, 'SingleSignOnService');
    for (let j = 0; j < sso.length; j++) {
      const s = sso.item(j)!;
      if (s.getAttribute('Binding') === REDIRECT) ssoUrl = s.getAttribute('Location') ?? undefined;
    }
    const certs: string[] = [];
    const kds = idp.getElementsByTagNameNS(NS_MD, 'KeyDescriptor');
    for (let j = 0; j < kds.length; j++) {
      const kd = kds.item(j)!;
      const use = kd.getAttribute('use');
      if (use && use !== 'signing') continue;
      const c = kd.getElementsByTagNameNS(NS_DS, 'X509Certificate');
      for (let k = 0; k < c.length; k++) certs.push((c.item(k)!.textContent ?? '').replace(/\s+/g, ''));
    }
    const nameEl = e.getElementsByTagNameNS(NS_MD, 'OrganizationDisplayName').item(0);
    const entityId = e.getAttribute('entityID');
    if (entityId && ssoUrl && certs.length > 0) out.push({ entityId, ssoUrl, certs, name: nameEl?.textContent?.trim() || undefined });
  }
  return out;
}

export interface SamlSpec {
  id: 'spid' | 'cie';
  label: string;
  assurance: Assurance;
  /** The level asked for by default. */
  defaultLevel: string;
}

interface SamlSession {
  requestId: string;
  idp: string;
  level: string;
}

function xmlEscape(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function pemBody(pem: string): string {
  return pem.replace(/-----(BEGIN|END)[^-]+-----/g, '').replace(/\s+/g, '');
}

/** Process-wide record of used request IDs and assertion IDs, so a SAML response works once. */
const used = new Map<string, number>();
function useOnce(key: string, ttlMs: number): boolean {
  const t = Date.now();
  for (const [k, exp] of used) if (exp < t) used.delete(k);
  if (used.has(key)) return false;
  used.set(key, t + ttlMs);
  return true;
}

export function createSamlConnector(spec: SamlSpec, env: Env, options: ConnectorOptions = {}): Connector {
  const id = spec.id;
  const now = options.now ?? (() => new Date());
  const fail = (code: ConstructorParameters<typeof ConnectorError>[1], message: string, providerCode?: string) =>
    new ConnectorError(id, code, message, providerCode);

  let idpCache: IdentityProvider[] | undefined;
  function idps(): IdentityProvider[] {
    if (idpCache) return idpCache;
    const raw = envValue(env, id, 'IDP_METADATA');
    if (!raw) throw fail('NOT_CONFIGURED', 'This login is not set up on this server.');
    const list = raw
      .split(/[;\n]/)
      .map((s) => s.trim())
      .filter(Boolean)
      .flatMap((s) => parseIdpMetadata(inlineOrFile(s)));
    if (list.length === 0) throw fail('NOT_CONFIGURED', 'No identity provider was found in the metadata.');
    idpCache = list;
    return list;
  }

  function sp() {
    const entityId = envValue(env, id, 'ENTITY_ID');
    const key = envValue(env, id, 'PRIVATE_KEY');
    const cert = envValue(env, id, 'CERT');
    if (!entityId || !key || !cert) throw fail('NOT_CONFIGURED', 'This login is not set up on this server.');
    return { entityId, privateKey: inlineOrFile(key), cert: inlineOrFile(cert) };
  }

  function level(): string {
    const l = envValue(env, id, 'LEVEL') ?? spec.defaultLevel;
    if (!LEVELS.includes(l)) throw fail('NOT_CONFIGURED', 'The SAML level setting is not valid.');
    return l;
  }

  function pickIdp(entityId?: string): IdentityProvider {
    const list = idps();
    if (entityId) {
      const found = list.find((i) => i.entityId === entityId);
      if (!found) throw fail('BAD_REQUEST', 'Unknown identity provider.');
      return found;
    }
    if (list.length === 1) return list[0];
    throw fail('BAD_REQUEST', 'Choose an identity provider (idp).');
  }

  return {
    id,
    label: spec.label,
    countries: ['IT'],
    assurance: spec.assurance,
    callbackMethod: 'POST',

    isConfigured(e: Env) {
      return hasAll(e, id, ['ENTITY_ID', 'PRIVATE_KEY', 'CERT', 'IDP_METADATA']);
    },

    identityProviders() {
      return idps().map(({ entityId, name }) => ({ entityId, name }));
    },

    async buildAuthUrl(p: AuthStartParams): Promise<AuthStart> {
      if (typeof p.state !== 'string' || p.state.length < 16 || p.state.length > 80) {
        throw fail('BAD_REQUEST', 'state must be 16 to 80 characters (it travels as SAML RelayState).');
      }
      const { entityId, privateKey } = sp();
      const idp = pickIdp(p.idp);
      const lvl = level();
      const requestId = `_${randomUUID()}`;
      const issueInstant = now().toISOString().replace(/\.\d{3}Z$/, 'Z');
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="${NS_SAML}"` +
        ` ID="${requestId}" Version="2.0" IssueInstant="${issueInstant}" Destination="${xmlEscape(idp.ssoUrl)}"` +
        ` ForceAuthn="true" AssertionConsumerServiceURL="${xmlEscape(p.redirectUri)}" ProtocolBinding="${POST}"` +
        ` AttributeConsumingServiceIndex="${xmlEscape(envValue(env, id, 'ATTRIBUTE_INDEX') ?? '0')}">` +
        `<saml:Issuer NameQualifier="${xmlEscape(entityId)}" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">${xmlEscape(entityId)}</saml:Issuer>` +
        `<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>` +
        `<samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>${lvl}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>` +
        `</samlp:AuthnRequest>`;

      // HTTP-Redirect binding (SAML 2.0 Bindings, section 3.4.4.1): sign
      // "SAMLRequest=..&RelayState=..&SigAlg=.." with the SP key, RSA-SHA256.
      const q =
        `SAMLRequest=${encodeURIComponent(deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64'))}` +
        `&RelayState=${encodeURIComponent(p.state)}` +
        `&SigAlg=${encodeURIComponent(RSA_SHA256)}`;
      let signature: string;
      try {
        signature = createSign('RSA-SHA256').update(q).sign(privateKey, 'base64');
      } catch {
        throw fail('NOT_CONFIGURED', 'The SAML signing key could not be used.');
      }
      const sep = idp.ssoUrl.includes('?') ? '&' : '?';
      const authUrl = `${idp.ssoUrl}${sep}${q}&Signature=${encodeURIComponent(signature)}`;
      const session: SamlSession = { requestId, idp: idp.entityId, level: lvl };
      return { authUrl, session: JSON.stringify(session) };
    },

    async handleCallback(c: CallbackParams): Promise<ConnectorResult> {
      const params = c.params ?? {};
      if (params.RelayState !== c.state) throw fail('STATE_MISMATCH', 'The login answer does not belong to this session.');
      if (typeof params.SAMLResponse !== 'string' || params.SAMLResponse === '') throw fail('INVALID_RESPONSE', 'The login answer is empty.');
      let session: SamlSession;
      try {
        session = JSON.parse(c.session ?? '') as SamlSession;
      } catch {
        throw fail('INVALID_RESPONSE', 'The saved login session is missing.');
      }
      if (typeof session.requestId !== 'string' || typeof session.idp !== 'string') throw fail('INVALID_RESPONSE', 'The saved login session is missing.');
      const idp = pickIdp(session.idp);
      const { entityId } = sp();

      // node-saml checks InResponseTo through a cache: give it exactly this login's request ID.
      const pending = new Map<string, string>([[session.requestId, now().toISOString()]]);
      const cache: CacheProvider = {
        saveAsync: async (key, value) => {
          pending.set(key, value);
          return { value, createdAt: Date.now() };
        },
        getAsync: async (key) => pending.get(key) ?? null,
        removeAsync: async (key) => {
          const v = key !== null ? pending.get(key) ?? null : null;
          if (key !== null) pending.delete(key);
          return v;
        },
      };
      const saml = new SAML({
        callbackUrl: c.redirectUri,
        issuer: entityId,
        audience: entityId,
        idpCert: idp.certs,
        idpIssuer: idp.entityId,
        wantAssertionsSigned: true,
        wantAuthnResponseSigned: false,
        validateInResponseTo: ValidateInResponseTo.always,
        requestIdExpirationPeriodMs: 15 * 60 * 1000,
        cacheProvider: cache,
        acceptedClockSkewMs: 30_000,
      });

      let profile: Record<string, unknown> | null;
      try {
        const res = await saml.validatePostResponseAsync({ SAMLResponse: params.SAMLResponse, RelayState: params.RelayState });
        profile = res.profile as unknown as Record<string, unknown> | null;
      } catch (err) {
        const status = (err as { xmlStatus?: unknown }).xmlStatus;
        if (typeof status === 'string' && status !== '') {
          throw fail('PROVIDER_ERROR', 'The login was cancelled or refused by the identity provider.', status.split(':').pop());
        }
        throw fail('INVALID_RESPONSE', 'The login answer could not be checked.', 'saml_validation');
      }
      if (!profile) throw fail('INVALID_RESPONSE', 'The login answer has no assertion.');

      const assertionXml = typeof profile.getAssertionXml === 'function' ? (profile.getAssertionXml as () => string)() : '';
      const doc = new DOMParser().parseFromString(assertionXml, 'text/xml');
      const assertion = doc.getElementsByTagNameNS(NS_SAML, 'Assertion').item(0);
      if (!assertion) throw fail('INVALID_RESPONSE', 'The login answer has no assertion.');
      const scd = doc.getElementsByTagNameNS(NS_SAML, 'SubjectConfirmationData').item(0);
      if (!scd || scd.getAttribute('Recipient') !== c.redirectUri) throw fail('INVALID_RESPONSE', 'The login answer was meant for another address.');
      const classRef = doc.getElementsByTagNameNS(NS_SAML, 'AuthnContextClassRef').item(0)?.textContent?.trim() ?? '';
      if (LEVELS.indexOf(classRef) < LEVELS.indexOf(session.level)) throw fail('INVALID_RESPONSE', 'The login was done at a lower level than asked.');
      const assertionId = assertion.getAttribute('ID') ?? '';
      if (!useOnce(`${id}|req|${session.requestId}`, 60 * 60 * 1000) || !useOnce(`${id}|as|${assertionId}`, 60 * 60 * 1000)) {
        throw fail('INVALID_RESPONSE', 'This login answer was already used.', 'replay');
      }

      const attrs = (profile.attributes as Record<string, unknown> | undefined) ?? profile;
      const first = (v: unknown) => (Array.isArray(v) ? v[0] : v);
      const fiscal = first(attrs.fiscalNumber);
      return decide(id, { subject: typeof fiscal === 'string' ? fiscal : undefined, birthDate: parseIsoDate(first(attrs.dateOfBirth)) }, now());
    },

    /**
     * Signed SP metadata with one HTTP-POST AssertionConsumerService and the attributes asked for
     * (CIE needs the eIDAS minimum dataset: name, familyName, dateOfBirth, fiscalNumber).
     * Before sending it to AgID or the CIE portal, add the Organization and ContactPerson details
     * their rules ask for (see docs/connectors/spid.md and cie.md).
     */
    async metadata(acsUrl: string): Promise<string> {
      const { entityId, privateKey, cert } = sp();
      const attrs = id === 'cie' ? ['name', 'familyName', 'dateOfBirth', 'fiscalNumber'] : ['dateOfBirth', 'fiscalNumber'];
      const orgName = xmlEscape(envValue(env, id, 'ORG_NAME') ?? 'V18');
      const orgUrl = xmlEscape(envValue(env, id, 'ORG_URL') ?? entityId);
      const mdId = `_${randomUUID()}`;
      const xml =
        `<md:EntityDescriptor xmlns:md="${NS_MD}" xmlns:ds="${NS_DS}" entityID="${xmlEscape(entityId)}" ID="${mdId}">` +
        `<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">` +
        `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${pemBody(cert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
        `<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>` +
        `<md:AssertionConsumerService index="0" isDefault="true" Binding="${POST}" Location="${xmlEscape(acsUrl)}"/>` +
        `<md:AttributeConsumingService index="0"><md:ServiceName xml:lang="it">V18</md:ServiceName>` +
        attrs.map((a) => `<md:RequestedAttribute Name="${a}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>`).join('') +
        `</md:AttributeConsumingService></md:SPSSODescriptor>` +
        `<md:Organization><md:OrganizationName xml:lang="it">${orgName}</md:OrganizationName>` +
        `<md:OrganizationDisplayName xml:lang="it">${orgName}</md:OrganizationDisplayName>` +
        `<md:OrganizationURL xml:lang="it">${orgUrl}</md:OrganizationURL></md:Organization>` +
        `</md:EntityDescriptor>`;
      const sig = new SignedXml({ privateKey, publicCert: cert, signatureAlgorithm: RSA_SHA256, canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#' });
      sig.addReference({
        xpath: `//*[local-name(.)='EntityDescriptor']`,
        transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
        digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      });
      sig.computeSignature(xml, { prefix: 'ds', location: { reference: `//*[local-name(.)='SPSSODescriptor']`, action: 'before' } });
      return sig.getSignedXml();
    },
  };
}

export function spid(env: Env, options?: ConnectorOptions): Connector {
  return createSamlConnector({ id: 'spid', label: 'SPID', assurance: 'high', defaultLevel: LEVELS[1] }, env, options);
}

export function cie(env: Env, options?: ConnectorOptions): Connector {
  return createSamlConnector({ id: 'cie', label: 'CIE (Entra con CIE)', assurance: 'high', defaultLevel: LEVELS[1] }, env, options);
}
