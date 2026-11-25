/**
 * The OpenID Connect / OAuth 2.0 connectors. Each spec follows the provider's public
 * developer documentation; the matching `docs/connectors/<id>.md` names the pages used.
 */
import { parseDayFirstDate, parseIsoDate, type BirthDate } from '../age.js';
import { envValue } from '../config.js';
import { secretOrKeyAuth, secretOrKeyRequired, str, type Extracted, type OidcSpec } from '../oidc.js';
import { ConnectorError, type Env } from '../types.js';

function obj(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function bool(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return undefined;
}

/** ISO first, then day-first (DD/MM/YYYY, DD.MM.YYYY, DDMMYYYY). */
function anyDate(value: unknown): BirthDate | undefined {
  return parseIsoDate(value) ?? parseDayFirstDate(value);
}

// ---------------------------------------------------------------- Singpass (SG)
/**
 * Singpass Login + Myinfo v5 on the FAPI 2.0 API: PAR, DPoP, PKCE, private_key_jwt (ES256),
 * an ID token that is always a JWE (ECDH-ES+A256KW / A256CBC-HS512) and a userinfo
 * response that is a signed JWT inside a JWE. Scope `dob`; value at `person_info.dob.value`.
 */
export function singpass(_env: Env): OidcSpec {
  return {
    id: 'singpass',
    label: 'Singpass (Myinfo)',
    countries: ['SG'],
    assurance: 'high',
    required: () => ['CLIENT_ID', 'SIGNING_KEY', 'ENCRYPTION_KEY'],
    discoveryUrl: 'https://id.singpass.gov.sg/fapi/.well-known/openid-configuration',
    clientAuth: () => 'private_key_jwt',
    assertionAudience: 'issuer',
    signingAlg: 'ES256',
    par: true,
    dpop: true,
    idToken: true,
    userinfo: true,
    encrypted: true,
    clientMetadata: {
      id_token_signed_response_alg: 'ES256',
      userinfo_signed_response_alg: 'ES256',
      dpop_bound_access_tokens: true,
    },
    authParams: (env) => {
      const p: Record<string, string> = { scope: 'openid dob' };
      const acr = envValue(env, 'singpass', 'ACR');
      if (acr) p.acr_values = acr;
      return p;
    },
    extract: ({ idToken, userinfo }) => {
      const person = obj(userinfo?.person_info) ?? userinfo;
      const dob = obj(person?.dob);
      return { subject: str(idToken?.sub), birthDate: parseIsoDate(dob?.value) };
    },
  };
}

// ---------------------------------------------------------------- DigiLocker (IN)
/**
 * DigiLocker (MeriPehchaan API spec v2.4): OAuth 2.0 with PKCE S256 (required), plus the
 * required `purpose` and `service_name` parameters. The `/public/oauth2/1/token` response
 * carries `digilockerid` (36 characters, stable) and `dob` as DDMMYYYY. We only accept
 * accounts whose details come from Aadhaar (`eaadhaar` = "Y") unless the operator turns that off.
 */
export function digilocker(_env: Env): OidcSpec {
  return {
    id: 'digilocker',
    label: 'DigiLocker',
    countries: ['IN'],
    assurance: 'high',
    required: () => ['CLIENT_ID', 'CLIENT_SECRET'],
    defaultIssuer: 'https://digilocker.meripehchaan.gov.in',
    staticMetadata: (issuer) => ({
      issuer,
      authorization_endpoint: `${issuer}/public/oauth2/1/authorize`,
      token_endpoint: `${issuer}/public/oauth2/1/token`,
    }),
    clientAuth: () => 'client_secret_post',
    idToken: false,
    userinfo: false,
    authParams: (env) => ({
      purpose: cleanLabel(envValue(env, 'digilocker', 'PURPOSE') ?? 'Age check'),
      service_name: cleanLabel(envValue(env, 'digilocker', 'SERVICE_NAME') ?? 'V18 age check'),
    }),
    extract: ({ token }, env) => {
      const requireAadhaar = envValue(env, 'digilocker', 'REQUIRE_EAADHAAR') !== '0';
      if (requireAadhaar && token.eaadhaar !== 'Y') {
        throw new ConnectorError('digilocker', 'MISSING_BIRTHDATE', 'This DigiLocker account is not linked to Aadhaar, so its birth date is not checked.');
      }
      return { subject: str(token.digilockerid), birthDate: parseDayFirstDate(token.dob) };
    },
  };
}

/** DigiLocker allows only letters, digits, spaces and underscores in purpose and service_name. */
function cleanLabel(value: string): string {
  return value.replace(/[^A-Za-z0-9 _]/g, '').slice(0, 100) || 'V18';
}

// ---------------------------------------------------------------- UAE PASS (AE)
/**
 * UAE PASS web login: OAuth 2.0 code flow, HTTP Basic client auth, scope
 * `urn:uae:digitalid:profile:general`, userinfo as JSON. The public attribute list has NO
 * birth date, so this connector stays OFF until the operator sets
 * `V18_CONNECTOR_UAEPASS_DOB_ATTRIBUTE` to the attribute name UAE PASS grants them.
 * Only verified accounts (userType SOP2 or SOP3) are accepted.
 */
export function uaepass(_env: Env): OidcSpec {
  return {
    id: 'uaepass',
    label: 'UAE PASS',
    countries: ['AE'],
    assurance: 'high',
    required: () => ['CLIENT_ID', 'CLIENT_SECRET', 'DOB_ATTRIBUTE'],
    defaultIssuer: 'https://id.uaepass.ae',
    staticMetadata: (issuer) => ({
      issuer,
      authorization_endpoint: `${issuer}/idshub/authorize`,
      token_endpoint: `${issuer}/idshub/token`,
      userinfo_endpoint: `${issuer}/idshub/userinfo`,
    }),
    clientAuth: () => 'client_secret_basic',
    idToken: false,
    userinfo: true,
    authParams: (env) => ({
      scope: envValue(env, 'uaepass', 'SCOPE') ?? 'urn:uae:digitalid:profile:general',
      acr_values: envValue(env, 'uaepass', 'ACR') ?? 'urn:safelayer:tws:policies:authentication:level:low',
      ui_locales: 'en',
    }),
    extract: ({ userinfo }, env) => {
      const userType = str(userinfo?.userType);
      if (userType !== 'SOP2' && userType !== 'SOP3') {
        throw new ConnectorError('uaepass', 'MISSING_BIRTHDATE', 'Only verified UAE PASS accounts can be used.');
      }
      const attr = envValue(env, 'uaepass', 'DOB_ATTRIBUTE') ?? 'dob';
      return { subject: str(userinfo?.uuid) ?? str(userinfo?.sub), birthDate: anyDate(userinfo?.[attr]) };
    },
  };
}

// ---------------------------------------------------------------- BankID (NO)
/**
 * BankID Norway OIDC: code flow with PKCE, scope `openid profile` gives `birthdate`
 * (YYYY-MM-DD) in the ID token. `sub` is documented as unstable, so the stable
 * `bankid_altsub` is the subject. `acr_values=urn:bankid:bid` (BankID High, LOA 4).
 */
export function bankidNo(_env: Env): OidcSpec {
  return {
    id: 'bankid_no',
    label: 'BankID (Norway)',
    countries: ['NO'],
    assurance: 'high',
    required: secretOrKeyRequired('bankid_no'),
    discoveryUrl: 'https://auth.bankid.no/auth/realms/prod/.well-known/openid-configuration',
    clientAuth: secretOrKeyAuth('bankid_no'),
    signingAlg: 'RS256',
    idToken: true,
    userinfo: false,
    authParams: (env) => ({
      scope: 'openid profile',
      acr_values: envValue(env, 'bankid_no', 'ACR') ?? 'urn:bankid:bid',
    }),
    extract: ({ idToken }) => ({ subject: str(idToken?.bankid_altsub), birthDate: parseIsoDate(idToken?.birthdate) }),
  };
}

// ---------------------------------------------------------------- itsme (BE, NL, LU)
/**
 * itsme v2 OIDC: scope `openid service:<SERVICE_CODE>`, private_key_jwt with the token
 * endpoint as audience, ID token and userinfo as nested JWTs (signed, then encrypted to our
 * key). We ask only for the `age_gte_18` yes/no claim (it reveals less than a birth date);
 * set `V18_CONNECTOR_ITSME_ASK_BIRTHDATE=1` to also ask for `birthdate` as a fallback.
 */
export function itsme(_env: Env): OidcSpec {
  return {
    id: 'itsme',
    label: 'itsme',
    countries: ['BE', 'NL', 'LU'],
    assurance: 'high',
    required: () => ['CLIENT_ID', 'SERVICE_CODE', 'SIGNING_KEY', 'ENCRYPTION_KEY'],
    discoveryUrl: 'https://idp.prd.itsme.services/v2/.well-known/openid-configuration',
    clientAuth: () => 'private_key_jwt',
    assertionAudience: 'token_endpoint',
    signingAlg: 'RS256',
    idToken: true,
    userinfo: true,
    encrypted: true,
    clientMetadata: { id_token_signed_response_alg: 'RS256', userinfo_signed_response_alg: 'RS256' },
    authParams: (env) => {
      const claims: Record<string, null> = { age_gte_18: null };
      if (envValue(env, 'itsme', 'ASK_BIRTHDATE') === '1') claims.birthdate = null;
      return {
        scope: `openid service:${envValue(env, 'itsme', 'SERVICE_CODE')}`,
        claims: JSON.stringify({ userinfo: claims }),
        acr_values: envValue(env, 'itsme', 'ACR') ?? 'http://itsme.services/v2/claim/acr_basic',
      };
    },
    extract: ({ idToken, userinfo }) => {
      const answer = bool(userinfo?.age_gte_18) ?? bool(idToken?.age_gte_18);
      const out: Extracted = { subject: str(idToken?.sub) };
      if (answer !== undefined) out.over18 = answer;
      else out.birthDate = parseIsoDate(userinfo?.birthdate) ?? parseIsoDate(idToken?.birthdate);
      return out;
    },
  };
}

// ---------------------------------------------------------------- FranceConnect (FR)
/**
 * FranceConnect v2: scope `openid birthdate`, `acr_values=eidas1`, client_secret_post,
 * ES256 ID token, userinfo as an ES256-signed JWT. state and nonce must be at least 32
 * characters. FranceConnect marks a guessed month or day as `-01`, so those dates are
 * treated as unknown (cautious). `V18_CONNECTOR_FRANCECONNECT_PLUS=1` switches to
 * FranceConnect+ (eidas2, encrypted tokens, needs an encryption key).
 */
export function franceconnect(env: Env): OidcSpec {
  const plus = envValue(env, 'franceconnect', 'PLUS') === '1';
  return {
    id: 'franceconnect',
    label: plus ? 'FranceConnect+' : 'FranceConnect',
    countries: ['FR'],
    assurance: 'substantial',
    required: () => (plus ? ['CLIENT_ID', 'CLIENT_SECRET', 'ENCRYPTION_KEY'] : ['CLIENT_ID', 'CLIENT_SECRET']),
    discoveryUrl: plus
      ? 'https://auth.franceconnect.gouv.fr/api/v2/.well-known/openid-configuration'
      : 'https://oidc.franceconnect.gouv.fr/api/v2/.well-known/openid-configuration',
    clientAuth: () => 'client_secret_post',
    idToken: true,
    userinfo: true,
    encrypted: plus,
    minStateLength: 32,
    clientMetadata: { id_token_signed_response_alg: 'ES256', userinfo_signed_response_alg: 'ES256' },
    authParams: () => ({ scope: 'openid birthdate', acr_values: plus ? 'eidas2' : 'eidas1', prompt: 'login consent' }),
    extract: ({ idToken, userinfo }) => ({
      subject: str(idToken?.sub),
      birthDate: franceConnectDate(userinfo?.birthdate ?? idToken?.birthdate),
    }),
  };
}

/** `YYYY-01-01` = month and day guessed; `YYYY-MM-01` = day guessed (FranceConnect docs). */
export function franceConnectDate(value: unknown): BirthDate | undefined {
  const d = parseIsoDate(value);
  if (!d || d.day === undefined) return d;
  if (d.month === 1 && d.day === 1) return { year: d.year };
  if (d.day === 1) return { year: d.year, month: d.month };
  return d;
}

// ---------------------------------------------------------------- MitID (DK), through a broker
/**
 * MitID is only open to relying parties through a certified MitID broker. This uses the
 * Signaturgruppen broker's documented OIDC interface. Default mode `age_verify`: scope
 * `openid age_verify:18`, and the ID token says only `idbrokerdk_age_verified: "18:true"`
 * (no birth date leaves the broker). Mode `mitid`: scope `openid mitid` and
 * `mitid.date_of_birth` from userinfo. `sub` is the broker's stable per-organisation UUID.
 */
export function mitid(env: Env): OidcSpec {
  const full = envValue(env, 'mitid', 'MODE') === 'mitid';
  return {
    id: 'mitid',
    label: 'MitID',
    countries: ['DK'],
    assurance: 'high',
    required: secretOrKeyRequired('mitid'),
    discoveryUrl: 'https://netseidbroker.dk/op/.well-known/openid-configuration',
    clientAuth: secretOrKeyAuth('mitid'),
    signingAlg: 'RS256',
    idToken: true,
    userinfo: full ? true : false,
    authParams: (): Record<string, string> =>
      full ? { scope: 'openid mitid', idp_values: 'mitid' } : { scope: 'openid age_verify:18', prompt: 'login' },
    extract: ({ idToken, userinfo }) => {
      const out: Extracted = { subject: str(idToken?.sub) };
      if (full) {
        out.birthDate = parseIsoDate(userinfo?.['mitid.date_of_birth']);
        return out;
      }
      const m = /^(\d+):(true|false)$/.exec(str(idToken?.idbrokerdk_age_verified) ?? '');
      if (m && m[1] === '18') out.over18 = m[2] === 'true';
      return out;
    },
  };
}

// ---------------------------------------------------------------- Freja eID (SE)
/**
 * Freja eID's own OIDC service: scope `openid https://frejaeid.com/oidc/scopes/birthdate`,
 * claim `birthdate` (YYYY-MM-DD). `min_registration_level=EXTENDED`, because a BASIC
 * Freja account has no checked ID document and no birth date.
 */
export function freja(_env: Env): OidcSpec {
  return {
    id: 'freja',
    label: 'Freja eID',
    countries: ['SE'],
    assurance: 'substantial',
    required: secretOrKeyRequired('freja'),
    discoveryUrl: 'https://oidc.prod.frejaeid.com/oidc/.well-known/openid-configuration',
    clientAuth: secretOrKeyAuth('freja', 'client_secret_post'),
    signingAlg: 'RS256',
    idToken: true,
    userinfo: 'if-needed',
    authParams: () => ({ scope: 'openid https://frejaeid.com/oidc/scopes/birthdate', min_registration_level: 'EXTENDED' }),
    extract: ({ idToken, userinfo }) => ({
      subject: str(idToken?.sub),
      birthDate: parseIsoDate(idToken?.birthdate) ?? parseIsoDate(userinfo?.birthdate),
    }),
  };
}

// ---------------------------------------------------------------- DigiD (NL), through a broker
/**
 * DigiD itself speaks SAML to government-approved organisations only and gives a BSN, not a
 * birth date. The usual route is a broker that speaks OIDC. This connector needs the broker's
 * discovery URL (`ISSUER`) and reads a birth date claim the broker adds
 * (`BIRTHDATE_CLAIM`, default `birthdate`). Without that claim every login fails with
 * MISSING_BIRTHDATE, so it is better left off unless the broker confirms it.
 */
export function digid(_env: Env): OidcSpec {
  return {
    id: 'digid',
    label: 'DigiD',
    countries: ['NL'],
    assurance: 'substantial',
    required: secretOrKeyRequired('digid', ['ISSUER']),
    clientAuth: secretOrKeyAuth('digid'),
    signingAlg: 'RS256',
    idToken: true,
    userinfo: 'if-needed',
    authParams: (env) => {
      const p: Record<string, string> = { scope: envValue(env, 'digid', 'SCOPE') ?? 'openid' };
      const acr = envValue(env, 'digid', 'ACR');
      if (acr) p.acr_values = acr;
      return p;
    },
    extract: ({ idToken, userinfo }, env) => {
      const dobClaim = envValue(env, 'digid', 'BIRTHDATE_CLAIM') ?? 'birthdate';
      const subClaim = envValue(env, 'digid', 'SUBJECT_CLAIM') ?? 'sub';
      return {
        subject: str(idToken?.[subClaim]) ?? str(userinfo?.[subClaim]),
        birthDate: anyDate(idToken?.[dobClaim]) ?? anyDate(userinfo?.[dobClaim]),
      };
    },
  };
}
