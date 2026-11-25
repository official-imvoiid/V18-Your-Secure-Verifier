/**
 * The connector registry. Only connectors whose settings are all present are listed,
 * so a login the operator has not registered for never shows up (PROTOCOL.md 4d.4).
 */
import { envName } from './config.js';
import { createOidcConnector, type OidcSpec } from './oidc.js';
import { createBankIdSe } from './providers/bankid-se.js';
import { bankidNo, digid, digilocker, franceconnect, freja, itsme, mitid, singpass, uaepass } from './providers/oidc-providers.js';
import { cie, spid } from './saml.js';
import type { Assurance, Connector, ConnectorId, ConnectorOptions, Env } from './types.js';

type Factory = (env: Env, options?: ConnectorOptions) => Connector;

function fromSpec(make: (env: Env) => OidcSpec): Factory {
  return (env, options) => createOidcConnector(make(env), env, options);
}

/** Every connector V18 knows, in a stable order. */
export const CONNECTOR_IDS: readonly ConnectorId[] = [
  'singpass',
  'digilocker',
  'uaepass',
  'bankid_se',
  'bankid_no',
  'mitid',
  'itsme',
  'franceconnect',
  'spid',
  'cie',
  'digid',
  'freja',
];

const FACTORIES: Record<ConnectorId, Factory> = {
  singpass: fromSpec(singpass),
  digilocker: fromSpec(digilocker),
  uaepass: fromSpec(uaepass),
  bankid_se: createBankIdSe,
  bankid_no: fromSpec(bankidNo),
  mitid: fromSpec(mitid),
  itsme: fromSpec(itsme),
  franceconnect: fromSpec(franceconnect),
  spid,
  cie,
  digid: fromSpec(digid),
  freja: fromSpec(freja),
};

/** Makes one connector, configured or not. Most callers want `createRegistry` instead. */
export function createConnector(id: ConnectorId, env: Env = process.env, options?: ConnectorOptions): Connector {
  const factory = FACTORIES[id];
  if (!factory) throw new Error(`Unknown connector: ${id}`);
  return factory(env, options);
}

export interface ConnectorSummary {
  id: ConnectorId;
  label: string;
  countries: readonly string[];
  assurance: Assurance;
  callbackMethod: 'GET' | 'POST';
}

export interface Registry {
  /** Only the configured connectors. */
  list(): Connector[];
  /** A configured connector, or undefined (treat as 404 / not enabled). */
  get(id: string): Connector | undefined;
  /** Small, safe descriptions of the configured connectors, for `/v1/catalog`. */
  summaries(): ConnectorSummary[];
  /** Configured connectors that serve a country (ISO alpha-2). */
  forCountry(country: string): Connector[];
}

export function createRegistry(env: Env = process.env, options?: ConnectorOptions): Registry {
  const enabled = new Map<ConnectorId, Connector>();
  for (const id of CONNECTOR_IDS) {
    const connector = FACTORIES[id](env, options);
    if (connector.isConfigured(env)) enabled.set(id, connector);
  }
  const list = () => [...enabled.values()];
  return {
    list,
    get: (id: string) => enabled.get(id as ConnectorId),
    summaries: () =>
      list().map((c) => ({ id: c.id, label: c.label, countries: c.countries, assurance: c.assurance, callbackMethod: c.callbackMethod })),
    forCountry: (country: string) => list().filter((c) => c.countries.includes(country.toUpperCase())),
  };
}

/** The environment variable names a connector reads, for docs and setup checks. */
export const CONNECTOR_ENV: Record<ConnectorId, { required: string[]; optional: string[] }> = {
  singpass: { required: ['CLIENT_ID', 'SIGNING_KEY', 'ENCRYPTION_KEY'], optional: ['ISSUER', 'ACR'] },
  digilocker: { required: ['CLIENT_ID', 'CLIENT_SECRET'], optional: ['ISSUER', 'PURPOSE', 'SERVICE_NAME', 'REQUIRE_EAADHAAR'] },
  uaepass: { required: ['CLIENT_ID', 'CLIENT_SECRET', 'DOB_ATTRIBUTE'], optional: ['ISSUER', 'SCOPE', 'ACR'] },
  bankid_se: { required: ['CA', 'PFX (or CERT and KEY)'], optional: ['PASSPHRASE', 'API_URL'] },
  bankid_no: { required: ['CLIENT_ID', 'CLIENT_SECRET (or SIGNING_KEY)'], optional: ['ISSUER', 'ACR', 'AUTH_METHOD'] },
  mitid: { required: ['CLIENT_ID', 'CLIENT_SECRET (or SIGNING_KEY)'], optional: ['ISSUER', 'MODE', 'AUTH_METHOD'] },
  itsme: { required: ['CLIENT_ID', 'SERVICE_CODE', 'SIGNING_KEY', 'ENCRYPTION_KEY'], optional: ['ISSUER', 'ACR', 'ASK_BIRTHDATE'] },
  franceconnect: { required: ['CLIENT_ID', 'CLIENT_SECRET'], optional: ['ISSUER', 'PLUS', 'ENCRYPTION_KEY (with PLUS=1)'] },
  spid: { required: ['ENTITY_ID', 'PRIVATE_KEY', 'CERT', 'IDP_METADATA'], optional: ['LEVEL', 'ATTRIBUTE_INDEX', 'ORG_NAME', 'ORG_URL'] },
  cie: { required: ['ENTITY_ID', 'PRIVATE_KEY', 'CERT', 'IDP_METADATA'], optional: ['LEVEL', 'ATTRIBUTE_INDEX', 'ORG_NAME', 'ORG_URL'] },
  digid: { required: ['ISSUER', 'CLIENT_ID', 'CLIENT_SECRET (or SIGNING_KEY)'], optional: ['SCOPE', 'ACR', 'BIRTHDATE_CLAIM', 'SUBJECT_CLAIM', 'AUTH_METHOD'] },
  freja: { required: ['CLIENT_ID', 'CLIENT_SECRET (or SIGNING_KEY)'], optional: ['ISSUER', 'AUTH_METHOD'] },
};

export { envName };
