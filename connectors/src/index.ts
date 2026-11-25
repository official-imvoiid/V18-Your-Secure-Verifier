/**
 * @v18/connectors: government and bank login connectors for V18 (PROTOCOL.md 4d.4).
 *
 *   import { createRegistry } from '@v18/connectors';
 *   const registry = createRegistry(process.env);
 *   const c = registry.get('singpass');           // undefined when not configured
 *   const { authUrl, session } = await c.buildAuthUrl({ state, nonce, codeVerifier, redirectUri });
 *   // ...the provider redirects to the callback...
 *   const { over18, subject } = await c.handleCallback({ params, state, nonce, codeVerifier, redirectUri, session });
 *   // nullifier = HMAC-SHA256(V18_NULLIFIER_SECRET, c.id + "|" + subject); then forget `subject`.
 */
export * from './types.js';
export { createRegistry, createConnector, CONNECTOR_IDS, CONNECTOR_ENV, envName, type Registry, type ConnectorSummary } from './registry.js';
export { bankIdQrData, BANKID_PRODUCTION_API, BANKID_TEST_API } from './providers/bankid-se.js';
export { parseIdpMetadata, type IdentityProvider } from './saml.js';
export { isOver18, parseIsoDate, parseDayFirstDate, birthDateFromSwedishPersonalNumber, type BirthDate } from './age.js';
