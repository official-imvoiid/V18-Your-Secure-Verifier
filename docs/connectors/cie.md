# CIE (Entra con CIE), Italy: `cie`

**What the person does:** logs in with their electronic identity card (CIE), using the CieID app
or a card reader. V18 gets the birth date and fiscal code, decides 18+, and keeps nothing.

**Assurance:** high. CIE always answers with level `SpidL3` (eIDAS high).

## Why SAML
"Entra con CIE" offers SAML 2.0 or OIDC (OpenID Federation). SAML lets CIE share code with SPID
(same request rules). It is built on `@node-saml/node-saml` and `xml-crypto`.

## What you must register for
- Federation through the **"Entra con CIE" federation portal** (Ministry of the Interior /
  Poligrafico). It is open to **public and private** service providers. Choose the SAML protocol.
- Upload your SP metadata (`connector.metadata(acsUrl)`). For CIE it asks for the eIDAS minimum
  dataset (`name`, `familyName`, `dateOfBirth`, `fiscalNumber`), because CIE requires that.
  V18 still reads only `dateOfBirth` and `fiscalNumber`.
- Download CIE's IdP metadata:
  - Pre-production: `https://preproduzione.idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata`
  - Production: `https://idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata`
- ACS (callback) URL: `https://<server>/v1/connect/cie/callback`. It receives an **HTTP POST**.

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_CIE_ENTITY_ID` | Your SP entity ID |
| `V18_CONNECTOR_CIE_PRIVATE_KEY` | SP private key (PEM) |
| `V18_CONNECTOR_CIE_CERT` | SP certificate (PEM) |
| `V18_CONNECTOR_CIE_IDP_METADATA` | Path to the CIE IdP metadata file (pre-production or production) |
| `V18_CONNECTOR_CIE_LEVEL` | Optional. Default asks `SpidL2` (CIE answers `SpidL3` anyway) |

## Test environment
Pre-production, with the CieID **test** app and test cards. It needs federation, so it needs
sign-up.

## How it works and what is read
Same as [SPID](spid.md): a signed AuthnRequest over HTTP-Redirect, and a signed assertion over
HTTP-POST checked by node-saml plus V18's own checks (`Recipient`, level, issuer, replays).
Read: `dateOfBirth` (YYYY-MM-DD) and `fiscalNumber` (`TINIT-...`) as the subject.

## Sources read
docs.italia.it: CIE manuale operativo (federation, SAML or OIDC, public and private providers);
CIE manuale tecnico; "Regole tecniche CIE id SAML" (federazione, protocolli, binding).
