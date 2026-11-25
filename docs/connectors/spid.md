# SPID, Italy: `spid`

**What the person does:** picks their SPID provider (Poste, Aruba, InfoCert, ...) and logs in.
V18 gets the birth date and the fiscal code, decides 18+, and keeps nothing.

**Assurance:** high (national scheme). V18 asks for level SpidL2 or higher.

## Why SAML
SPID's long-standing interface is SAML 2.0 with AgID's technical rules. (There is also a newer
SPID/CIE OpenID Connect profile, but it needs OpenID Federation trust chains.)
`@node-saml/node-saml` checks the responses, and `xml-crypto` signs the metadata.

## What you must register for
- Join SPID as a **private service provider** with AgID (convention), or go through a SPID
  **aggregator**. AgID publishes your signed metadata to the identity providers.
- Make an RSA key (2048+ bits) and a certificate in the form AgID's rules ask for.
- Download the **identity providers' metadata** from AgID's registry (registry.spid.gov.it) and
  save it as files.
- Your ACS (callback) URL: `https://<server>/v1/connect/spid/callback`. It receives an
  **HTTP POST**.

## Settings
| Variable | Value |
|----------|-------|
| `V18_CONNECTOR_SPID_ENTITY_ID` | Your SP entity ID (a URL you control) |
| `V18_CONNECTOR_SPID_PRIVATE_KEY` | SP private key (PEM text or path) |
| `V18_CONNECTOR_SPID_CERT` | SP certificate (PEM) |
| `V18_CONNECTOR_SPID_IDP_METADATA` | IdP metadata file paths (or XML), separated by `;` or new lines |
| `V18_CONNECTOR_SPID_LEVEL` | Optional. Default `https://www.spid.gov.it/SpidL2` |
| `V18_CONNECTOR_SPID_ATTRIBUTE_INDEX` | Optional. Default `0` |
| `V18_CONNECTOR_SPID_ORG_NAME` / `_ORG_URL` | Optional. For the metadata |

## Test environment
AgID offers a validator and a demo IdP (spid-saml-check, demo.spid.gov.it). They were not used
here. Use them to check the request and metadata before applying.

## How it works and what is read
- The person picks an IdP: `connector.identityProviders()` lists them, and the chosen
  `entityId` is passed as `idp`.
- AuthnRequest over **HTTP-Redirect**, signed RSA-SHA256: `ForceAuthn`, Issuer with
  `NameQualifier` and `Format=entity`, NameIDPolicy `transient`, `RequestedAuthnContext`
  minimum SpidL2, `AssertionConsumerServiceURL` with HTTP-POST, `AttributeConsumingServiceIndex`.
- Response over HTTP-POST. Checked: the assertion signature (the IdP certificate from its
  metadata), `InResponseTo` (this login only), audience, time limits, `Recipient` = our ACS URL,
  the IdP's issuer, a level at least as high as asked, and no replays.
- Read: `dateOfBirth` (YYYY-MM-DD) and **`fiscalNumber`** (`TINIT-...`) as the subject. The
  fiscal number is the same at every SPID provider, so one person gets one nullifier. `spidCode`,
  `name`, `familyName` and the rest are dropped.
- `metadata(acsUrl)` makes signed SP metadata, asking only for `dateOfBirth` and `fiscalNumber`.
  **Before you submit it,** add the `ContactPerson` / SPID extension elements that AgID's rules
  ask of private providers. They are not generated.

## Sources read
docs.italia.it/italia/spid/spid-regole-tecniche: single sign-on (AuthnRequest, Response),
attributes, metadata, registry.
