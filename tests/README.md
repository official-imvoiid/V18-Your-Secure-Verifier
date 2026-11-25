# V18 tests

Every part of V18 has its own unit tests next to its code. This folder adds **product tests**:
they start the real, built V18 server and check whole journeys with real cryptography and the real
website libraries, the way the finished product works.

## Run everything

From the project folder, after `npm run build`:

```
npm run test:all
```

This runs every suite one after another and prints one table: server, login connectors, the Node
and Python website libraries, the widget, the demo site, the country catalog, the Windows app, the
Android app (only if Flutter is installed) and the product tests below.

## Product tests (`tests/product/`)

```
npm run test:product
```

| File | What it proves |
|------|----------------|
| `1-production.test.mjs` | The server in **production mode**, exactly as deployed. Test identities are refused, no ticket is signed without an age card and its device signature, challenges work once, security headers are sent, only widget endpoints are open to any website, a website cannot start a QR hand-off for another site, signing keys stay encrypted, and request contents never reach the log. |
| `2-user-journeys.test.mjs` | Whole journeys. An adult gets an age card and a one-time ticket that a website accepts once. The ticket fails on another site, for another visit, or for a 21+ site. A changed ticket is refused. The Python library agrees. Under-18s get no card. The QR hand-off delivers the ticket once. The PC gets its own card through a device link. A stolen card ID is useless. A deleted card is dead. Nothing that identifies the person is stored. |

The journeys run the server in dev mode only so that a **test identity** (`test_dev`) can stand in
for a real ID document. Real documents cannot be used in automated tests. Everything after the
age card (keys, blind signatures, device signatures, tickets, website checks) is the real product
path. Each run uses its own port and its own empty data folder, which is deleted afterwards.

## What these tests cannot cover

- **Reading a real passport or ID-card chip:** this needs a real Android phone with NFC.
- **Real government and bank logins:** each provider requires the operator to register first.
- **Real phone wallet IDs:** these need a wallet app holding a real digital ID.
