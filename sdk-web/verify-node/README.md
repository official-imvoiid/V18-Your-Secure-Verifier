# @v18/verify (Node.js)

Check V18 age tickets on your website's **server**. It uses only Node's built-in `crypto`, and it
applies every rule in V18's protocol (PROTOCOL.md section 3.7): the V18 seal, your site's origin,
your one-time challenge, the age, the time window, and a replay cache.

```js
const { V18Verifier, ChallengeStore } = require('@v18/verify');

const verifier = new V18Verifier({ serverUrl: 'https://api.v18.example', origin: 'https://shop.example', minAge: 18 });
const challenges = new ChallengeStore();

// POST /v18/challenge
res.json(challenges.create(visitId));

// POST /v18/verify  {ticket}
const result = await verifier.verifyTicket(req.body.ticket, { expectedChallenge: challenges.checker(visitId) });
if (result.valid) { /* the visitor is 18+ */ } else { /* result.code, result.error */ }
```

Needs Node 20 or newer. The full guide for website owners is `docs/web/INTEGRATION.md`.
Licence: UNLICENSED (no licence chosen yet, see LICENSE).
