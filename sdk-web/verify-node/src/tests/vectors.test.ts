// Shared test vectors: the Python library runs the same file (sdk-web/test-vectors/v1-tickets.json).
import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { V18Verifier, JwksKeyStore } from '../index.js';

const file = path.resolve(__dirname, '../../../test-vectors/v1-tickets.json');
const vectors = JSON.parse(fs.readFileSync(file, 'utf8'));

describe('@v18/verify: shared v1 test vectors', () => {
  const keyStore = new JwksKeyStore();
  keyStore.setJwks(vectors.jwks);
  const verifier = new V18Verifier({ keyStore, origin: vectors.origin, clock: () => vectors.now * 1000 });

  for (const c of vectors.cases) {
    it(`${c.name} -> ${c.expect}`, async () => {
      const r = await verifier.verifyTicket(c.ticket, { expectedChallenge: vectors.challenge, minAge: c.minAge ?? 18 });
      assert.equal(r.valid ? 'VALID' : r.code, c.expect, r.valid ? '' : r.error);
      if (r.valid && c.minAgeOut) assert.equal(r.ticket.minAge, c.minAgeOut);
    });
  }
});
