/** TEST ONLY: shared assertions. */
import assert from 'node:assert/strict';
import { ConnectorError, type ConnectorErrorCode, type ConnectorResult } from '../../types.js';

/** The "discard everything else" rule: the result has exactly two keys and nothing hidden. */
export function assertOnlyAgeAndSubject(result: ConnectorResult, expected: { over18: boolean; subject: string }) {
  assert.deepEqual(Object.getOwnPropertyNames(result).sort(), ['over18', 'subject']);
  assert.deepEqual(Object.getOwnPropertySymbols(result), []);
  assert.equal(Object.getPrototypeOf(result), Object.prototype);
  assert.equal(result.over18, expected.over18);
  assert.equal(result.subject, expected.subject);
  assert.equal(typeof result.over18, 'boolean');
  assert.equal(typeof result.subject, 'string');
}

/** Awaits a promise that must fail with a ConnectorError with this code, and checks the error leaks nothing. */
export async function assertConnectorError(
  p: Promise<unknown>,
  code: ConnectorErrorCode,
  options: { providerCode?: string; mustNotContain?: string[] } = {},
): Promise<ConnectorError> {
  let caught: unknown;
  try {
    await p;
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof ConnectorError, `expected ConnectorError ${code}, got ${String(caught)}`);
  const err = caught as ConnectorError;
  assert.equal(err.code, code, `expected ${code}, got ${err.code} (${err.message}, ${err.providerCode})`);
  if (options.providerCode !== undefined) assert.equal(err.providerCode, options.providerCode);
  assert.equal((err as Error & { cause?: unknown }).cause, undefined, 'errors must not carry a cause');
  const everything = `${err.message}\n${err.stack}\n${JSON.stringify(err)}\n${String(err.providerCode)}`;
  for (const secret of options.mustNotContain ?? []) {
    assert.ok(!everything.includes(secret), `error text must not include personal data (${secret.length} chars)`);
  }
  return err;
}
