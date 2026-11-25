import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { allowedServerOrigins, defaultServer, normalizeServer } from '../src/shared/allowlist.js';
import { DeepLinkError, findDeepLinkArg, parseDeepLink } from '../src/shared/deeplink.js';
import { displayOrigin, parseWebOrigin } from '../src/shared/origin.js';

const opts = { debug: true, defaultServer: 'http://localhost:8080/v1' };
const enc = encodeURIComponent;
const SID = 'pair_0123456789abcdefABCDEF';
const verify = (extra: Record<string, string> = {}) => {
  const p = { session: SID, origin: 'https://example-site.test', challenge: 'chal-0123456789', minAge: '18', server: 'http://localhost:8080/v1', ...extra };
  return 'v18://verify?' + Object.entries(p).map(([k, v]) => `${k}=${enc(v)}`).join('&');
};
const code = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return e instanceof DeepLinkError ? e.code : 'OTHER';
  }
  return 'NONE';
};

describe('server allowlist (PROTOCOL 3.10)', () => {
  it('accepts the debug server with or without /v1', () => {
    for (const s of ['http://localhost:8080', 'http://localhost:8080/', 'http://localhost:8080/v1', 'http://localhost:8080/v1/']) {
      assert.ok(normalizeServer(s, true), s);
    }
    assert.equal(normalizeServer('http://localhost:8080', true), 'http://localhost:8080/v1');
  });
  it('refuses the Android emulator address on Windows (PROTOCOL 4b item 9)', () => {
    assert.equal(normalizeServer('http://10.0.2.2:8080', true), null);
    assert.deepEqual(allowedServerOrigins(true), ['http://localhost:8080', 'https://api.v18.example']);
  });
  it('accepts the production placeholder in every build', () => {
    assert.equal(normalizeServer('https://api.v18.example', false), 'https://api.v18.example/v1');
    assert.equal(normalizeServer('https://api.v18.example', true), 'https://api.v18.example/v1');
  });
  it('refuses localhost in release builds', () => {
    assert.equal(normalizeServer('http://localhost:8080', false), null);
    assert.deepEqual(allowedServerOrigins(false), ['https://api.v18.example']);
  });
  it('refuses look-alikes and tricks', () => {
    for (const s of [
      'http://localhost:8081',
      'https://localhost:8080',
      'http://127.0.0.1:8080',
      'http://localhost:8080.evil.test',
      'http://user@localhost:8080',
      'http://localhost:8080/v2',
      'http://localhost:8080/v1/../admin',
      'http://localhost:8080/v1?x=1',
      'http://localhost:8080#x',
      'https://api.v18.example.evil.test',
      'javascript:alert(1)',
      '',
    ]) {
      assert.equal(normalizeServer(s, true), null, s);
    }
  });
  it('has a sensible default', () => {
    assert.equal(defaultServer(true), 'http://localhost:8080/v1');
    assert.equal(defaultServer(false), 'https://api.v18.example/v1');
  });
});

describe('web origins', () => {
  it('accepts bare https origins and http loopback', () => {
    assert.equal(parseWebOrigin('https://example-site.test'), 'https://example-site.test');
    assert.equal(parseWebOrigin('https://example-site.test:8443'), 'https://example-site.test:8443');
    assert.equal(parseWebOrigin('http://localhost:3000'), 'http://localhost:3000');
  });
  it('refuses paths, queries, user names, http on the internet, and other schemes', () => {
    for (const o of ['https://a.test/path', 'https://a.test?x', 'https://a.test#x', 'https://u@a.test', 'http://a.test', 'ftp://a.test', 'https://a.test:443', 'a.test', 'file:///c:/x']) {
      assert.equal(parseWebOrigin(o), null, o);
    }
  });
  it('shows punycode for look-alike hosts and flags http', () => {
    assert.equal(displayOrigin('https://xn--exmple-cua.test'), 'xn--exmple-cua.test');
    assert.match(displayOrigin('http://localhost:3000'), /not secure/);
  });
});

describe('deep links (PROTOCOL 3.8, 3.9)', () => {
  it('parses a verify link', () => {
    const l = parseDeepLink(verify(), opts);
    assert.deepEqual(l, { kind: 'verify', sessionId: SID, origin: 'https://example-site.test', challenge: 'chal-0123456789', minAge: 18, server: 'http://localhost:8080/v1', serverGiven: true });
  });
  it('accepts the trailing slash Windows sometimes adds', () => {
    assert.equal(parseDeepLink(verify().replace('v18://verify?', 'v18://verify/?'), opts).kind, 'verify');
  });
  it('uses the default server when server= is missing (the current server leaves it out)', () => {
    const raw = verify().replace(/&server=[^&]*/, '');
    const l = parseDeepLink(raw, opts);
    assert.ok(l.kind === 'verify' && l.server === 'http://localhost:8080/v1' && l.serverGiven === false);
  });
  it('refuses a server that is not on the allowlist', () => {
    assert.equal(code(() => parseDeepLink(verify({ server: 'https://evil.test/v1' }), opts)), 'SERVER_NOT_ALLOWED');
    assert.equal(code(() => parseDeepLink(verify(), { ...opts, debug: false })), 'SERVER_NOT_ALLOWED');
  });
  it('refuses bad origins, sessions, challenges and ages', () => {
    assert.equal(code(() => parseDeepLink(verify({ origin: 'https://a.test/login' }), opts)), 'BAD_ORIGIN');
    assert.equal(code(() => parseDeepLink(verify({ origin: 'http://a.test' }), opts)), 'BAD_ORIGIN');
    assert.equal(code(() => parseDeepLink(verify({ session: 'short' }), opts)), 'BAD_SESSION');
    assert.equal(code(() => parseDeepLink(verify({ session: 'has spaces in it ok?' }), opts)), 'BAD_SESSION');
    assert.equal(code(() => parseDeepLink(verify({ challenge: 'has space 12345' }), opts)), 'BAD_CHALLENGE');
    assert.equal(code(() => parseDeepLink(verify({ minAge: '18.5' }), opts)), 'BAD_MIN_AGE');
    assert.equal(code(() => parseDeepLink(verify({ minAge: '0' }), opts)), 'BAD_MIN_AGE');
  });
  it('refuses duplicate parameters (no "which one wins" games)', () => {
    assert.equal(code(() => parseDeepLink(verify() + '&origin=' + enc('https://evil.test'), opts)), 'DUPLICATE_PARAM');
  });
  it('refuses other schemes, paths and unknown actions', () => {
    assert.equal(code(() => parseDeepLink(verify().replace('v18:', 'https:'), opts)), 'BAD_LINK');
    assert.equal(code(() => parseDeepLink(verify().replace('v18://verify?', 'v18://verify/x?'), opts)), 'BAD_LINK');
    assert.equal(code(() => parseDeepLink('v18://wipe?all=1', opts)), 'UNKNOWN_ACTION');
    assert.equal(code(() => parseDeepLink('v18://verify?' + 'a'.repeat(5000), opts)), 'BAD_LINK');
  });
  it('parses a device link', () => {
    const l = parseDeepLink(`v18://link?id=lnk_0123456789abcdef&server=${enc('http://localhost:8080')}`, opts);
    assert.deepEqual(l, { kind: 'link', linkId: 'lnk_0123456789abcdef', server: 'http://localhost:8080/v1' });
  });
  it('finds the link in a Windows command line', () => {
    assert.equal(findDeepLinkArg(['C:\\V18\\V18.exe', '--allow-file-access', verify()]), verify());
    assert.equal(findDeepLinkArg(['C:\\V18\\V18.exe']), null);
  });
  it('takes test-only extra servers only when asked', () => {
    const raw = verify({ server: 'http://127.0.0.1:5555/v1' });
    assert.equal(code(() => parseDeepLink(raw, opts)), 'SERVER_NOT_ALLOWED');
    assert.equal(parseDeepLink(raw, { ...opts, extraServerOrigins: ['http://127.0.0.1:5555'] }).kind, 'verify');
  });
});
