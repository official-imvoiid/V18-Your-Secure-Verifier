import 'package:flutter_test/flutter_test.dart';
import 'package:v18/protocol/deep_links.dart';

void main() {
  final debugList = ServerAllowlist.forBuild(debug: true);
  final releaseList = ServerAllowlist.forBuild(debug: false);

  group('server allowlist (PROTOCOL 3.10)', () {
    test('debug build allows the dev servers and the production placeholder', () {
      expect(debugList.normalize('http://localhost:8080'), 'http://localhost:8080');
      expect(debugList.normalize('http://10.0.2.2:8080'), 'http://10.0.2.2:8080');
      expect(debugList.normalize(productionServerUrl), productionServerUrl);
    });

    test('a trailing /v1 or / is accepted (protocol writes both forms)', () {
      expect(debugList.normalize('http://localhost:8080/v1'), 'http://localhost:8080');
      expect(debugList.normalize('http://localhost:8080/'), 'http://localhost:8080');
      expect(debugList.normalize('http://LOCALHOST:8080/v1/'), 'http://localhost:8080');
    });

    test('release build refuses the dev servers', () {
      expect(releaseList.normalize('http://localhost:8080'), isNull);
      expect(releaseList.normalize('http://10.0.2.2:8080'), isNull);
      expect(releaseList.normalize(productionServerUrl), productionServerUrl);
    });

    for (final bad in [
      'http://evil.test:8080',
      'https://localhost:8080',
      'http://localhost:8081',
      'http://localhost',
      'http://localhost:8080@evil.test',
      'http://evil.test@localhost:8080',
      'http://localhost:8080/other',
      'http://localhost:8080/v1?x=1',
      'http://localhost:8080#frag',
      'localhost:8080',
      '',
    ]) {
      test('refuses "$bad"', () => expect(debugList.normalize(bad), isNull));
    }
  });

  group('web origin', () {
    test('https origins are normalized', () {
      expect(normalizeWebOrigin('https://Example-Site.com', debug: false), 'https://example-site.com');
      expect(normalizeWebOrigin('https://a.test:443/', debug: false), 'https://a.test');
      expect(normalizeWebOrigin('https://a.test:8443', debug: false), 'https://a.test:8443');
    });
    test('http only for local test sites in debug builds', () {
      expect(normalizeWebOrigin('http://localhost:3000', debug: true), 'http://localhost:3000');
      expect(normalizeWebOrigin('http://localhost:3000', debug: false), isNull);
      expect(normalizeWebOrigin('http://example.com', debug: true), isNull);
    });
    test('paths, queries, user info and other schemes are refused', () {
      expect(normalizeWebOrigin('https://a.test/page', debug: true), isNull);
      expect(normalizeWebOrigin('https://a.test?x', debug: true), isNull);
      expect(normalizeWebOrigin('https://u@a.test', debug: true), isNull);
      expect(normalizeWebOrigin('javascript:alert(1)', debug: true), isNull);
      expect(normalizeWebOrigin('ftp://a.test', debug: true), isNull);
    });
  });

  group('v18://verify (PROTOCOL 3.8)', () {
    const session = 'AbCdEfGhIjKlMnOpQrStUv';
    String link({String? server = 'http%3A%2F%2Flocalhost%3A8080', String origin = 'http%3A%2F%2Flocalhost%3A3000', String minAge = '18', String challenge = 'abc123', String s = session}) =>
        'v18://verify?session=$s&origin=$origin&challenge=$challenge&minAge=$minAge'
        '${server == null ? '' : '&server=$server'}';

    test('parses a good link', () {
      final l = parseDeepLink(link(), allowlist: debugList, debug: true) as VerifyLink;
      expect(l.sessionId, session);
      expect(l.origin, 'http://localhost:3000');
      expect(l.challenge, 'abc123');
      expect(l.minAge, 18);
      expect(l.server, 'http://localhost:8080');
      expect(l.displayHost, 'localhost');
    });

    test('url-encoded server with /v1 is accepted', () {
      final l = parseDeepLink(link(server: 'http%3A%2F%2F10.0.2.2%3A8080%2Fv1'),
          allowlist: debugList, debug: true) as VerifyLink;
      expect(l.server, 'http://10.0.2.2:8080');
    });

    test('no server= uses the app default', () {
      final l = parseDeepLink(link(server: null),
          allowlist: debugList, defaultServer: 'http://10.0.2.2:8080', debug: true) as VerifyLink;
      expect(l.server, 'http://10.0.2.2:8080');
    });

    test('a server not on the allowlist is refused', () {
      expect(
          () => parseDeepLink(link(server: 'https%3A%2F%2Fevil.test'), allowlist: debugList, debug: true),
          throwsA(isA<DeepLinkError>().having((e) => e.serverNotAllowed, 'serverNotAllowed', true)));
    });

    test('release build refuses the dev server in a link', () {
      expect(() => parseDeepLink(link(), allowlist: releaseList, debug: false),
          throwsA(isA<DeepLinkError>()));
    });

    test('bad session, origin, challenge or age are refused', () {
      expect(() => parseDeepLink(link(s: 'short'), allowlist: debugList, debug: true),
          throwsA(isA<DeepLinkError>()));
      expect(() => parseDeepLink(link(origin: 'https%3A%2F%2Fa.test%2Fpath'), allowlist: debugList, debug: true),
          throwsA(isA<DeepLinkError>()));
      expect(() => parseDeepLink(link(challenge: 'a%0Ab'), allowlist: debugList, debug: true),
          throwsA(isA<DeepLinkError>()));
      expect(() => parseDeepLink(link(challenge: ''), allowlist: debugList, debug: true),
          throwsA(isA<DeepLinkError>()));
      expect(() => parseDeepLink(link(minAge: 'abc'), allowlist: debugList, debug: true),
          throwsA(isA<DeepLinkError>()));
      expect(() => parseDeepLink(link(minAge: '0'), allowlist: debugList, debug: true),
          throwsA(isA<DeepLinkError>()));
    });

    test('other schemes and hosts are refused', () {
      expect(() => parseDeepLink('https://example.com', allowlist: debugList),
          throwsA(isA<DeepLinkError>()));
      expect(() => parseDeepLink('v18://pay?x=1', allowlist: debugList),
          throwsA(isA<DeepLinkError>()));
    });
  });

  group('v18://link (PROTOCOL 3.9)', () {
    test('parses a good link', () {
      final l = parseDeepLink(
          'v18://link?id=lnk_0123456789abcdefghij&server=http%3A%2F%2Flocalhost%3A8080',
          allowlist: debugList) as LinkApprovalLink;
      expect(l.linkId, 'lnk_0123456789abcdefghij');
      expect(l.server, 'http://localhost:8080');
    });

    test('needs a server and a long enough id', () {
      expect(() => parseDeepLink('v18://link?id=lnk_0123456789abcdefghij', allowlist: debugList),
          throwsA(isA<DeepLinkError>()));
      expect(
          () => parseDeepLink('v18://link?id=x&server=http%3A%2F%2Flocalhost%3A8080',
              allowlist: debugList),
          throwsA(isA<DeepLinkError>()));
    });
  });
}
