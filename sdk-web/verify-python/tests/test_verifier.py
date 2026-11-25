"""
Tests for v18_verify: every rule in PROTOCOL.md 3.7, positive and negative, plus the shared
test vectors in sdk-web/test-vectors/v1-tickets.json (real blind signatures from @cloudflare/blindrsa-ts).

All in one file because the root `npm run test:verify-python` script runs this file.
"""
import base64
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from v18_verify import (  # noqa: E402
    ChallengeStore,
    JwksKeyStore,
    MemoryReplayCache,
    V18Verifier,
    is_web_origin,
    normalize_server_url,
    verify_ticket,
)

ORIGIN = "https://example-site.test"
NOW = 1_762_700_000
CHAL = "a" * 64
VECTORS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "test-vectors", "v1-tickets.json"))


# ---------------------------------------------------------------- helpers

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64u_int(n: int) -> str:
    return b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


class SigningKey:
    def __init__(self, kid, min_age=18, nbf=NOW - 86_400, exp=NOW + 6 * 86_400, alg="RSABSSA-SHA384-PSS-Randomized", omit=()):
        self.kid = kid
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = self.private.public_key().public_numbers()
        self.jwk = {"kid": kid, "kty": "RSA", "n": b64u_int(nums.n), "e": b64u_int(nums.e), "use": "sig",
                    "alg": alg, "v18_min_age": min_age, "nbf": nbf, "exp": exp}
        for k in omit:
            del self.jwk[k]

    def ticket(self, body, salt_length=48, kid=None, hash_alg=None):
        msg = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        prepared = os.urandom(32) + msg  # RFC 9474 prepare (randomized): 32 random bytes, then the message
        h = hash_alg or hashes.SHA384()
        sig = self.private.sign(prepared, padding.PSS(mgf=padding.MGF1(h), salt_length=salt_length), h)
        return f"{kid or self.kid}.{b64u(prepared)}.{b64u(sig)}"


def payload(**over):
    p = {"v": 1, "ticketId": b64u(os.urandom(16)), "origin": ORIGIN, "challenge": CHAL,
         "minAge": 18, "iat": NOW, "expiresAt": NOW + 300}
    p.update(over)
    return p


def code(r):
    return "VALID" if r.valid else r.code


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture(scope="module")
def keys():
    return {
        "k18": SigningKey("v18-age18-20261109"),
        "k21": SigningKey("v18-age21-20261109", min_age=21),
        "attacker": SigningKey("v18-age18-20261109"),  # same kid, other private key
    }


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def verifier(keys, clock):
    store = JwksKeyStore()
    store.set_jwks({"keys": [keys["k18"].jwk, keys["k21"].jwk]})
    return V18Verifier(key_cache=store, origin=ORIGIN, clock=clock)


def single_key_verifier(k, now=NOW):
    store = JwksKeyStore()
    store.add_jwk(k.jwk)
    return V18Verifier(key_cache=store, origin=ORIGIN, clock=lambda: now)


# ---------------------------------------------------------------- positive

def test_valid_ticket_reports_key_threshold(verifier, keys):
    r = verifier.verify_ticket(keys["k18"].ticket(payload()), expected_challenge=CHAL)
    assert code(r) == "VALID"
    assert r.ticket.min_age == 18 and r.ticket.key_id == "v18-age18-20261109" and r.ticket.origin == ORIGIN
    assert bool(r) is True


def test_per_call_origin_overrides_default(verifier, keys):
    t = keys["k18"].ticket(payload(origin="http://localhost:3000"))
    assert code(verifier.verify_ticket(t, expected_origin="http://localhost:3000", expected_challenge=CHAL)) == "VALID"


# ---------------------------------------------------------------- rule 1

def test_rule1_unknown_key(verifier, keys):
    t = keys["k18"].ticket(payload(), kid="v18-age18-19990101")
    assert code(verifier.verify_ticket(t, expected_challenge=CHAL)) == "UNKNOWN_KEY"


def test_rule1_grace_period_599s_ok():
    k = SigningKey("v18-age18-grace", nbf=NOW - 7 * 86_400, exp=NOW - 599)
    assert code(single_key_verifier(k).verify_ticket(k.ticket(payload()), expected_challenge=CHAL)) == "VALID"


def test_rule1_expired_601s_refused():
    k = SigningKey("v18-age18-old", nbf=NOW - 7 * 86_400, exp=NOW - 601)
    assert code(single_key_verifier(k).verify_ticket(k.ticket(payload()), expected_challenge=CHAL)) == "KEY_EXPIRED"


def test_rule1_next_key_not_yet_valid():
    k = SigningKey("v18-age18-next", nbf=NOW + 3600, exp=NOW + 8 * 86_400)
    assert code(single_key_verifier(k).verify_ticket(k.ticket(payload()), expected_challenge=CHAL)) == "KEY_NOT_YET_VALID"


@pytest.mark.parametrize("bad", [{"omit": ("v18_min_age",)}, {"omit": ("nbf",)}, {"omit": ("exp",)}, {"alg": "PS384"}])
def test_rule1_unusable_jwks_keys_are_ignored(bad):
    k = SigningKey("v18-age18-bad", **bad)
    store = JwksKeyStore()
    assert store.set_jwks({"keys": [k.jwk]}) == 0
    with pytest.raises(ValueError):
        store.add_jwk(k.jwk)
    v = V18Verifier(key_cache=store, origin=ORIGIN, clock=lambda: NOW)
    assert code(v.verify_ticket(k.ticket(payload()), expected_challenge=CHAL)) == "UNKNOWN_KEY"


# ---------------------------------------------------------------- rule 2

def test_rule2_changed_signature(verifier, keys):
    kid, p, s = keys["k18"].ticket(payload()).split(".")
    sig = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    sig[10] ^= 1
    assert code(verifier.verify_ticket(f"{kid}.{p}.{b64u(bytes(sig))}", expected_challenge=CHAL)) == "INVALID_SIGNATURE"


def test_rule2_changed_message(verifier, keys):
    kid, p, s = keys["k18"].ticket(payload(origin="https://evil.test")).split(".")
    prepared = base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))
    edited = prepared[:32] + prepared[32:].replace(b"https://evil.test", b"https://good.test")
    assert code(verifier.verify_ticket(f"{kid}.{b64u(edited)}.{s}", expected_challenge=CHAL)) == "INVALID_SIGNATURE"


def test_rule2_other_private_key_same_kid(verifier, keys):
    assert code(verifier.verify_ticket(keys["attacker"].ticket(payload()), expected_challenge=CHAL)) == "INVALID_SIGNATURE"


def test_rule2_wrong_salt_or_hash(verifier, keys):
    assert code(verifier.verify_ticket(keys["k18"].ticket(payload(), salt_length=32), expected_challenge=CHAL)) == "INVALID_SIGNATURE"
    t = keys["k18"].ticket(payload(), salt_length=32, hash_alg=hashes.SHA256())
    assert code(verifier.verify_ticket(t, expected_challenge=CHAL)) == "INVALID_SIGNATURE"


# ---------------------------------------------------------------- rule 3

@pytest.mark.parametrize("v", ["missing", 2, "1", True, None])
def test_rule3_version_must_be_1(verifier, keys, v):
    p = payload()
    if v == "missing":
        del p["v"]
    else:
        p["v"] = v
    assert code(verifier.verify_ticket(keys["k18"].ticket(p), expected_challenge=CHAL)) == "UNSUPPORTED_VERSION"


# ---------------------------------------------------------------- rule 4

@pytest.mark.parametrize("o", ["https://evil.test", "example-site.test", ORIGIN + "/", ORIGIN + ":8443", "http://example-site.test"])
def test_rule4_origin_must_match_exactly(verifier, keys, o):
    assert code(verifier.verify_ticket(keys["k18"].ticket(payload(origin=o)), expected_challenge=CHAL)) == "ORIGIN_MISMATCH"


def test_rule4_bad_expected_origin_is_config_error(verifier, keys):
    t = keys["k18"].ticket(payload(origin="localhost:3000"))
    assert code(verifier.verify_ticket(t, expected_origin="localhost:3000", expected_challenge=CHAL)) == "CONFIG_ERROR"
    with pytest.raises(ValueError):
        V18Verifier(origin="https://example.com/")


def test_is_web_origin():
    for good in ["https://example.com", "http://localhost:3000", "http://127.0.0.1:8080", "https://a.b.c:8443"]:
        assert is_web_origin(good), good
    for bad in ["example.com", "https://example.com/", "https://example.com/x", "https://Example.com",
                "https://example.com:443", "http://example.com:80", "ftp://example.com", "https://u@example.com", "", None]:
        assert not is_web_origin(bad), bad


# ---------------------------------------------------------------- rule 5

def test_rule5_other_challenge(verifier, keys):
    assert code(verifier.verify_ticket(keys["k18"].ticket(payload(challenge="b" * 64)), expected_challenge=CHAL)) == "CHALLENGE_MISMATCH"


def test_rule5_challenge_required(verifier, keys):
    t = keys["k18"].ticket(payload())
    assert code(verifier.verify_ticket(t)) == "CHALLENGE_REQUIRED"
    assert code(verifier.verify_ticket(t, expected_challenge="")) == "CHALLENGE_REQUIRED"


def test_rule5_challenge_store_single_use(verifier, keys, clock):
    store = ChallengeStore(clock=clock)
    ch = store.create("visit-1").challenge
    t1 = keys["k18"].ticket(payload(challenge=ch))
    t2 = keys["k18"].ticket(payload(challenge=ch))
    assert code(verifier.verify_ticket(t1, expected_challenge=store.checker("visit-1"))) == "VALID"
    assert code(verifier.verify_ticket(t2, expected_challenge=store.checker("visit-1"))) == "CHALLENGE_MISMATCH"


def test_rule5_challenge_belongs_to_one_visit(verifier, keys, clock):
    store = ChallengeStore(clock=clock)
    ch = store.create("visit-A").challenge
    store.create("visit-B")
    t = keys["k18"].ticket(payload(challenge=ch))
    assert code(verifier.verify_ticket(t, expected_challenge=store.checker("visit-B"))) == "CHALLENGE_MISMATCH"


# ---------------------------------------------------------------- rule 6

def test_rule6_payload_cannot_raise_the_age(verifier, keys):
    t = keys["k18"].ticket(payload(minAge=21))
    assert code(verifier.verify_ticket(t, expected_challenge=CHAL, min_age=21)) == "AGE_INSUFFICIENT"


def test_rule6_key_threshold_decides(verifier, keys):
    r = verifier.verify_ticket(keys["k21"].ticket(payload(minAge=0)), expected_challenge=CHAL, min_age=18)
    assert code(r) == "VALID" and r.ticket.min_age == 21
    assert code(verifier.verify_ticket(keys["k21"].ticket(payload()), expected_challenge=CHAL, min_age=21)) == "VALID"


# ---------------------------------------------------------------- rule 7

def test_rule7_window_edges_pass(verifier, keys, clock):
    clock.t = NOW - 60
    assert code(verifier.verify_ticket(keys["k18"].ticket(payload()), expected_challenge=CHAL)) == "VALID"
    clock.t = NOW + 360
    assert code(verifier.verify_ticket(keys["k18"].ticket(payload()), expected_challenge=CHAL)) == "VALID"


def test_rule7_from_the_future(verifier, keys, clock):
    clock.t = NOW - 61
    assert code(verifier.verify_ticket(keys["k18"].ticket(payload()), expected_challenge=CHAL)) == "TICKET_NOT_YET_VALID"


def test_rule7_expired(verifier, keys, clock):
    clock.t = NOW + 361
    assert code(verifier.verify_ticket(keys["k18"].ticket(payload()), expected_challenge=CHAL)) == "TICKET_EXPIRED"


def test_rule7_lifetime(verifier, keys):
    assert code(verifier.verify_ticket(keys["k18"].ticket(payload(expiresAt=NOW + 301)), expected_challenge=CHAL)) == "TICKET_LIFETIME_INVALID"
    assert code(verifier.verify_ticket(keys["k18"].ticket(payload(expiresAt=NOW - 1)), expected_challenge=CHAL)) == "TICKET_LIFETIME_INVALID"
    assert code(verifier.verify_ticket(keys["k18"].ticket(payload(expiresAt=NOW + 300)), expected_challenge=CHAL)) == "VALID"


# ---------------------------------------------------------------- rule 8

def test_rule8_replay(verifier, keys):
    t = keys["k18"].ticket(payload())
    assert code(verifier.verify_ticket(t, expected_challenge=CHAL)) == "VALID"
    assert code(verifier.verify_ticket(t, expected_challenge=CHAL)) == "REPLAY_DETECTED"


def test_rule8_reused_ticket_id(verifier, keys):
    p = payload()
    assert code(verifier.verify_ticket(keys["k18"].ticket(p), expected_challenge=CHAL)) == "VALID"
    assert code(verifier.verify_ticket(keys["k18"].ticket(p), expected_challenge=CHAL)) == "REPLAY_DETECTED"


def test_rule8_refused_ticket_keeps_its_id(verifier, keys):
    p = payload()
    assert code(verifier.verify_ticket(keys["k18"].ticket(p), expected_challenge="c" * 64)) == "CHALLENGE_MISMATCH"
    assert code(verifier.verify_ticket(keys["k18"].ticket(p), expected_challenge=CHAL)) == "VALID"


def test_rule8_memory_cache_forgets_later():
    c = Clock()
    cache = MemoryReplayCache(clock=c)
    assert cache.check_and_remember("t1", NOW + 10) is True
    assert cache.check_and_remember("t1", NOW + 10) is False
    c.t = NOW + 11
    assert cache.check_and_remember("t1", NOW + 20) is True


# ---------------------------------------------------------------- format

def test_format_errors(verifier, keys):
    t = keys["k18"].ticket(payload())
    kid, p, s = t.split(".")
    for bad in ["", "abc", f"{kid}.{p}", f"{t}.x", f"{kid}.{p}=.{s}", f"{kid}.{p}.{s}+/", f"{kid}.{p}.{s}!", "x" * 9000, 12345, None]:
        assert code(verifier.verify_ticket(bad, expected_challenge=CHAL)) == "INVALID_FORMAT", str(bad)[:40]


@pytest.mark.parametrize("body", [
    b"not json", b"\xff\xfe{}", b"[1,2,3]", b'\xef\xbb\xbf{"v":1}', b'{"v":1,"iat":NaN}',
    {"short_ticket_id": True}, {"8_byte_ticket_id": True}, {"iat": "1762700000"}, {"expiresAt": NOW + 0.5},
    {"origin": 42}, {"challenge": None},
])
def test_malformed_payloads(verifier, keys, body):
    if isinstance(body, dict):
        over = dict(body)
        if over.pop("short_ticket_id", None):
            over["ticketId"] = "short"
        if over.pop("8_byte_ticket_id", None):
            over["ticketId"] = b64u(os.urandom(8))
        body = payload(**over)
    assert code(verifier.verify_ticket(keys["k18"].ticket(body), expected_challenge=CHAL)) == "MALFORMED_PAYLOAD"


# ---------------------------------------------------------------- JWKS over HTTP (mock V18 server)

class MockV18:
    def __init__(self, jwks):
        self.jwks, self.status, self.hits = jwks, 200, 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path != "/v1/keys":
                    self.send_response(404)
                    self.end_headers()
                    return
                outer.hits += 1
                body = json.dumps(outer.jwks if outer.status == 200 else {"error": "down"}).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def mock_server(keys):
    m = MockV18({"keys": [keys["k18"].jwk]})
    yield m
    m.close()


def test_jwks_fetch_and_verify(mock_server, keys):
    v = V18Verifier(server_url=mock_server.url + "/v1/", origin=ORIGIN, clock=lambda: NOW)
    assert code(v.verify_ticket(keys["k18"].ticket(payload()), expected_challenge=CHAL)) == "VALID"
    assert mock_server.hits == 1


def test_jwks_rotation_refetch_is_rate_limited(mock_server, keys):
    c = Clock()
    store = JwksKeyStore(server_url=mock_server.url, clock=c)
    v = V18Verifier(key_cache=store, origin=ORIGIN, clock=c)
    assert code(v.verify_ticket(keys["k18"].ticket(payload()), expected_challenge=CHAL)) == "VALID"
    mock_server.jwks = {"keys": [keys["k18"].jwk, keys["k21"].jwk]}
    c.t += 10
    assert code(v.verify_ticket(keys["k21"].ticket(payload()), expected_challenge=CHAL)) == "UNKNOWN_KEY"
    assert mock_server.hits == 1
    c.t += 21
    assert code(v.verify_ticket(keys["k21"].ticket(payload(iat=NOW + 31, expiresAt=NOW + 331)), expected_challenge=CHAL)) == "VALID"
    assert mock_server.hits == 2


def test_jwks_removed_key_is_dropped(mock_server, keys):
    c = Clock()
    store = JwksKeyStore(server_url=mock_server.url, cache_ttl_seconds=60, clock=c)
    v = V18Verifier(key_cache=store, origin=ORIGIN, clock=c)
    assert code(v.verify_ticket(keys["k18"].ticket(payload()), expected_challenge=CHAL)) == "VALID"
    mock_server.jwks = {"keys": [keys["k21"].jwk]}
    c.t += 61
    assert code(v.verify_ticket(keys["k18"].ticket(payload(iat=NOW + 61, expiresAt=NOW + 361)), expected_challenge=CHAL)) == "UNKNOWN_KEY"


def test_jwks_unavailable(mock_server, keys):
    mock_server.status = 503
    v = V18Verifier(server_url=mock_server.url, origin=ORIGIN, clock=lambda: NOW)
    assert code(v.verify_ticket(keys["k18"].ticket(payload()), expected_challenge=CHAL)) == "KEYS_UNAVAILABLE"


def test_jwks_cached_key_survives_failed_refresh(mock_server, keys):
    c = Clock()
    store = JwksKeyStore(server_url=mock_server.url, cache_ttl_seconds=60, clock=c)
    v = V18Verifier(key_cache=store, origin=ORIGIN, clock=c)
    assert code(v.verify_ticket(keys["k18"].ticket(payload()), expected_challenge=CHAL)) == "VALID"
    mock_server.status = 500
    c.t += 120
    assert code(v.verify_ticket(keys["k18"].ticket(payload(iat=NOW + 120, expiresAt=NOW + 420)), expected_challenge=CHAL)) == "VALID"


def test_verify_ticket_helper(mock_server):
    import time as _time
    now = int(_time.time())
    live = SigningKey("v18-age18-live", nbf=now - 100, exp=now + 86_400)
    mock_server.jwks = {"keys": [live.jwk]}
    t = live.ticket(payload(iat=now, expiresAt=now + 300))
    assert code(verify_ticket(t, expected_origin=ORIGIN, expected_challenge=CHAL, server_url=mock_server.url)) == "VALID"


def test_normalize_server_url():
    assert normalize_server_url("http://localhost:8080/v1/") == "http://localhost:8080"
    assert normalize_server_url("http://localhost:8080/") == "http://localhost:8080"


# ---------------------------------------------------------------- ChallengeStore

def test_challenge_store_basics():
    s = ChallengeStore()
    a = s.create("v")
    b = s.create("v")
    assert len(a.challenge) == 64 and all(ch in "0123456789abcdef" for ch in a.challenge)
    assert a.challenge != b.challenge
    assert a.to_dict()["expiresAt"].endswith("Z")
    assert s.take("v", a.challenge) is True
    assert s.take("v", a.challenge) is False
    with pytest.raises(TypeError):
        s.create("")
    assert len(ChallengeStore.new_visit_id()) == 43


def test_challenge_store_ttl_and_limits():
    c = Clock()
    s = ChallengeStore(clock=c, max_per_visit=2)
    c1 = s.create("v").challenge
    c2 = s.create("v").challenge
    c3 = s.create("v").challenge
    assert s.open_count("v") == 2
    assert s.take("v", c1) is False
    assert s.take("v", c2) is True
    c.t += 301
    assert s.take("v", c3) is False
    other = s.create("a").challenge
    assert s.take("b", other) is False


# ---------------------------------------------------------------- shared test vectors

def _vector_cases():
    with open(VECTORS, encoding="utf-8") as f:
        data = json.load(f)
    return data, data["cases"]


def test_shared_vectors_match_node():
    data, cases = _vector_cases()
    store = JwksKeyStore()
    store.set_jwks(data["jwks"])
    v = V18Verifier(key_cache=store, origin=data["origin"], clock=lambda: data["now"])
    assert len(cases) >= 20
    for c in cases:  # in order: one case is a replay of an earlier one
        r = v.verify_ticket(c["ticket"], expected_challenge=data["challenge"], min_age=c.get("minAge", 18))
        assert code(r) == c["expect"], f'{c["name"]}: {r.error}'
        if r.valid and c.get("minAgeOut"):
            assert r.ticket.min_age == c["minAgeOut"]
