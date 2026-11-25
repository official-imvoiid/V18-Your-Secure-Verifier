"""Loads and caches V18's public keys from ``GET /v1/keys`` (PROTOCOL.md 3.2)."""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers

from . import errors
from ._util import as_safe_int, b64url_decode, normalize_server_url

_KID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


@dataclass(frozen=True)
class V18Key:
    kid: str
    public_key: RSAPublicKey
    min_age: int  # the age this key certifies; authorization uses this, never the ticket's own minAge
    nbf: int
    exp: int


@dataclass(frozen=True)
class KeyLookup:
    key: Optional[V18Key]
    unavailable: bool = False
    reason: Optional[str] = None


def parse_v18_jwk(jwk: Any) -> Tuple[Optional[V18Key], Optional[str]]:
    """Returns (key, None), or (None, reason) for keys we must not use."""
    if not isinstance(jwk, dict):
        return None, "not an object"
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not _KID.match(kid):
        return None, "bad kid"
    if jwk.get("kty") != "RSA":
        return None, f"{kid}: kty is not RSA"
    if jwk.get("alg") != errors.ALGORITHM:
        return None, f"{kid}: alg is not {errors.ALGORITHM}"
    if "use" in jwk and jwk["use"] != "sig":
        return None, f"{kid}: use is not sig"
    min_age = as_safe_int(jwk.get("v18_min_age"))
    if min_age is None or min_age < 0:
        return None, f"{kid}: missing v18_min_age"
    nbf, exp = as_safe_int(jwk.get("nbf")), as_safe_int(jwk.get("exp"))
    if nbf is None or exp is None or exp <= nbf:
        return None, f"{kid}: bad nbf/exp"
    n_bytes, e_bytes = b64url_decode(jwk.get("n")), b64url_decode(jwk.get("e"))
    if not n_bytes or not e_bytes:
        return None, f"{kid}: missing n/e"
    try:
        public_key = RSAPublicNumbers(int.from_bytes(e_bytes, "big"), int.from_bytes(n_bytes, "big")).public_key()
    except Exception as e:  # noqa: BLE001
        return None, f"{kid}: {e}"
    if public_key.key_size < 2048:
        return None, f"{kid}: RSA key is only {public_key.key_size} bits"
    return V18Key(kid=kid, public_key=public_key, min_age=min_age, nbf=nbf, exp=exp), None


def _default_fetch_json(url: str, timeout: float) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URL is the site's own config)
        if resp.status != 200:
            raise RuntimeError(f"JWKS fetch failed: HTTP {resp.status}")
        return json.loads(resp.read().decode("utf-8"))


class JwksKeyStore:
    """
    Caches V18's JWKS. Keys that vanish from the JWKS are dropped on the next refresh.
    Pinned keys (``add_jwk``, ``set_jwks``) need no network and never expire from the cache.
    """

    def __init__(
        self,
        server_url: Optional[str] = None,
        jwks_url: Optional[str] = None,
        cache_ttl_seconds: float = 3600,
        min_refresh_interval_seconds: float = 30,
        timeout_seconds: float = 5,
        fetch_json: Optional[Callable[[str, float], Any]] = None,
        clock: Callable[[], float] = time.time,
    ):
        if jwks_url:
            self.jwks_url: Optional[str] = jwks_url
        elif server_url:
            self.jwks_url = f"{normalize_server_url(server_url)}/v1/keys"
        else:
            self.jwks_url = None
        self._ttl = cache_ttl_seconds
        self._min_refresh = min_refresh_interval_seconds
        self._timeout = timeout_seconds
        self._fetch_json = fetch_json or _default_fetch_json
        self._clock = clock
        self._fetched: Dict[str, V18Key] = {}
        self._pinned: Dict[str, V18Key] = {}
        self._last_fetch = 0.0
        self._last_attempt = 0.0
        self._lock = threading.Lock()

    def add_jwk(self, jwk: Any) -> V18Key:
        key, reason = parse_v18_jwk(jwk)
        if key is None:
            raise ValueError(f"[V18] Unusable key: {reason}")
        self._pinned[key.kid] = key
        return key

    def set_jwks(self, jwks: Any) -> int:
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list):
            raise ValueError('[V18] JWKS must look like {"keys": [...]}')
        self._pinned.clear()
        for jwk in keys:
            key, _ = parse_v18_jwk(jwk)
            if key is not None:
                self._pinned[key.kid] = key
        return len(self._pinned)

    def refresh(self) -> None:
        """Fetches the JWKS now. Raises on network or format errors."""
        if not self.jwks_url:
            return
        self._last_attempt = self._clock()
        data = self._fetch_json(self.jwks_url, self._timeout)
        keys = data.get("keys") if isinstance(data, dict) else None
        if not isinstance(keys, list):
            raise ValueError('JWKS response has no "keys" array')
        nxt: Dict[str, V18Key] = {}
        for jwk in keys:
            key, _ = parse_v18_jwk(jwk)
            if key is not None:
                nxt[key.kid] = key
        self._fetched = nxt
        self._last_fetch = self._clock()

    def get_key(self, kid: str) -> KeyLookup:
        pinned = self._pinned.get(kid)
        if pinned is not None:
            return KeyLookup(pinned)
        if not self.jwks_url:
            return KeyLookup(None)
        with self._lock:
            now = self._clock()
            stale = self._last_fetch == 0 or now - self._last_fetch >= self._ttl
            unknown = kid not in self._fetched
            may_retry = self._last_attempt == 0 or now - self._last_attempt >= self._min_refresh
            if (stale or unknown) and may_retry:
                try:
                    self.refresh()
                except Exception as e:  # noqa: BLE001
                    cached = self._fetched.get(kid)
                    if cached is not None:  # V18 being down must not break sites
                        return KeyLookup(cached)
                    return KeyLookup(None, unavailable=True, reason=str(e))
            return KeyLookup(self._fetched.get(kid))

    def list(self) -> List[V18Key]:
        return list(self._fetched.values()) + list(self._pinned.values())


# Old name, kept so existing imports keep working.
KeyCache = JwksKeyStore
