"""Checks V18 tickets on your website's server. Implements every rule in PROTOCOL.md 3.7."""
from __future__ import annotations

import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from . import errors as E
from ._util import as_safe_int, b64url_decode, is_base64url, is_web_origin
from .key_cache import JwksKeyStore
from .replay_cache import MemoryReplayCache, ReplayStore

_KID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

ChallengeExpectation = Union[str, Callable[[str], bool]]


@dataclass(frozen=True)
class VerifiedTicket:
    ticket_id: str
    origin: str
    min_age: int  # the threshold certified by V18's signing key (its v18_min_age)
    key_id: str
    iat: int
    expires_at: int


@dataclass
class VerifyResult:
    valid: bool
    code: Optional[str] = None
    error: Optional[str] = None
    ticket: Optional[VerifiedTicket] = None
    payload: Optional[Dict[str, Any]] = None

    def __bool__(self) -> bool:  # `if result:` reads naturally
        return self.valid


def _fail(code: str, error: str) -> VerifyResult:
    return VerifyResult(valid=False, code=code, error=error)


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


class V18Verifier:
    """
    Never trust the browser alone: call this on your server.

    ``server_url`` is the V18 server base URL (for the JWKS). ``origin`` is your site's web origin,
    for example ``https://example.com``.
    """

    def __init__(
        self,
        server_url: str = "http://localhost:8080",
        origin: Optional[str] = None,
        min_age: int = 18,
        key_cache: Optional[JwksKeyStore] = None,
        replay_cache: Optional[ReplayStore] = None,
        clock: Callable[[], float] = time.time,
    ):
        if origin is not None and not is_web_origin(origin):
            raise ValueError(
                f'[V18] origin must be a web origin like "https://example.com" (no path, no trailing slash). Got "{origin}".'
            )
        self._clock = clock
        self.key_cache = key_cache or JwksKeyStore(server_url=server_url, clock=clock)
        self.replay_cache: ReplayStore = replay_cache or MemoryReplayCache(clock=clock)
        self._origin = origin
        self._min_age = min_age

    def verify_ticket(
        self,
        ticket_string: Any,
        expected_origin: Optional[str] = None,
        expected_challenge: Optional[ChallengeExpectation] = None,
        min_age: Optional[int] = None,
    ) -> VerifyResult:
        """Never raises for a bad ticket: returns ``VerifyResult(valid=False, code=..., error=...)``."""
        # --- The website's own settings ---
        origin_expected = expected_origin if expected_origin is not None else self._origin
        if not is_web_origin(origin_expected):
            return _fail(E.CONFIG_ERROR, f'expected_origin must be a web origin like "https://example.com". Got "{origin_expected}".')
        required_age = min_age if min_age is not None else self._min_age
        if as_safe_int(required_age) is None or isinstance(required_age, float) or required_age < 1:
            return _fail(E.CONFIG_ERROR, f'min_age must be a whole number of at least 1. Got "{required_age}".')
        if expected_challenge is None or expected_challenge == "":
            return _fail(E.CHALLENGE_REQUIRED, "No expected challenge given. Issue a challenge for each visit and pass it here.")

        # --- Ticket shape ---
        if not isinstance(ticket_string, str) or not ticket_string:
            return _fail(E.INVALID_FORMAT, "Ticket is empty or not a string")
        if len(ticket_string) > E.MAX_TICKET_LENGTH:
            return _fail(E.INVALID_FORMAT, "Ticket is too long")
        parts = ticket_string.strip().split(".")
        if len(parts) != 3:
            return _fail(E.INVALID_FORMAT, "Ticket must have 3 parts: keyId.prepared.signature")
        key_id, prepared_b64, sig_b64 = parts
        if not _KID.match(key_id) or not is_base64url(prepared_b64) or not is_base64url(sig_b64):
            return _fail(E.INVALID_FORMAT, "Ticket parts must be base64url without padding")
        prepared = b64url_decode(prepared_b64)
        signature = b64url_decode(sig_b64)
        assert prepared is not None and signature is not None

        now = int(self._clock())

        # --- Rule 1: the key is in the JWKS and not too old ---
        lookup = self.key_cache.get_key(key_id)
        if lookup.key is None:
            if lookup.unavailable:
                return _fail(E.KEYS_UNAVAILABLE, f"Could not load V18 public keys: {lookup.reason}")
            return _fail(E.UNKNOWN_KEY, f'Key "{key_id}" is not in the V18 JWKS')
        key = lookup.key
        if now > key.exp + E.KEY_EXPIRY_GRACE_SECONDS:
            return _fail(E.KEY_EXPIRED, f'Key "{key_id}" expired at {_iso(key.exp)}')
        if now < key.nbf - E.CLOCK_SKEW_SECONDS:
            return _fail(E.KEY_NOT_YET_VALID, f'Key "{key_id}" is not valid until {_iso(key.nbf)}')

        # --- Rule 2: RSA-PSS, SHA-384, MGF1-SHA-384, salt 48, over `prepared` ---
        try:
            key.public_key.verify(
                signature,
                prepared,
                padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=E.PSS_SALT_LENGTH),
                hashes.SHA384(),
            )
        except (InvalidSignature, ValueError):
            return _fail(E.INVALID_SIGNATURE, "The V18 seal on this ticket is not valid (forged or changed)")

        # --- The signed message: 32 random bytes, then UTF-8 JSON ---
        if len(prepared) <= E.PREPARE_PREFIX_BYTES:
            return _fail(E.MALFORMED_PAYLOAD, "Signed message is too short")
        try:
            payload = json.loads(prepared[E.PREPARE_PREFIX_BYTES:].decode("utf-8"), parse_constant=_reject_constant)
        except (UnicodeDecodeError, ValueError):
            return _fail(E.MALFORMED_PAYLOAD, "Signed message is not UTF-8 JSON")
        if not isinstance(payload, dict):
            return _fail(E.MALFORMED_PAYLOAD, "Signed message is not a JSON object")

        # --- Rule 3: version ---
        if as_safe_int(payload.get("v")) != 1:
            return _fail(E.UNSUPPORTED_VERSION, f"Ticket version is {json.dumps(payload.get('v'))}, expected 1")

        ticket_id = payload.get("ticketId")
        tid_bytes = b64url_decode(ticket_id) if isinstance(ticket_id, str) and len(ticket_id) <= 64 else None
        if not tid_bytes or len(tid_bytes) < 16:
            return _fail(E.MALFORMED_PAYLOAD, "ticketId must be base64url of at least 16 random bytes")
        origin, challenge = payload.get("origin"), payload.get("challenge")
        if not isinstance(origin, str) or not isinstance(challenge, str):
            return _fail(E.MALFORMED_PAYLOAD, "origin and challenge must be strings")
        p_min_age, iat, expires_at = (as_safe_int(payload.get(k)) for k in ("minAge", "iat", "expiresAt"))
        if p_min_age is None or iat is None or expires_at is None:
            return _fail(E.MALFORMED_PAYLOAD, "minAge, iat and expiresAt must be whole numbers")

        # --- Rule 4: origin ---
        if origin != origin_expected:
            return _fail(E.ORIGIN_MISMATCH, f'Ticket is for "{origin}", this site is "{origin_expected}"')

        # --- Rule 6: the KEY's threshold, never the payload's minAge ---
        if key.min_age < required_age:
            return _fail(E.AGE_INSUFFICIENT, f'Key "{key_id}" certifies {key.min_age}+, this site needs {required_age}+')

        # --- Rule 7: time window ---
        lifetime = expires_at - iat
        if lifetime < 0 or lifetime > E.MAX_TICKET_LIFETIME_SECONDS:
            return _fail(E.TICKET_LIFETIME_INVALID, f"Ticket lifetime is {lifetime} seconds (allowed 0 to 300)")
        if now < iat - E.CLOCK_SKEW_SECONDS:
            return _fail(E.TICKET_NOT_YET_VALID, "Ticket was issued in the future (check the clocks)")
        if now > expires_at + E.CLOCK_SKEW_SECONDS:
            return _fail(E.TICKET_EXPIRED, f"Ticket expired at {_iso(expires_at)}")

        # --- Rule 5: challenge (checked late, because a checker function uses the challenge up) ---
        if isinstance(expected_challenge, str):
            challenge_ok = hmac.compare_digest(challenge.encode("utf-8"), expected_challenge.encode("utf-8"))
        else:
            try:
                challenge_ok = expected_challenge(challenge) is True
            except Exception:  # noqa: BLE001
                challenge_ok = False
        if not challenge_ok:
            return _fail(E.CHALLENGE_MISMATCH, "Ticket was not made for the challenge this site issued for this visit")

        # --- Rule 8: single use ---
        if not self.replay_cache.check_and_remember(ticket_id, expires_at + E.CLOCK_SKEW_SECONDS + 60):
            return _fail(E.REPLAY_DETECTED, "This ticket was already used")

        return VerifyResult(
            valid=True,
            ticket=VerifiedTicket(ticket_id, origin, key.min_age, key_id, iat, expires_at),
            payload={"v": 1, "ticketId": ticket_id, "origin": origin, "challenge": challenge,
                     "minAge": p_min_age, "iat": iat, "expiresAt": expires_at},
        )
