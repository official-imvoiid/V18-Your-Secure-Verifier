"""Check V18 age tickets on your website's server (Python, uses the ``cryptography`` package)."""
from __future__ import annotations

from typing import Dict, Optional

from . import errors
from ._util import is_web_origin, normalize_server_url
from .challenge import ChallengeStore, IssuedChallenge
from .key_cache import JwksKeyStore, KeyCache, KeyLookup, V18Key, parse_v18_jwk
from .replay_cache import MemoryReplayCache, ReplayCache, ReplayStore
from .verifier import ChallengeExpectation, V18Verifier, VerifiedTicket, VerifyResult

_default_verifiers: Dict[str, V18Verifier] = {}


def verify_ticket(
    ticket_string: str,
    expected_origin: str,
    expected_challenge: Optional[ChallengeExpectation] = None,
    min_age: int = 18,
    server_url: str = "http://localhost:8080",
) -> VerifyResult:
    """One-call helper. Keeps one verifier (and one replay cache) per V18 server URL."""
    v = _default_verifiers.get(server_url)
    if v is None:
        v = _default_verifiers[server_url] = V18Verifier(server_url=server_url)
    return v.verify_ticket(
        ticket_string,
        expected_origin=expected_origin,
        expected_challenge=expected_challenge,
        min_age=min_age,
    )


__version__ = "1.0.0"
__all__ = [
    "V18Verifier",
    "VerifyResult",
    "VerifiedTicket",
    "ChallengeExpectation",
    "ChallengeStore",
    "IssuedChallenge",
    "JwksKeyStore",
    "KeyCache",
    "KeyLookup",
    "V18Key",
    "parse_v18_jwk",
    "MemoryReplayCache",
    "ReplayCache",
    "ReplayStore",
    "errors",
    "is_web_origin",
    "normalize_server_url",
    "verify_ticket",
]
