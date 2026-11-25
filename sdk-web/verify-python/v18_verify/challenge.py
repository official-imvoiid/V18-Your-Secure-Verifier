"""
Makes and remembers a fresh challenge for each visit to your website (PROTOCOL.md 3.7 rule 5).

A "visit" is whatever ID you already keep for the browser, such as a session cookie.
``ChallengeStore.new_visit_id()`` makes one if you have nothing yet::

    challenges = ChallengeStore()
    issued = challenges.create(visit_id)          # give issued.challenge to the widget
    result = verifier.verify_ticket(ticket, expected_challenge=challenges.checker(visit_id))

Each challenge works once. This store is in memory, so it fits one process. With several worker
processes, keep challenges in your shared session store (for example Flask's signed session,
Django sessions, or Redis) and pass the string as ``expected_challenge``.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


@dataclass(frozen=True)
class IssuedChallenge:
    challenge: str  # 64 hex characters (32 random bytes)
    expires_at: str  # ISO date string

    def to_dict(self) -> dict:
        return {"challenge": self.challenge, "expiresAt": self.expires_at}


class ChallengeStore:
    def __init__(
        self,
        ttl_seconds: float = 300,
        max_per_visit: int = 5,
        max_visits: int = 100_000,
        clock: Callable[[], float] = time.time,
    ):
        self._ttl = ttl_seconds
        self._max_per_visit = max_per_visit
        self._max_visits = max_visits
        self._clock = clock
        self._visits: "OrderedDict[str, OrderedDict[str, float]]" = OrderedDict()
        self._last_prune = 0.0
        self._lock = threading.Lock()

    @staticmethod
    def new_visit_id() -> str:
        """A new random visit ID (32 bytes, base64url) for a cookie."""
        return secrets.token_urlsafe(32)

    def create(self, visit_id: str) -> IssuedChallenge:
        if not isinstance(visit_id, str) or not visit_id:
            raise TypeError("[V18] ChallengeStore.create needs a visit ID")
        with self._lock:
            now = self._clock()
            self._maybe_prune(now)
            challenge = secrets.token_hex(32)
            expires = now + self._ttl
            open_ = self._visits.pop(visit_id, None) or OrderedDict()
            for c in [c for c, exp in open_.items() if exp <= now]:
                del open_[c]
            open_[challenge] = expires
            while len(open_) > self._max_per_visit:
                open_.popitem(last=False)
            self._visits[visit_id] = open_
            while len(self._visits) > self._max_visits:
                self._visits.popitem(last=False)
        iso = datetime.fromtimestamp(expires, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return IssuedChallenge(challenge=challenge, expires_at=iso)

    def take(self, visit_id: str, challenge: str) -> bool:
        """Single use: True (and forgotten) if this visit was given it and it has not expired."""
        with self._lock:
            open_ = self._visits.get(visit_id)
            if not open_ or not isinstance(challenge, str):
                return False
            exp = open_.pop(challenge, None)
            if not open_:
                self._visits.pop(visit_id, None)
            return exp is not None and exp > self._clock()

    def checker(self, visit_id: str) -> Callable[[str], bool]:
        """A function to pass as ``expected_challenge``. It takes (uses up) the challenge."""
        return lambda challenge: self.take(visit_id, challenge)

    def clear(self, visit_id: str) -> None:
        with self._lock:
            self._visits.pop(visit_id, None)

    def open_count(self, visit_id: str) -> int:
        now = self._clock()
        return sum(1 for exp in self._visits.get(visit_id, {}).values() if exp > now)

    def _maybe_prune(self, now: float) -> None:
        if now - self._last_prune < 60:
            return
        self._last_prune = now
        for vid in list(self._visits):
            open_ = self._visits[vid]
            for c in [c for c, exp in open_.items() if exp <= now]:
                del open_[c]
            if not open_:
                del self._visits[vid]
