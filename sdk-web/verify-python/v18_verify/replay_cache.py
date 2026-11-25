"""
Remembers ticket IDs already accepted, so a ticket works only once (PROTOCOL.md 3.7 rule 8).

The default ``MemoryReplayCache`` lives in this process. If your site runs several worker
processes or servers (gunicorn with many workers, for example), they must share one store:
implement ``check_and_remember`` with Redis ``SET key 1 NX EXAT <until>``.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Dict, Protocol


class ReplayStore(Protocol):
    def check_and_remember(self, ticket_id: str, remember_until_epoch: int) -> bool:
        """Atomically: False if seen before; otherwise remember it until the given time and return True."""
        ...


class MemoryReplayCache:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._seen: Dict[str, int] = {}
        self._clock = clock
        self._last_prune = 0.0
        self._lock = threading.Lock()

    def check_and_remember(self, ticket_id: str, remember_until_epoch: int) -> bool:
        with self._lock:
            now = self._clock()
            if now - self._last_prune >= 30:
                self._last_prune = now
                for tid in [t for t, until in self._seen.items() if until < now]:
                    del self._seen[tid]
            until = self._seen.get(ticket_id)
            if until is not None and until >= now:
                return False
            self._seen[ticket_id] = remember_until_epoch
            return True

    def has(self, ticket_id: str) -> bool:
        return ticket_id in self._seen

    def __len__(self) -> int:
        return len(self._seen)

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


# Old name, kept so existing imports keep working.
ReplayCache = MemoryReplayCache
