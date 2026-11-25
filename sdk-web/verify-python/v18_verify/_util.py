"""Small helpers shared by the library. Behaviour matches the Node library on purpose."""
from __future__ import annotations

import base64
import re
from typing import Any, Optional
from urllib.parse import urlsplit

_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_SAFE_INT = 2**53 - 1


def is_base64url(s: Any) -> bool:
    return isinstance(s, str) and len(s) > 0 and bool(_B64URL.match(s)) and len(s) % 4 != 1


def b64url_decode(s: str) -> Optional[bytes]:
    """Strict base64url (no padding). Returns None for anything else."""
    if not is_base64url(s):
        return None
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def as_safe_int(x: Any) -> Optional[int]:
    """A JSON whole number, the way JavaScript's Number.isSafeInteger sees it. Booleans are not numbers."""
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        return x if -_MAX_SAFE_INT <= x <= _MAX_SAFE_INT else None
    if isinstance(x, float) and x.is_integer() and -_MAX_SAFE_INT <= x <= _MAX_SAFE_INT:
        return int(x)
    return None


def is_web_origin(s: Any) -> bool:
    """True if ``s`` is exactly a web origin such as ``https://example.com`` or ``http://localhost:3000``."""
    if not isinstance(s, str) or not s:
        return False
    try:
        u = urlsplit(s)
        port = u.port
    except ValueError:
        return False
    if u.scheme not in ("http", "https") or u.path or u.query or u.fragment:
        return False
    if u.username is not None or u.password is not None or not u.hostname:
        return False
    host = u.hostname
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if u.scheme == "https" else 80
    rebuilt = f"{u.scheme}://{host}" + (f":{port}" if port is not None and port != default_port else "")
    return rebuilt == s


def normalize_server_url(url: str) -> str:
    """``http://host:8080/v1/`` -> ``http://host:8080``."""
    url = url.strip().rstrip("/")
    if url.endswith("/v1"):
        url = url[: -len("/v1")]
    return url
