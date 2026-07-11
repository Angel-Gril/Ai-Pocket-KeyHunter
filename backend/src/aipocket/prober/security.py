from __future__ import annotations

from urllib.parse import urlsplit

Origin = tuple[str, str, int]


def normalized_origin(url: str) -> Origin | None:
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if (
        scheme not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    effective_port = port if port is not None else {"http": 80, "https": 443}[scheme]
    return scheme, hostname.lower(), effective_port


def scope_authorizes_origin(scope: str, origin: Origin) -> bool:
    try:
        parsed = urlsplit(scope)
    except ValueError:
        return False
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return False
    return normalized_origin(scope) == origin
