"""Sanitize user-supplied relay / gateway URLs for manual target entry.

Strips path / query / fragment noise (e.g. ``/login/xxxx``), normalizes host
case and default ports, and rejects non-http(s) or unparseable input.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# Hostnames: labels of alnum/hyphen, no leading/trailing hyphen, optional dots.
# Also allow IPv4 / IPv6 (via ipaddress after bracket strip).
_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)
_MAX_URL_LEN = 2048


@dataclass(frozen=True, slots=True)
class SanitizedUrl:
    """Canonical origin for a manual target (scheme + host + port only)."""

    url: str  # e.g. https://web.ymocode.com or http://10.0.0.1:8080
    scheme: str
    hostname: str
    port: int
    host_key: str  # scheme-agnostic hostname:port for dedup/display


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _format_url(scheme: str, hostname: str, port: int) -> str:
    host_disp = f"[{hostname}]" if ":" in hostname else hostname
    default = _default_port(scheme)
    suffix = "" if port == default else f":{port}"
    return f"{scheme}://{host_disp}{suffix}"


def _format_host_key(hostname: str, port: int) -> str:
    if ":" in hostname:
        return f"[{hostname}]:{port}"
    return f"{hostname}:{port}"


def _looks_like_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(hostname)
        return True
    return bool(_HOSTNAME_RE.match(hostname))


def sanitize_target_url(raw: str) -> SanitizedUrl | None:
    """Clean one user-entered address into a scheme://host[:port] origin.

    Returns None when the input is empty, too long, not http(s), or unparseable.
    """
    text = (raw or "").strip()
    if not text or len(text) > _MAX_URL_LEN:
        return None

    # Drop accidental quotes / trailing punctuation common in paste noise.
    text = text.strip("\"'` \t")
    text = text.rstrip(".,;")
    if not text:
        return None

    # Reject obvious non-URLs early (javascript:, data:, file:, etc.).
    lower = text.lower()
    if lower.startswith(("javascript:", "data:", "file:", "vbscript:", "about:")):
        return None

    # Protocol-relative //host/path → https
    if text.startswith("//"):
        text = "https:" + text

    if "://" not in text:
        # Bare host or host/path — default to https.
        text = "https://" + text.lstrip("/")

    try:
        parsed = urlsplit(text)
    except ValueError:
        return None

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return None

    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        return None

    with contextlib.suppress(ValueError):
        hostname = ipaddress.ip_address(hostname).compressed

    if not _looks_like_hostname(hostname):
        return None

    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = _default_port(scheme)
    if not (1 <= port <= 65535):
        return None

    return SanitizedUrl(
        url=_format_url(scheme, hostname, port),
        scheme=scheme,
        hostname=hostname,
        port=port,
        host_key=_format_host_key(hostname, port),
    )


def sanitize_target_urls(
    lines: list[str] | tuple[str, ...] | str,
) -> tuple[list[SanitizedUrl], list[str]]:
    """Sanitize many inputs (list or newline-separated string).

    Returns ``(accepted, rejected_raw_lines)``. Dedupes by ``(scheme, host, port)``
    while preserving first-seen order.
    """
    raw_items = lines.splitlines() if isinstance(lines, str) else list(lines)

    accepted: list[SanitizedUrl] = []
    rejected: list[str] = []
    seen: set[tuple[str, str, int]] = set()

    for item in raw_items:
        raw = (item or "").strip()
        if not raw:
            continue
        cleaned = sanitize_target_url(raw)
        if cleaned is None:
            rejected.append(raw)
            continue
        key = (cleaned.scheme, cleaned.hostname, cleaned.port)
        if key in seen:
            continue
        seen.add(key)
        accepted.append(cleaned)
    return accepted, rejected


def urls_to_host_hits(urls: list[SanitizedUrl] | list[str]) -> list[dict]:
    """Convert sanitized (or raw) URLs into FOFA/Shodan-shaped host hits.

    Hits are tagged ``_source=manual`` so the shared canonicalize → probe →
    validate pipeline treats them like other host discovery lanes.
    """
    hits: list[dict] = []
    for item in urls:
        if isinstance(item, SanitizedUrl):
            cleaned = item
        else:
            cleaned = sanitize_target_url(str(item))
            if cleaned is None:
                continue
        hits.append(
            {
                "host": cleaned.url,
                "protocol": cleaned.scheme,
                "port": str(cleaned.port),
                "ip": cleaned.hostname if _is_ip(cleaned.hostname) else "",
                "link": cleaned.url,
                "_source": "manual",
                "_query_id": "manual-target",
                # Same as FOFA body= hits: no passive banner body — run Generic
                # leak paths alongside the product prober when one is identified.
                "_requires_content_refetch": True,
            }
        )
    return hits


def _is_ip(hostname: str) -> bool:
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(hostname)
        return True
    return False
