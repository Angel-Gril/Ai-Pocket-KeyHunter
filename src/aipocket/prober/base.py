"""Prober base class + shared utilities."""

from __future__ import annotations

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

import httpx

from ..key_patterns import KEY_PATTERNS as _PROBE_KEY_PATTERNS_BASE
from ..key_patterns import is_noise as _is_noise
from ..models import Credential

log = logging.getLogger(__name__)


def _is_tls_verify_error(exc: BaseException) -> bool:
    """True if *exc* is a TLS certificate verification failure.

    httpx surfaces these as ConnectError whose cause is an ssl.SSLCertVerificationError
    (message contains 'CERTIFICATE_VERIFY_FAILED' / 'certificate verify failed').
    Match on the message so we don't import ssl across platforms.
    """
    msg = ""
    cur: BaseException | None = exc
    while cur is not None:
        msg = " ".join(filter(None, [msg, type(cur).__name__, str(cur)]))
        cur = cur.__cause__ or cur.__context__
    low = msg.lower()
    return "certificate" in low and ("verify" in low or "mismatch" in low or "self-signed" in low or "expired" in low)

# ---------------------------------------------------------------------------
# Default weak credentials to try on products that ship with defaults.
# Kept intentionally small — this is a config-read prober, not a brute-forcer.
# ---------------------------------------------------------------------------
WEAK_CREDENTIALS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "123456"),
    ("admin", "admin@123"),
    ("admin", "Admin123!"),
]

# Default timeout for a single probe request (seconds).
PROBE_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


def _base_url(host: str, protocol: str = "https") -> str:
    """Normalise a FOFA/Shodan host field into a base URL."""
    h = host.strip()
    if not h:
        return ""
    if h.startswith("http://") or h.startswith("https://"):
        return h.rstrip("/")
    if not protocol or protocol not in ("http", "https"):
        protocol = "https"
    return f"{protocol}://{h}".rstrip("/")


def extract_keys_from_text(
    text: str,
    host: str = "",
    source_label: str = "prober",
) -> list[Credential]:
    """Extract API keys from arbitrary text using the expanded pattern set.

    Patterns are aligned with ``FINGERPRINTS.md`` — broader than the passive
    extractor because we're now reading live config dumps (high signal).
    """
    creds: list[Credential] = []
    seen: set[str] = set()

    for label, pat in _PROBE_KEY_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            val = val.strip().strip("\"':,;})").lstrip("=")
            if len(val) < 15:
                continue
            if _is_noise(val):
                continue
            if val in seen:
                continue
            seen.add(val)
            creds.append(
                Credential(
                    apikey=val,
                    apiurl="",
                    source=f"{source_label}:{label}",
                    source_type="fingerprint",
                    host=host,
                    raw_context=text[:500],
                )
            )
    return creds


# ---------------------------------------------------------------------------
# Key patterns — imported from key_patterns, with prober-only generic_bearer
# appended.
# ---------------------------------------------------------------------------
_PROBE_KEY_PATTERNS = _PROBE_KEY_PATTERNS_BASE + [
    ("generic_bearer", re.compile(r'(?:api[_-]?key|apikey|bearer|token|secret|authorization)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{32,})["\']?', re.I)),
]


class Prober(ABC):
    """Base class for product-specific credential probes."""

    #: Product identifier — must match ``_product`` tag on hits or be matched
    #: by :meth:`identify`.
    product_name: str = ""

    def __init__(self, client: httpx.AsyncClient, sem: asyncio.Semaphore):
        self._client = client
        self._sem = sem

    @classmethod
    @abstractmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        """Return True if *hit* looks like this product (title/header/banner)."""

    @abstractmethod
    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        """Run all probes for this product on *hit*'s host.

        Return a list of extracted credentials (may be empty).
        """

    # -- helpers for subclasses --------------------------------------------

    def _url(self, hit: dict[str, Any], path: str = "") -> str:
        host = hit.get("host", "") or hit.get("link", "")
        proto = hit.get("protocol", "")
        base = _base_url(host, proto if proto in ("http", "https") else "https")
        if not base:
            return ""
        return base + path

    async def _get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        """GET *url* with timeout + error suppression. Returns None on failure.

        If the TLS handshake fails on cert verification (common for self-signed /
        IP-mismatched gateway certs), retry once with verify=False — these are
        exposed gateways we already know are misconfigured, not trusted services.
        """
        if not url:
            return None
        kwargs.setdefault("timeout", PROBE_TIMEOUT)
        kwargs.setdefault("follow_redirects", True)
        try:
            async with self._sem:
                return await self._client.get(url, **kwargs)
        except Exception as e:  # noqa: BLE001 — prober must never crash on a bad host
            if _is_tls_verify_error(e):
                return await self._insecure_retry("GET", url, **kwargs)
            return None

    async def _post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        if not url:
            return None
        kwargs.setdefault("timeout", PROBE_TIMEOUT)
        kwargs.setdefault("follow_redirects", True)
        try:
            async with self._sem:
                return await self._client.post(url, **kwargs)
        except Exception as e:  # noqa: BLE001
            if _is_tls_verify_error(e):
                return await self._insecure_retry("POST", url, **kwargs)
            return None

    async def _insecure_retry(self, method: str, url: str, **kwargs: Any) -> httpx.Response | None:
        """Retry a request with verify=False in a throwaway client (TLS-broken hosts)."""
        try:
            async with httpx.AsyncClient(
                timeout=kwargs.pop("timeout", PROBE_TIMEOUT),
                follow_redirects=kwargs.pop("follow_redirects", True),
                verify=False,
            ) as insecure, self._sem:
                if method == "GET":
                    return await insecure.get(url, **kwargs)
                return await insecure.post(url, **kwargs)
        except Exception:  # noqa: BLE001
            return None

    def _extract_from_response(
        self, resp: httpx.Response | None, hit: dict[str, Any], tag: str,
    ) -> list[Credential]:
        if resp is None or resp.status_code != 200:
            return []
        text = resp.text
        if not text or len(text) < 20:
            return []
        host = hit.get("host", "")
        creds = extract_keys_from_text(text, host=host, source_label=f"prober:{tag}")
        for c in creds:
            base = self._url(hit)
            c.apiurl = base
            c.backend = hit.get("_source", "")
            c.ip = hit.get("ip", "")
            c.port = hit.get("port", "")
        return creds

    def _match_any(self, text: str, keywords: tuple[str, ...]) -> bool:
        t = text.lower()
        return any(k in t for k in keywords)
