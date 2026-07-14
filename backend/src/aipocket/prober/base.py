"""Prober base class + shared utilities."""

from __future__ import annotations

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from aipocket.core.key_patterns import KEY_PATTERNS as _PROBE_KEY_PATTERNS_BASE
from aipocket.core.key_patterns import is_noise as _is_noise
from aipocket.core.models import Credential
from aipocket.services.config_extractor import extract_config_bundles

from .budget import BudgetExhausted, RequestBudget
from .credentials_dict import BUILTIN_WEAK_CREDENTIALS
from .security import normalized_origin

log = logging.getLogger(__name__)

# Builtin seed only; full dict is loaded by get_weak_credentials() in the engine.
WEAK_CREDENTIALS: list[tuple[str, str]] = list(BUILTIN_WEAK_CREDENTIALS)


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
    return "certificate" in low and (
        "verify" in low or "mismatch" in low or "self-signed" in low or "expired" in low
    )


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

    for bundle in extract_config_bundles(text):
        value = bundle.secret_value.reveal()
        if value in seen:
            continue
        seen.add(value)
        creds.append(
            Credential(
                apikey=value,
                apiurl=bundle.endpoint_candidates[0]
                if len(bundle.endpoint_candidates) == 1
                else "",
                source=f"{source_label}:{bundle.provider_hint}",
                source_type="fingerprint",
                host=host,
                bundle=bundle,
            )
        )

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
    (
        "generic_bearer",
        re.compile(
            r'(?:api[_-]?key|apikey|bearer|token|secret|authorization)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{32,})["\']?',
            re.I,
        ),
    ),
]


class Prober(ABC):
    """Base class for product-specific credential probes."""

    #: Product identifier — must match ``_product`` tag on hits or be matched
    #: by :meth:`identify`.
    product_name: str = ""

    def __init__(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        budget: RequestBudget | None = None,
        *,
        max_redirects: int = 2,
        intrusive_checks: bool = False,
        authorized_scope: tuple[str, ...] = (),
    ):
        self._client = client
        self._sem = sem
        self._budget = budget
        self._max_redirects = max_redirects
        self._intrusive_checks = intrusive_checks
        self._authorized_scope = frozenset(authorized_scope)
        # Filled by :meth:`run_specs` so the runner can collect findings/node_outcomes.
        self.last_result: Any = None

    def _consume_request(self) -> None:
        if self._budget is not None:
            self._budget.consume()

    @property
    def budget_consumed(self) -> int:
        return 0 if self._budget is None else self._budget.consumed

    @property
    def budget_remaining(self) -> int | None:
        """Remaining requests, or None when no budget is attached."""
        if self._budget is None:
            return None
        return self._budget.remaining

    @classmethod
    @abstractmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        """Return True if *hit* looks like this product (title/header/banner)."""

    @abstractmethod
    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        """Run all probes for this product on *hit*'s host.

        Return a list of extracted credentials (may be empty).
        """

    async def run_specs(self, hit: dict[str, Any], specs: list[Any]) -> list[Credential]:
        """Execute audited ProbeSpecs and stash the full ProbeResult on ``last_result``."""
        from .capability import run_product_plan

        result = await run_product_plan(self, hit, specs)
        self.last_result = result
        return result.credentials

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
        kwargs["follow_redirects"] = False
        try:
            self._consume_request()
            async with self._sem:
                response = await self._client.get(url, **kwargs)
            return await self._follow_same_origin(response, kwargs)
        except BudgetExhausted:
            return None
        except Exception as e:  # noqa: BLE001 — prober must never crash on a bad host
            if _is_tls_verify_error(e):
                return await self._insecure_retry("GET", url, **kwargs)
            return None

    async def _post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        if not url:
            return None
        kwargs.setdefault("timeout", PROBE_TIMEOUT)
        kwargs["follow_redirects"] = False
        try:
            self._consume_request()
            async with self._sem:
                return await self._client.post(url, **kwargs)
        except BudgetExhausted:
            return None
        except Exception as e:  # noqa: BLE001
            if _is_tls_verify_error(e):
                return await self._insecure_retry("POST", url, **kwargs)
            return None

    async def _insecure_retry(self, method: str, url: str, **kwargs: Any) -> httpx.Response | None:
        """Retry a request with verify=False in a throwaway client (TLS-broken hosts)."""
        try:
            async with (
                httpx.AsyncClient(
                    timeout=kwargs.pop("timeout", PROBE_TIMEOUT),
                    follow_redirects=False,
                    verify=False,
                ) as insecure,
                self._sem,
            ):
                self._consume_request()
                if method == "GET":
                    return await insecure.get(url, **kwargs)
                return await insecure.post(url, **kwargs)
        except BudgetExhausted:
            return None

    async def _follow_same_origin(
        self, response: httpx.Response, kwargs: dict[str, Any]
    ) -> httpx.Response | None:
        origin = normalized_origin(str(response.request.url))
        current = response
        for _ in range(self._max_redirects):
            if not current.is_redirect or "location" not in current.headers:
                return current
            location = current.headers["location"]
            try:
                location_parts = urlsplit(location)
            except ValueError:
                return None
            if location_parts.scheme and normalized_origin(location) is None:
                return None
            next_url = urljoin(str(current.request.url), location)
            if normalized_origin(next_url) != origin:
                return None
            try:
                self._consume_request()
                async with self._sem:
                    current = await self._client.get(next_url, **kwargs)
            except (BudgetExhausted, httpx.HTTPError):
                return None
        return None if current.is_redirect else current

    def _intrusive_authorized(self, hit: dict[str, Any]) -> bool:
        """Legacy L1 gate (weak password / IDOR). Prefer security.allows() for Specs.

        Empty ``authorized_scope`` means unrestricted when intrusive_checks is on.
        """
        from .security import scope_permits

        if not self._intrusive_checks:
            return False
        target_origin = normalized_origin(self._url(hit))
        if target_origin is None:
            return False
        return scope_permits(target_origin, self._authorized_scope)

    def _extract_from_response(
        self,
        resp: httpx.Response | None,
        hit: dict[str, Any],
        tag: str,
        *,
        max_body_chars: int | None = None,
    ) -> list[Credential]:
        """Extract credentials from a probe response.

        Preserves endpoints already recovered by structured config extraction
        (``bundle.endpoint_candidates``). Only fills empty ``apiurl`` with the
        probed site origin so we do not overwrite a correct upstream endpoint.
        """
        if resp is None or resp.status_code != 200:
            return []
        text = resp.text
        if not text or len(text) < 20:
            return []
        if max_body_chars is not None and max_body_chars > 0:
            text = text[:max_body_chars]
        host = hit.get("host", "")
        leak_origin = self._url(hit)
        creds = extract_keys_from_text(text, host=host, source_label=f"prober:{tag}")
        for c in creds:
            # Keep structured endpoint when the extractor already paired one.
            if not (c.apiurl and c.apiurl.strip()):
                if c.bundle is not None and c.bundle.endpoint_candidates:
                    # Prefer single unambiguous candidate; else leave empty for
                    # validator to resolve rather than force leak origin.
                    if len(c.bundle.endpoint_candidates) == 1:
                        c.apiurl = c.bundle.endpoint_candidates[0]
                    # else leave empty
                else:
                    c.apiurl = leak_origin
            c.backend = hit.get("_source", "")
            c.ip = hit.get("ip", "")
            c.port = hit.get("port", "")
            # Record leak host separately via source tag when apiurl is upstream
            if (
                c.apiurl
                and c.apiurl.rstrip("/") != leak_origin.rstrip("/")
                and "leak_host=" not in c.source
            ):
                c.source = f"{c.source}|leak_host={host}" if c.source else f"leak_host={host}"
        return creds

    def _match_any(self, text: str, keywords: tuple[str, ...]) -> bool:
        t = text.lower()
        return any(k in t for k in keywords)
