from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from aipocket.core.advisory import (
    AdvisoryRecord,
    AttackSurface,
    CredentialRelevance,
    SourceConfidence,
)

_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
_GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.I)
_HUNTR_RE = re.compile(r"\b(?:huntr\.dev|huntr\.com)/bounties/([a-f0-9-]{8,})\b", re.I)
_VERSION_RE = re.compile(
    r"(?:affected|versions?|before|prior to|<=|<)\s*[:\s]*([0-9]+(?:\.[0-9A-Za-z.-]+)*)",
    re.I,
)
_ZERO_DAY_CLAIM = re.compile(r"\b0[\s-]?day\b|\bzero[\s-]?day\b", re.I)

# Products that store or proxy provider credentials (subset aligned with tavily).
KNOWN_AI_PRODUCTS = (
    "one-api",
    "new-api",
    "litellm",
    "openrouter",
    "dify",
    "flowise",
    "librechat",
    "open webui",
    "openwebui",
    "fastgpt",
    "anythingllm",
    "langflow",
    "mlflow",
    "portkey",
    "lobe-chat",
    "lobechat",
    "wandb",
    "chatgpt-next-web",
    "nextchat",
    "deepseek",
    "qwen",
    "moonshot",
)

_SURFACE_KEYWORDS: tuple[tuple[AttackSurface, tuple[str, ...]], ...] = (
    (
        "credential_exposure",
        (
            "api key",
            "apikey",
            "credential leak",
            "secret leak",
            "token leak",
            "hardcoded",
            "env var",
            "expose key",
        ),
    ),
    (
        "auth_bypass",
        (
            "authentication bypass",
            "auth bypass",
            "unauthorized access",
            "unauthenticated",
            "idor",
        ),
    ),
    ("ssrf", ("ssrf", "server-side request forgery", "metadata endpoint")),
    (
        "rce",
        ("remote code execution", "code execution", " rce", "command injection"),
    ),
    ("sqli", ("sql injection", "sqli")),
    (
        "privilege_escalation",
        ("privilege escalation", "privesc", "admin access"),
    ),
    (
        "info_disclosure",
        ("information disclosure", "path traversal", "config leak", ".env"),
    ),
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_product(text: str) -> str:
    low = text.lower()
    for product in sorted(KNOWN_AI_PRODUCTS, key=len, reverse=True):
        if product in low:
            return product.replace(" ", "-")
    return ""


def _extract_versions(text: str) -> tuple[str, ...]:
    found = [match.group(1) for match in _VERSION_RE.finditer(text)]
    # Stable unique order
    return tuple(dict.fromkeys(found))


def _classify_surface(text: str) -> AttackSurface:
    low = text.lower()
    for surface, keywords in _SURFACE_KEYWORDS:
        if any(keyword in low for keyword in keywords):
            return surface
    return "unknown"


def _credential_relevance(surface: AttackSurface, text: str) -> CredentialRelevance:
    if surface in {"credential_exposure", "auth_bypass", "ssrf"}:
        return "high"
    if surface in {"info_disclosure", "rce", "privilege_escalation"}:
        return "medium"
    if "api key" in text.lower() or "credential" in text.lower():
        return "high"
    if surface == "unknown":
        return "low"
    return "medium"


def _source_confidence(url: str, *, has_stable_id: bool) -> SourceConfidence:
    host = url.lower()
    if any(
        domain in host
        for domain in (
            "nvd.nist.gov",
            "cve.mitre.org",
            "github.com/advisories",
            "huntr.dev",
            "huntr.com",
            "cve.org",
        )
    ):
        return "high"
    if has_stable_id:
        return "medium"
    return "low"


def _safe_check_profile(product: str, surface: AttackSurface) -> str:
    if not product:
        return ""
    if surface in {"auth_bypass", "credential_exposure", "info_disclosure"}:
        return f"readonly-fingerprint:{product}"
    if surface == "ssrf":
        return f"readonly-ssrf-surface:{product}"
    return f"readonly-product:{product}"


def _stable_disclosure_id(title: str, url: str) -> str:
    digest = hashlib.sha256(f"{title}|{url}".encode()).hexdigest()[:12]
    return f"DISCLOSURE-{digest}"


def parse_advisory_from_text(
    *,
    title: str = "",
    content: str = "",
    url: str = "",
    min_year: int = 0,
) -> AdvisoryRecord | None:
    """Parse a search/result snippet into a unified advisory or reject it."""
    combined = f"{title} {content} {url}".strip()
    if not combined:
        return None

    # Reject uncorroborated 0-day claims without a stable ID or authoritative host.
    zero_day = bool(_ZERO_DAY_CLAIM.search(combined))
    cve_match = _CVE_RE.search(combined)
    ghsa_match = _GHSA_RE.search(combined)
    huntr_match = _HUNTR_RE.search(url) or _HUNTR_RE.search(combined)

    product = _extract_product(combined)
    if not product and not cve_match and not ghsa_match and not huntr_match:
        return None

    advisory_id = ""
    has_stable_id = False
    if cve_match:
        year = int(cve_match.group(1))
        if min_year and year < min_year:
            # Older CVEs are retained when still product-relevant (no year hard reject).
            pass
        advisory_id = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
        has_stable_id = True
    elif ghsa_match:
        advisory_id = ghsa_match.group(0).upper()
        has_stable_id = True
    elif huntr_match:
        advisory_id = f"HUNTR-{huntr_match.group(1)[:12]}"
        has_stable_id = True
    else:
        # Credible public disclosure without assigned identifier.
        if zero_day and _source_confidence(url, has_stable_id=False) == "low":
            return None
        if not product or not url:
            return None
        if _source_confidence(url, has_stable_id=False) == "low" and zero_day:
            return None
        # Require product + non-empty disclosure text.
        if len(content.strip()) < 40 and len(title.strip()) < 20:
            return None
        advisory_id = _stable_disclosure_id(title or product, url)
        # Uncorroborated 0-day without authoritative source → reject.
        if (
            zero_day
            and "nvd.nist.gov" not in url.lower()
            and "github.com" not in url.lower()
            and not any(token in url.lower() for token in ("security", "advisory", "vuln", "blog"))
        ):
            return None

    if not product:
        # Stable IDs without product are still accepted with unknown product blank reject
        # for query planning usefulness — require product for scan relevance.
        return None

    surface = _classify_surface(combined)
    relevance = _credential_relevance(surface, combined)
    confidence = _source_confidence(url, has_stable_id=has_stable_id)
    if zero_day and not has_stable_id and confidence != "high":
        return None

    versions = _extract_versions(combined)
    description = (content or title).strip().replace("\n", " ")[:300]
    if advisory_id.upper().startswith(("CVE-", "GHSA-", "HUNTR-")):
        advisory_id = advisory_id.upper()
    return AdvisoryRecord(
        advisory_id=advisory_id,
        product=product,
        affected_versions=versions,
        attack_surface=surface,
        credential_relevance=relevance,
        safe_check_profile=_safe_check_profile(product, surface),
        source_confidence=confidence,
        published_at="",
        updated_at=_now(),
        sources=(url,) if url else (),
        description=description,
        title=title[:200],
    )


def parse_search_result(result: dict[str, Any]) -> AdvisoryRecord | None:
    return parse_advisory_from_text(
        title=str(result.get("title", "")),
        content=str(result.get("content", "")),
        url=str(result.get("url", "")),
    )


def merge_advisories(
    existing: list[AdvisoryRecord],
    discovered: list[AdvisoryRecord],
) -> tuple[list[AdvisoryRecord], int]:
    """Merge by advisory_id; newer non-empty fields win. Returns (merged, added)."""
    by_id: dict[str, AdvisoryRecord] = {item.advisory_id: item for item in existing}
    added = 0
    for item in discovered:
        current = by_id.get(item.advisory_id)
        if current is None:
            by_id[item.advisory_id] = item
            added += 1
            continue
        if item.updated_at >= current.updated_at:
            by_id[item.advisory_id] = AdvisoryRecord(
                advisory_id=item.advisory_id,
                product=item.product or current.product,
                affected_versions=item.affected_versions or current.affected_versions,
                attack_surface=(
                    item.attack_surface
                    if item.attack_surface != "unknown"
                    else current.attack_surface
                ),
                credential_relevance=item.credential_relevance or current.credential_relevance,
                safe_check_profile=item.safe_check_profile or current.safe_check_profile,
                source_confidence=(
                    item.source_confidence
                    if item.source_confidence != "low"
                    else current.source_confidence
                ),
                published_at=item.published_at or current.published_at,
                updated_at=item.updated_at or current.updated_at,
                sources=tuple(dict.fromkeys((*current.sources, *item.sources))),
                description=item.description or current.description,
                cvss=item.cvss or current.cvss,
                title=item.title or current.title,
            )
    merged = sorted(by_id.values(), key=lambda rec: rec.advisory_id)
    return merged, added
