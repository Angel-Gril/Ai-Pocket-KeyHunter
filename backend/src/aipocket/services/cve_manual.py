"""Manually add CVE / advisory records from a URL or form fields.

Manual entries are merged via ``merge_cves`` so they land in the same PG
``cves`` table (and optional JSONL file) as Tavily-synced rows. Subsequent
``sync_cves`` loads the full existing set first and only upserts new/changed
records — it never deletes — so manual rows survive sync.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from aipocket.clients.advisories import parse_advisory_from_text
from aipocket.clients.tavily import CVSS_RE, _classify_type, _extract_products, merge_cves

log = logging.getLogger(__name__)

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_GHSA_ID_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.I)
_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style)[^>]*>.*?</\1>")
_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
_TAG_RE = re.compile(r"(?is)<[^>]+>")
_WS_RE = re.compile(r"\s+")

VALID_TYPES = (
    "API key泄露",
    "认证绕过",
    "SSRF",
    "信息泄露",
    "SQL注入",
    "RCE",
    "权限提升",
)

VALID_HUNTABLE = ("高", "中", "低")


def _now_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_url(url: str) -> str:
    raw = url.strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL 必须以 http:// 或 https:// 开头")
    return raw


def _html_to_title_and_text(html: str) -> tuple[str, str]:
    cleaned = _SCRIPT_STYLE_RE.sub(" ", html)
    title_match = _TITLE_RE.search(cleaned)
    title = _WS_RE.sub(" ", _TAG_RE.sub(" ", title_match.group(1))).strip() if title_match else ""
    text = _WS_RE.sub(" ", _TAG_RE.sub(" ", cleaned)).strip()
    return title, text


async def fetch_url_text(url: str, *, timeout: float = 20.0) -> tuple[str, str]:
    """Fetch a page and return ``(title, text)`` best-effort."""
    headers = {
        "User-Agent": "aipocket-cve-manual/1.0 (+https://github.com/aipocket)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        try:
            response = await client.get(url)
        except httpx.HTTPError as exc:
            raise ValueError(f"无法访问该 URL: {exc}") from exc

    if response.status_code >= 400:
        raise ValueError(f"URL 返回 HTTP {response.status_code}")

    content_type = response.headers.get("content-type", "").lower()
    body = response.text or ""
    if "html" in content_type or body.lstrip().lower().startswith(("<!doctype", "<html")):
        return _html_to_title_and_text(body)
    # Plain text / markdown / JSON-ish advisory pages
    text = _WS_RE.sub(" ", body).strip()
    title = text[:120]
    return title, text


def _fallback_parse(*, title: str, content: str, url: str) -> dict[str, Any] | None:
    """Lightweight CVE-only fallback when the advisory parser rejects the page."""
    combined = f"{title} {content} {url}"
    cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", combined, re.I)
    if not cve_match:
        return None
    cve_id = cve_match.group(0).upper()
    product = _extract_products(combined)
    if not product:
        return None
    cvss_match = CVSS_RE.search(combined)
    cvss = float(cvss_match.group(1)) if cvss_match else 0.0
    cve_type = _classify_type(combined)
    description = (content or title)[:300].strip()
    return {
        "id": cve_id,
        "cvss": cvss,
        "product": product,
        "type": cve_type,
        "description": description,
        "huntable": "高"
        if cve_type in ("API key泄露", "认证绕过", "SSRF") or cvss >= 8.0
        else "中",
        "date": _now_date(),
        "source_url": url,
        "updated_at": _now_iso(),
    }


def _apply_overrides(record: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    out = dict(record)
    for key, value in overrides.items():
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if key == "cvss" and value in (0, 0.0) and out.get("cvss"):
            # Keep parsed score unless the caller explicitly set a positive one
            # or the base had none.
            continue
        out[key] = value
    return out


def _normalize_manual_fields(
    *,
    cve_id: str = "",
    product: str = "",
    cve_type: str = "",
    description: str = "",
    source_url: str = "",
    cvss: float = 0.0,
    huntable: str = "",
) -> dict[str, Any]:
    cid = cve_id.strip().upper()
    # Allow free-form IDs (e.g. vendor advisories) but keep them non-empty.
    known_id = bool(
        _CVE_ID_RE.match(cid)
        or _GHSA_ID_RE.match(cid)
        or cid.startswith("HUNTR-")
        or cid.startswith("DISCLOSURE-")
    )
    if cid and not known_id and len(cid) < 3:
        raise ValueError("CVE ID 无效")

    product_clean = product.strip()
    type_clean = cve_type.strip() or "信息泄露"
    if type_clean not in VALID_TYPES:
        type_clean = "信息泄露"

    hunt = huntable.strip()
    if hunt not in VALID_HUNTABLE:
        hunt = "高" if type_clean in ("API key泄露", "认证绕过", "SSRF") or cvss >= 8.0 else "中"

    if not cid:
        raise ValueError("请填写 CVE / GHSA ID，或提供可解析的 URL")
    if not product_clean:
        raise ValueError("请填写产品名称，或提供可解析出产品的 URL")

    return {
        "id": cid,
        "cvss": float(cvss or 0.0),
        "product": product_clean,
        "type": type_clean,
        "description": description.strip()[:500],
        "huntable": hunt,
        "date": _now_date(),
        "source_url": source_url.strip(),
        "updated_at": _now_iso(),
    }


async def build_cve_from_input(
    *,
    url: str = "",
    cve_id: str = "",
    product: str = "",
    cve_type: str = "",
    description: str = "",
    cvss: float = 0.0,
    huntable: str = "",
) -> dict[str, Any]:
    """Build a legacy CVE dict from a URL and/or explicit fields."""
    source_url = _validate_url(url) if url else ""
    overrides: dict[str, Any] = {
        "id": cve_id.strip().upper() if cve_id.strip() else None,
        "product": product.strip() or None,
        "type": cve_type.strip() or None,
        "description": description.strip() or None,
        "source_url": source_url or None,
        "cvss": cvss if cvss and cvss > 0 else None,
        "huntable": huntable.strip() or None,
    }

    record: dict[str, Any] | None = None
    if source_url:
        title, text = await fetch_url_text(source_url)
        # Cap text for parser / storage
        content = text[:8000]
        advisory = parse_advisory_from_text(title=title, content=content, url=source_url)
        if advisory is not None:
            record = advisory.to_legacy_cve_dict()
            cvss_match = CVSS_RE.search(f"{title} {content}")
            if cvss_match and not record.get("cvss"):
                record["cvss"] = float(cvss_match.group(1))
            product_guess = _extract_products(f"{title} {content}")
            if product_guess and not record.get("product"):
                record["product"] = product_guess
        else:
            record = _fallback_parse(title=title, content=content, url=source_url)

        if record is None:
            # Partial parse: still try to seed id/description from the page
            combined = f"{title} {content} {source_url}"
            cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", combined, re.I)
            ghsa_match = re.search(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", combined, re.I)
            seed_id = (
                (cve_match.group(0).upper() if cve_match else "")
                or (ghsa_match.group(0).upper() if ghsa_match else "")
                or cve_id.strip().upper()
            )
            seed_product = _extract_products(combined) or product.strip()
            if seed_id and seed_product:
                record = {
                    "id": seed_id,
                    "cvss": float(cvss or 0.0),
                    "product": seed_product,
                    "type": cve_type.strip() or _classify_type(combined),
                    "description": (description.strip() or content or title)[:300],
                    "huntable": huntable.strip() or "中",
                    "date": _now_date(),
                    "source_url": source_url,
                    "updated_at": _now_iso(),
                }
            elif cve_id.strip() and product.strip():
                # User supplied enough fields; page only used as source_url
                record = None
            else:
                raise ValueError(
                    "无法从该 URL 解析 CVE。请补充 ID 与产品名称，或换一个 advisory 链接"
                )

    if record is not None:
        record = _apply_overrides(record, overrides)
        if not record.get("source_url") and source_url:
            record["source_url"] = source_url
        if not record.get("date"):
            record["date"] = _now_date()
        if not record.get("updated_at"):
            record["updated_at"] = _now_iso()
        if not record.get("id") or not record.get("product"):
            # Overrides still incomplete → fall through to full manual normalize
            record = None

    if record is None:
        record = _normalize_manual_fields(
            cve_id=cve_id,
            product=product,
            cve_type=cve_type,
            description=description,
            source_url=source_url,
            cvss=cvss,
            huntable=huntable,
        )

    record["manual"] = True
    record["updated_at"] = _now_iso()
    if not record.get("date"):
        record["date"] = _now_date()
    if not record.get("description"):
        record["description"] = f"{record.get('product', '')} · {record.get('type', '')}".strip(
            " ·"
        )
    return record


async def add_manual_cve(
    *,
    url: str = "",
    cve_id: str = "",
    product: str = "",
    cve_type: str = "",
    description: str = "",
    cvss: float = 0.0,
    huntable: str = "",
) -> tuple[dict[str, Any], bool, int]:
    """Parse/build a CVE and merge into the store.

    Returns ``(record, created, total)`` where ``created`` is True when the id
    was new, False when an existing row was updated.
    """
    if not url.strip() and not cve_id.strip():
        raise ValueError("请至少填写 URL 或 CVE ID")

    record = await build_cve_from_input(
        url=url,
        cve_id=cve_id,
        product=product,
        cve_type=cve_type,
        description=description,
        cvss=cvss,
        huntable=huntable,
    )

    from aipocket.services.queries import load_cves

    existing = load_cves()
    existed = any(c.get("id") == record["id"] for c in existing)
    merged, _added = merge_cves(existing, [record])
    # merge_cves ``added`` only counts brand-new ids; recompute for clarity
    created = not existed
    total = len(merged)
    log.info(
        "Manual CVE %s: %s (product=%s, total=%d)",
        "added" if created else "updated",
        record["id"],
        record.get("product"),
        total,
    )
    return record, created, total
