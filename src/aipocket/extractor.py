from __future__ import annotations

import logging
import re
from typing import Any

from .models import Credential

log = logging.getLogger(__name__)

APIKEY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai", re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b")),
    ("openai_legacy", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("generic", re.compile(r"\b(?:api[_-]?key|apikey|authorization|bearer)[\"'\s:=]+([A-Za-z0-9_\-\.]{20,})\b", re.I)),
]

URL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai_url", re.compile(r"\b(?:https?://[a-z0-9.\-]*openai\.com(?:/v1)?)\b", re.I)),
    ("anthropic_url", re.compile(r"\b(?:https?://[a-z0-9.\-]*anthropic\.com(?:/v1)?)\b", re.I)),
    ("generic_apiurl", re.compile(r'\b(?:api[_-]?url|base[_-]?url|api[_-]?base|endpoint)[":\s=\']*?(https?://[^\s"\'<>]+)', re.I)),
    ("bare_v1", re.compile(r'\b(https?://[a-z0-9.\-]+(?::\d+)?/v1)\b', re.I)),
]

DETECTION_ENDPOINT_HINTS = {
    "litellm": "/v1",
    "flowise": "/api/v1",
    "dify": "/console/api",
    "librechat": "/api",
    "openwebui": "/api/v1",
    "langflow": "/api/v1",
    "one-api": "/v1",
    "new-api": "/v1",
}


def extract_credentials(hits: list[dict[str, Any]]) -> list[Credential]:
    creds: list[Credential] = []
    seen_keys: set[tuple[str, str]] = set()

    for hit in hits:
        host = hit.get("host", "") or hit.get("link", "")
        ip = hit.get("ip", "")
        port = hit.get("port", "")
        product = hit.get("product", "")

        combined = _scan_blob(hit)

        local_creds = combined["credentials"]
        api_urls = combined["api_urls"]

        base_url = _infer_base_url(hit, api_urls)

        for cred in local_creds:
            dedup_key = (cred.apikey, base_url or cred.host)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            cred.apiurl = cred.apiurl or base_url
            cred.host = host
            cred.ip = ip
            cred.port = port
            cred.product = product
            creds.append(cred)

    return creds


def _scan_blob(hit: dict[str, Any]) -> dict[str, Any]:
    credentials: list[Credential] = []
    api_urls: set[str] = set()

    for field in ("header", "banner", "cert", "title"):
        blob = hit.get(field, "")
        if not blob:
            continue
        _scan_text(blob, field, hit, credentials, api_urls)

    link = hit.get("link", "")
    if link:
        api_urls.add(link)

    return {"credentials": credentials, "api_urls": api_urls}


def _scan_text(
    text: str,
    field: str,
    hit: dict[str, Any],
    out_creds: list[Credential],
    out_urls: set[str],
) -> None:
    if not text:
        return

    matched_keys: dict[str, str] = {}
    for label, pat in APIKEY_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            val = val.strip().strip("\"':,;")
            if len(val) < 15:
                continue
            matched_keys.setdefault(val, label)

    for _label, pat in URL_PATTERNS:
        for m in pat.finditer(text):
            url = m.group(1) if m.groups() else m.group(0)
            url = url.strip().strip("\"':,;").rstrip("\\").rstrip("/")
            if url.startswith("http"):
                out_urls.add(url)

    source_type = "header" if field == "header" else ("banner" if field == "banner" else "body")
    for key, keytype in matched_keys.items():
        out_creds.append(
            Credential(
                apikey=key,
                apiurl="",
                source=keytype,
                source_type=source_type,
                host=hit.get("host", ""),
                raw_context=text[:500],
            )
        )


def _infer_base_url(hit: dict[str, Any], api_urls: set[str]) -> str:
    if api_urls:
        priority = [u for u in api_urls if "v1" in u] or list(api_urls)
        return sorted(priority)[0].rstrip("/")

    host = hit.get("host", "")
    if not host:
        return ""
    proto = hit.get("protocol", "https")
    if proto not in ("http", "https"):
        proto = "https"
    if not host.startswith("http"):
        host = f"{proto}://{host}"

    title = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
    for fingerprint, suffix in DETECTION_ENDPOINT_HINTS.items():
        if fingerprint in title:
            return f"{host.rstrip('/')}{suffix}"

    return host.rstrip("/")
