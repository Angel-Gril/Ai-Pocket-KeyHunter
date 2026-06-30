from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from .config import settings

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CVSS_RE = re.compile(r"CVSS[:\s]*v?[23]?\.?1?\s*[:\s]*([0-9]+\.?[0-9]*)", re.I)

KNOWN_AI_PRODUCTS = [
    "dify", "flowise", "librechat", "litellm", "open webui", "openwebui",
    "langflow", "mlflow", "langchain", "langgraph", "portkey", "praison",
    "one-api", "new-api", "fastgpt", "anythingllm", "vllm", "text-generation-webui",
    "qdrant", "chromadb", "pinea", "llamafile", "ollama", "localai",
    "glitter", "lobe-chat", "lobechat", "cherry-studio", "dify.ai",
    "baichuan", "qwen", "chatglm", "xmchat",
    "mistral.rs", "mistralrs", "text-generation-inference", "tgi",
    "jan", "chatbox", "chatbot-ollama",
    "simpleoneai", "chatgpt-next-web", "nextchat", "gpt-next-web",
    "chatgpt-next", "chat-ollama",
]

CVE_TYPE_KEYWORDS = {
    "RCE": ["remote code execution", "code execution", "rce", "arbitrary code", "command execution"],
    "认证绕过": ["authentication bypass", "auth bypass", "bypass authentication", "idor"],
    "API key泄露": ["api key", "apikey", "credential leak", "secret leak", "token leak", "hardcoded"],
    "信息泄露": ["information disclosure", "info leak", "data leak", "sensitive info", "ssrf"],
    "权限提升": ["privilege escalation", "privesc", "escalation"],
    "SQL注入": ["sql injection", "sqli"],
    "SSRF": ["ssrf", "server-side request forgery"],
    "沙箱逃逸": ["sandbox escape", "sandbox bypass", "escape sandbox"],
    "DoS": ["denial of service", "dos", "crash", "oom", "out of memory"],
}

SEARCH_QUERIES = [
    "AI LLM gateway CVE 2026 vulnerability RCE",
    "Dify Flowise Langflow CVE 2026",
    "LiteLLM LibreChat OpenWebUI CVE 2026",
    "LangChain LangGraph MLflow CVE 2026 vulnerability",
    "one-api new-api fastgpt CVE 2026",
    "AI proxy gateway api_key leak CVE 2026",
    "site:nvd.nist.gov AI LLM 2026",
    "site:huntr.dev AI LLM vulnerability 2026",
    "site:github.com GHSA AI gateway vulnerability 2026",
]


def _classify_type(text: str) -> str:
    lower = text.lower()
    for vuln_type, keywords in CVE_TYPE_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return vuln_type
    return "信息泄露"


def _extract_products(text: str) -> str:
    lower = text.lower()
    for prod in KNOWN_AI_PRODUCTS:
        if prod in lower:
            return prod
    return ""


def _parse_cve_from_result(result: dict[str, Any]) -> dict[str, Any] | None:
    url = result.get("url", "")
    title = result.get("title", "")
    content = result.get("content", "")
    combined = f"{title} {content}"

    cve_matches = CVE_RE.findall(combined)
    if not cve_matches:
        return None

    cve_id = cve_matches[0].upper()
    if not cve_id.startswith("CVE-2026"):
        return None

    product = _extract_products(combined)
    if not product:
        return None

    cvss_match = CVSS_RE.search(combined)
    cvss = float(cvss_match.group(1)) if cvss_match else 0.0

    cve_type = _classify_type(combined)

    description = content[:300].strip().replace("\n", " ")
    if not description:
        description = title

    return {
        "id": cve_id,
        "cvss": cvss,
        "product": product,
        "type": cve_type,
        "description": description,
        "huntable": "高" if cvss >= 7.0 or cve_type in ("RCE", "认证绕过", "API key泄露") else "中",
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "source_url": url,
    }


async def search_cves(
    queries: list[str] | None = None,
    max_results: int = 10,
    timeout: float = 30.0,
) -> list[dict[str, Any]]:
    if not settings.tavily_key:
        raise RuntimeError("TAVILY_KEY not configured")
    if not settings.tavily_base_url:
        raise RuntimeError("TAVILY_BASE_URL not configured")

    queries = queries or SEARCH_QUERIES
    base = settings.tavily_base_url.rstrip("/")
    found: dict[str, dict[str, Any]] = {}

    async with httpx.AsyncClient(timeout=timeout) as client:
        for q in queries:
            log.info("Tavily search: %s", q[:80])
            try:
                r = await client.post(
                    f"{base}/search",
                    headers={
                        "Authorization": f"Bearer {settings.tavily_key}",
                        "Content-Type": "application/json",
                    },
                    json={"query": q, "max_results": max_results},
                )
            except httpx.HTTPError as e:
                log.warning("  Tavily error: %s", e)
                continue

            if r.status_code != 200:
                log.warning("  Tavily HTTP %d: %s", r.status_code, r.text[:120])
                continue

            try:
                data = r.json()
            except ValueError:
                log.warning("  Tavily non-json response")
                continue

            for result in data.get("results", []):
                parsed = _parse_cve_from_result(result)
                if parsed and parsed["id"] not in found:
                    found[parsed["id"]] = parsed
                    log.info("  found %s | %s | %s", parsed["id"], parsed["product"], parsed["type"])

    return list(found.values())


def merge_cves(
    existing: list[dict[str, Any]],
    new: list[dict[str, Any]],
    path: Path | None = None,
) -> tuple[list[dict[str, Any]], int]:
    path = path or (Path(__file__).resolve().parents[2] / "sources" / "cve_2026_ai.json")
    seen = {c["id"] for c in existing}
    added = 0
    merged = list(existing)
    for cve in new:
        if cve["id"] not in seen:
            merged.append(cve)
            seen.add(cve["id"])
            added += 1

    if added and path:
        merged_sorted = sorted(merged, key=lambda c: c.get("id", ""))
        path.write_text(json.dumps(merged_sorted, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Wrote %d CVEs (%d new) to %s", len(merged_sorted), added, path)

    return merged, added


async def sync_cves() -> tuple[list[dict[str, Any]], int]:
    log.info("Syncing CVEs from Tavily...")
    from .queries import load_cves

    existing = load_cves()
    new = await search_cves()
    return merge_cves(existing, new)
