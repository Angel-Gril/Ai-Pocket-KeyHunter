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
CVSS_RE = re.compile(r"CVSS\s*(?:v[23](?:\.\d)?)?\s*[:/]\s*([0-9]\.[0-9])", re.I)

# Products that STORE or PROXY multiple API keys — one compromise = key jackpot
KNOWN_AI_PRODUCTS = [
    # --- P0: Gateway/Aggregator (stores dozens~hundreds of provider keys) ---
    "one-api", "new-api", "litellm", "openrouter",
    "siliconflow", "silicon flow", "302ai", "302.ai",
    "portkey", "lobe-chat", "lobechat",
    "praisonai", "praison",  # PraisonAI Gateway
    "gitlab ai gateway",
    # --- P1: AI Platforms (stores provider keys in config/DB) ---
    "dify", "flowise", "librechat", "open webui", "openwebui",
    "fastgpt", "anythingllm", "langflow", "mlflow",
    "langchain-chatchat", "langchain chatchat",
    "wandb",  # hardcoded LITELLM_MASTER_KEY
    # --- P2: Chat UIs (often deployed with naked provider keys in env) ---
    "chatgpt-next-web", "nextchat", "cherry-studio",
    "chat-ollama", "chatbox",
    # --- Chinese AI platforms (direct key targets) ---
    "deepseek", "chatglm", "qwen", "dashscope", "moonshot",
]

# Only CVE types that lead to API key extraction
CVE_TYPE_KEYWORDS = {
    "API key泄露": ["api key", "apikey", "api_key", "credential leak", "secret leak",
                   "token leak", "hardcoded", "env var", "environment variable",
                   "exfiltrat", "leaking", "expose key", "expose credential",
                   "default credential", "default password", "plaintext"],
    "认证绕过": ["authentication bypass", "auth bypass", "bypass authentication",
                "idor", "unauthorized access", "no authentication",
                "without authentication", "unauthenticated", "cors"],
    "SSRF": ["ssrf", "server-side request forgery", "internal endpoint",
             "metadata endpoint", "169.254", "redirect", "internal service"],
    "信息泄露": ["information disclosure", "info leak", "data leak",
                "config leak", "path traversal", "directory traversal",
                "env exposure", ".env"],
    "SQL注入": ["sql injection", "sqli", "database", "read/modify",
               "cypher injection"],
    "RCE": ["remote code execution", "code execution", "rce", "arbitrary code",
             "command execution", "command injection"],
    "权限提升": ["privilege escalation", "privesc", "role elevation",
                "proxy_admin", "admin access"],
}

# Queries laser-focused on key-leaking attack surfaces
SEARCH_QUERIES = [
    # Direct key leak CVEs in AI gateways (2025+2026, old CVEs still exploitable)
    "one-api new-api LiteLLM CVE 2026 API key leak credential",
    "one-api new-api LiteLLM CVE 2025 API key credential",
    "AI gateway credential exposure environment variable leak CVE 2026",
    # Auth bypass → access gateway key management
    "LiteLLM Dify Flowise authentication bypass CVE 2026",
    "one-api new-api admin bypass unauthenticated CVE 2026",
    "Portkey PraisonAI gateway SSRF authentication bypass CVE",
    # SSRF → reach internal key stores / cloud metadata
    "OpenWebUI LibreChat Dify SSRF CVE 2026 internal",
    # RCE on gateways = dump all stored keys
    "LiteLLM Flowise LibreChat RCE CVE 2026 gateway",
    "Langflow MLflow RCE credential CVE 2026",
    # Config/env leak in AI deployments
    "LobeChat FastGPT config leak api_key env CVE 2026",
    # Authoritative sources (narrowed to key-relevant)
    "site:huntr.dev AI LLM api key leak 2026",
    "site:nvd.nist.gov litellm one-api dify flowise 2026",
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
    if not (cve_id.startswith("CVE-2026") or cve_id.startswith("CVE-2025")):
        return None

    product = _extract_products(combined)
    if not product:
        return None

    cvss_match = CVSS_RE.search(combined)
    cvss = float(cvss_match.group(1)) if cvss_match else 0.0

    cve_type = _classify_type(combined)

    # Filter garbage: skip descriptions that are clearly page boilerplate
    description = content[:500].strip().replace("\n", " ")
    garbage_signals = [
        "cookie", "opens in a new window", "opens in a new tab",
        "this website utilizes technologies", "survey opens",
        "change history", "change records found show changes",
    ]
    desc_lower = description.lower()
    if any(sig in desc_lower for sig in garbage_signals):
        # Fall back to title which is usually cleaner
        description = title
    # Trim to reasonable length
    description = description[:300]
    if not description:
        description = title

    return {
        "id": cve_id,
        "cvss": cvss,
        "product": product,
        "type": cve_type,
        "description": description,
        "huntable": "高" if cve_type in ("API key泄露", "认证绕过", "SSRF") or cvss >= 8.0 else "中",
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
