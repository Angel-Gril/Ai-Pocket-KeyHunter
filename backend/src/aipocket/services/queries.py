from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Default CVE map. Override with AIPOCKET_CVE_PATH (e.g. sources/cve_realtest.json)
# to run a small end-to-end real scan against a trimmed CVE subset.
_DEFAULT_CVE_PATH = Path(__file__).resolve().parents[3] / "sources" / "cve_2026_ai.json"
CVE_PATH = Path(os.environ.get("AIPOCKET_CVE_PATH", _DEFAULT_CVE_PATH))


PRODUCT_QUERIES: dict[str, list[str]] = {
    "LiteLLM": [
        'body="litellm" && body="sk-"',
        'body="litellm_proxy" && body="api_key"',
        'body="LiteLLM Proxy" && body="master_key"',
    ],
    "Flowise": [
        'body="Flowise" && body="sk-"',
        'body="flowise" && body="apiKey"',
    ],
    "Dify": [
        'body="dify" && body="sk-"',
        'body="dify" && body="OPENAI_API_KEY"',
        'body="dify" && body="ANTHROPIC_API_KEY"',
    ],
    "LibreChat": [
        'body="librechat" && body="sk-"',
        'body="librechat" && body="OPENAI_API_KEY"',
        'body="librechat" && body="ANTHROPIC_API_KEY"',
    ],
    "OpenWebUI": [
        'body="Open WebUI" && body="sk-"',
        'body="open-webui" && body="api_key"',
    ],
    "Langflow": [
        'body="langflow" && body="sk-"',
        'body="langflow" && body="OPENAI_API_KEY"',
    ],
    "MLflow": [
        'body="mlflow" && body="sk-"',
        'body="mlflow" && body="api_key"',
    ],
    "Portkey AI Gateway": [
        'body="portkey" && body="sk-"',
        'body="portkey" && body="api_key"',
    ],
    "LangChain": [
        'body="langchain" && body="OPENAI_API_KEY"',
        'body="langchain" && body="sk-"',
    ],
    "PraisonAI": [
        'body="praisonai" && body="sk-"',
    ],
    "GitLab AI Gateway": [
        'body="ai-gateway" && body="sk-"',
    ],
    "FastGPT": [
        'body="fastgpt" && body="sk-"',
        'body="fastgpt" && body="OPENAI_API_KEY"',
    ],
    "New-API": [
        'body="new-api" && body="sk-"',
        'body="new-api" && body="token"',
    ],
    "AnythingLLM": [
        'body="anythingllm" && body="sk-"',
        'body="anythingllm" && body="OPENAI_API_KEY"',
    ],
    "ChatGPT-Next-Web": [
        'body="nextchat" && body="sk-"',
        'body="chatgpt-next-web" && body="OPENAI_API_KEY"',
    ],
    "vLLM": [
        'body="vllm" && body="sk-"',
        'body="vllm" && body="api_key"',
    ],
    "Ollama": [
        'body="ollama" && body="sk-"',
    ],
    "LocalAI": [
        'body="localai" && body="sk-"',
    ],
    "Text-Generation-WebUI": [
        'body="text-generation-webui" && body="sk-"',
    ],
    "LobeChat": [
        'body="lobe-chat" && body="sk-"',
        'body="lobechat" && body="OPENAI_API_KEY"',
    ],
    "Jan": [
        'body="jan.ai" && body="sk-"',
    ],
    "Claude": [
        'body="claude" && body="sk-ant-"',
        'body="ANTHROPIC_API_KEY" && body="sk-ant-"',
        'body="anthropic" && body="api_key" && body="sk-"',
    ],
    "Codex CLI": [
        'body="codex" && body="OPENAI_API_KEY"',
    ],
}

VULN_TYPE_PRIORITIES = {
    "API key泄露": 1,
    "信息泄露": 1,
    "认证绕过": 1,
    "RCE": 2,
    "权限提升": 2,
    "SSRF": 3,
    "SQL注入": 2,
    "沙箱逃逸": 3,
    "DoS": 5,
}

# Credential leak queries — not CVE-bound, hit plaintext keys in exposed headers/banners/bodies.
# FOFA proxy (fofoapi.com) does NOT return the `body` field in results, so `body=`
# queries work as *filters* (FOFA matches the body) but we can only extract keys from
# the `header`/`banner` fields we actually get back.
#
# Strategy: lead with header=/banner= queries (highest ROI — we get that content back),
# keep a smaller set of body= queries as net to catch hosts that also leak in header/banner.
CREDENTIAL_QUERIES: list[str] = [
    # --- Header queries that ACTUALLY work (full header string match) ---
    # These return few results but keys are directly extractable from header field.
    'header="authorization: bearer sk-"',
    'header="authorization: bearer sk-proj"',
    'header="authorization: bearer sk-ant-"',
    'header="x-api-key: sk-"',
    'header="x-api-key: sk-ant-"',
    'header="api-key: sk-"',
    'header="apikey: sk-"',
    'banner="authorization: bearer sk-"',
    'banner="authorization: bearer sk-proj"',
    'banner="authorization: bearer sk-ant-"',
    'banner="OPENAI_API_KEY=sk-"',
    'banner="ANTHROPIC_API_KEY=sk-ant-"',
    # --- Body queries: find hosts with keys in page → GenericPageProber extracts ---
    # These are HIGH VOLUME but GenericPageProber fetches the actual key.
    'body="sk-proj-"',
    'body="sk-ant-api"',
    'body="OPENAI_API_KEY" && body="sk-"',
    'body="ANTHROPIC_API_KEY" && body="sk-ant-"',
    'body="DEEPSEEK_API_KEY" && body="sk-"',
    'body=".env" && body="sk-"',
    'body="docker-compose" && body="sk-"',
    'body="api_key" && body="sk-proj-"',
    # --- Domestic providers ---
    'body="moonshot" && body="sk-"',
    'body="deepseek" && body="sk-"',
    # --- Exposed config / gateway leaks ---
    'body="master_key" && body="sk-"',
    'body="DANGEROUSLY_DISABLE_AUTH" && body="sk-"',
]


def load_cves(path: Path | None = None) -> list[dict[str, Any]]:
    """Load the CVE map.

    An explicit ``path`` always reads that file (used by ``--realtest`` for a
    trimmed subset). With no path: read PG (``cves`` table) when enabled, falling
    back to the file if the table is empty (pre-backfill), else read the default
    file.
    """
    if path is not None:
        return _load_cves_file(path)

    from aipocket.core.config import settings

    if settings.pg_enabled:
        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn:
            rows = conn.execute("SELECT record FROM cves ORDER BY id").fetchall()
        if rows:
            return [r["record"] for r in rows]
        # Empty table (not yet backfilled) → fall back to the file.

    return _load_cves_file(CVE_PATH)


def _load_cves_file(p: Path) -> list[dict[str, Any]]:
    try:
        text = p.read_text(encoding="utf-8").strip()
        return json.loads(text) if text else []
    except (json.JSONDecodeError, FileNotFoundError):
        return []


SKIP_PRODUCTS = frozenset({
    "langgraph", "langsmith",
})


def _should_skip(product: str) -> bool:
    p = product.lower()
    return any(s in p for s in SKIP_PRODUCTS)


def build_queries(cves: list[dict[str, Any]] | None = None, *, skip_direct: bool = False) -> list[dict[str, str]]:
    cves = cves or load_cves()
    seen: set[str] = set()
    out: list[dict[str, str]] = []

    for tmpl in CREDENTIAL_QUERIES:
        if skip_direct:
            continue
        q = tmpl
        if q in seen:
            continue
        seen.add(q)
        out.append({
            "query": q,
            "cve_id": "DIRECT-CRED-LEAK",
            "product": "generic",
            "type": "API key泄露",
            "cvss": "",
        })

    sorted_cves = sorted(cves, key=lambda c: (VULN_TYPE_PRIORITIES.get(c.get("type", ""), 9), -c.get("cvss", 0)))

    for cve in sorted_cves:
        product = cve.get("product", "")
        cve_type = cve.get("type", "")
        priority = VULN_TYPE_PRIORITIES.get(cve_type, 9)
        if priority > 4:
            continue

        if _should_skip(product):
            continue

        base_product = _normalize_product(product)
        templates = PRODUCT_QUERIES.get(base_product)
        if not templates:
            continue

        for tmpl in templates:
            q = f"{tmpl} && status_code=\"200\""
            if q in seen:
                continue
            seen.add(q)
            out.append(
                {
                    "query": q,
                    "cve_id": cve["id"],
                    "product": product,
                    "type": cve_type,
                    "cvss": str(cve.get("cvss", "")),
                }
            )

    return out


def _normalize_product(product: str) -> str:
    p = product.lower()
    for key in PRODUCT_QUERIES:
        if key.lower() in p or p in key.lower():
            return key
    if "litellm" in p:
        return "LiteLLM"
    if "flowise" in p:
        return "Flowise"
    if "dify" in p:
        return "Dify"
    if "librechat" in p:
        return "LibreChat"
    if "openwebui" in p or "open webui" in p:
        return "OpenWebUI"
    if "langflow" in p:
        return "Langflow"
    if "mlflow" in p:
        return "MLflow"
    if "portkey" in p:
        return "Portkey AI Gateway"
    if "langchain" in p:
        return "LangChain"
    if "praison" in p:
        return "PraisonAI"
    if "gitlab" in p:
        return "GitLab AI Gateway"
    if "new-api" in p or "newapi" in p:
        return "New-API"
    if "fastgpt" in p:
        return "FastGPT"
    if "anythingllm" in p:
        return "AnythingLLM"
    if "next-web" in p or "nextchat" in p:
        return "ChatGPT-Next-Web"
    if "vllm" in p:
        return "vLLM"
    if "ollama" in p:
        return "Ollama"
    if "localai" in p:
        return "LocalAI"
    if "text-generation" in p or "oobabooga" in p:
        return "Text-Generation-WebUI"
    if "lobe" in p:
        return "LobeChat"
    if "jan.ai" in p:
        return "Jan"
    if "wandb" in p or "weight & bias" in p:
        return "OpenWebUI"
    return product
