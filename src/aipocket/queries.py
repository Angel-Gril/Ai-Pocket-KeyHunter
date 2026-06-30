from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

CVE_PATH = Path(__file__).resolve().parents[2] / "sources" / "cve_2026_ai.json"


PRODUCT_QUERIES: dict[str, list[str]] = {
    "LiteLLM": [
        'body="LiteLLM" || header="LiteLLM"',
        'body="litellm_proxy" || body="litellm-dashboard"',
        'body="LiteLLM Proxy" && body="api_key"',
        'header="x-litellm"',
    ],
    "Flowise": [
        'body="Flowise" || header="Flowise"',
        'body="/api/v1/chat-messages" && body="flowise"',
        'icon_hash="-1720536238"',
    ],
    "Dify": [
        'body="dify" || header="dify"',
        'body="console/api" && body="dify"',
        'body="Next.js" && body="/console/api/setup"',
    ],
    "LibreChat": [
        'body="LibreChat" || header="LibreChat"',
        'body="librechat" && body="/api/auth"',
        'body="/api/keys" && body="librechat"',
    ],
    "OpenWebUI": [
        'body="Open WebUI" || header="open-webui"',
        'body="open-webui" && body="/api/v1"',
    ],
    "Langflow": [
        'body="langflow" || header="langflow"',
        'body="/api/v1/flows" && body="langflow"',
    ],
    "MLflow": [
        'header="MLflow" || body="mlflow"',
        'body="ajax-api" && body="mlflow"',
    ],
    "Portkey AI Gateway": [
        'header="x-portkey" || body="portkey"',
    ],
    "LangChain": [
        'body="langchain" && (body="api_key" || body="openai_api_key")',
    ],
    "PraisonAI": [
        'body="praisonai" || header="praison"',
    ],
    "GitLab AI Gateway": [
        'header="X-Gitlab-Duo" || body="ai-gateway"',
    ],
    "FastGPT": [
        'body="fastgpt" || header="fastgpt"',
        'body="/api/v1" && body="fastgpt"',
    ],
    "New-API": [
        'body="new-api" || body="new api"',
        'body="/api/status" && body="new-api"',
    ],
    "AnythingLLM": [
        'body="anythingllm" || header="anythingllm"',
        'body="/api/v1/workspaces" && body="anythingllm"',
    ],
    "ChatGPT-Next-Web": [
        'body="nextchat" || body="chatgpt-next-web"',
        'body="ChatGPT Next Web" && body="api"',
    ],
    "vLLM": [
        'header="vllm" || body="vllm"',
        'body="/v1/models" && body="vllm"',
    ],
    "Ollama": [
        'header="ollama" || body="ollama"',
        'body="/api/tags" && body="ollama"',
    ],
    "LocalAI": [
        'body="localai" || header="localai"',
        'body="/v1/models" && body="localai"',
    ],
    "Text-Generation-WebUI": [
        'body="text-generation-webui" || body="oobabooga"',
    ],
    "LobeChat": [
        'body="lobe-chat" || body="lobechat"',
        'body="LobeChat" && body="/api"',
    ],
    "Jan": [
        'body="jan.ai" || body="Jan AI"',
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
# Fields we can RETRIEVE from current FOFA plan: header, banner, cert, title (NOT body).
# body="..." queries still work as FILTERS (FOFA matches on body) — if those hosts also
# leak keys in header/banner, we'll catch them. Header/banner queries are highest-ROI
# because we actually get that content back.
CREDENTIAL_QUERIES: list[str] = [
    # --- OpenAI official keys: sk-proj-*, sk-* ---
    'header="authorization: bearer sk-"',
    'header="authorization: bearer sk-proj-"',
    'header="x-api-key: sk-"',
    'banner="authorization: bearer sk-"',
    'banner="authorization: bearer sk-proj-"',
    # --- body-filtered (host has key in body; we catch if also in header/banner) ---
    'body="OPENAI_API_KEY=sk-"',
    'body="OPENAI_API_KEY=sk-proj-"',
    'body="api_key=sk-proj-"',
    'body="apiKey=sk-proj-"',
    'body="api_key=sk-"',
    'body="apiKey=sk-"',
    'body="authorization=Bearer%20sk-"',
    'body="sk-ant-"',
    'body="ANTHROPIC_API_KEY=sk-ant-"',
    'body=".env" && body="OPENAI_API_KEY"',
    'body="config.yml" && body="api_key"',
    'body="OPENAI_API_KEY" && body="sk-"',
    'body="OPENAI_API_KEY" && body="sk-proj-"',
    'body="\\"api_key\\":\\"sk-"',
    'body="DANGEROUSLY_DISABLE_AUTH" && body="sk-"',
]


def load_cves(path: Path | None = None) -> list[dict[str, Any]]:
    p = path or CVE_PATH
    with p.open(encoding="utf-8") as f:
        return json.load(f)


SKIP_PRODUCTS = frozenset({
    "claude code", "claude desktop", "langgraph", "langsmith",
})


def _should_skip(product: str) -> bool:
    p = product.lower()
    return any(s in p for s in SKIP_PRODUCTS)


def build_queries(cves: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    cves = cves or load_cves()
    seen: set[str] = set()
    out: list[dict[str, str]] = []

    for tmpl in CREDENTIAL_QUERIES:
        q = f'{tmpl} && status_code="200"'
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
        if priority > 3:
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
