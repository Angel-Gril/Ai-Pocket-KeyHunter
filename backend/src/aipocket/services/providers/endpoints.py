from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit


@dataclass(frozen=True, slots=True)
class CanonicalEndpoint:
    api_base: str
    origin: str


_OFFICIAL_BASES: dict[str, dict[str, str]] = {
    "openai": {"api.openai.com": "/v1"},
    "anthropic": {"api.anthropic.com": "/v1"},
    "deepseek": {"api.deepseek.com": ""},
    "kimi": {
        "api.moonshot.cn": "/v1",
        "api.moonshot.ai": "/v1",
    },
    "glm": {"open.bigmodel.cn": "/api/paas/v4"},
    "nvidia": {"integrate.api.nvidia.com": "/v1"},
    "ksyun": {"kspmas.ksyun.com": "/v1"},
}

_MINIMAX_HOSTS = frozenset({"api.minimax.io", "api.minimaxi.com", "api.minimax.chat"})
_OPERATION_SUFFIXES = (
    "/chat/completions",
    "/messages",
    "/models",
    "/user/balance",
    "/users/me/balance",
    "/token_plan/remains",
)


def _parse_url(raw_url: str) -> SplitResult | None:
    value = (raw_url or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = f"https://{value}"
    try:
        parsed = urlsplit(value)
    except ValueError:
        # urllib raises ValueError for invalid IPv6 / bracketed netlocs.
        return None
    try:
        host = parsed.hostname
    except ValueError:
        return None
    if not host:
        return None
    return parsed


def _netloc(parsed: SplitResult) -> str:
    host = (parsed.hostname or "").lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    default_port = (parsed.scheme.lower() == "https" and port == 443) or (
        parsed.scheme.lower() == "http" and port == 80
    )
    if port is not None and not default_port:
        return f"{host}:{port}"
    return host


def _origin(parsed: SplitResult) -> str:
    scheme = parsed.scheme.lower() if parsed.scheme.lower() in {"http", "https"} else "https"
    return urlunsplit((scheme, _netloc(parsed), "", "", ""))


def _strip_operation_path(path: str) -> str:
    normalized = "/" + "/".join(part for part in path.split("/") if part)
    if normalized == "/":
        return ""
    lowered = normalized.lower()
    for suffix in _OPERATION_SUFFIXES:
        if lowered.endswith(suffix):
            base = normalized[: -len(suffix)].rstrip("/")
            if suffix == "/models" and base.lower() == "/v1":
                return ""
            return base
    return normalized.rstrip("/")


def canonicalize_endpoint(raw_url: str, *, provider: str) -> CanonicalEndpoint:
    """Return the stable API base and origin without mutating a credential key."""
    parsed = _parse_url(raw_url)
    if parsed is None:
        return CanonicalEndpoint(api_base="", origin="")

    origin = _origin(parsed)
    host = (parsed.hostname or "").lower().rstrip(".")
    provider_name = (provider or "unknown").lower()

    official_path = _OFFICIAL_BASES.get(provider_name, {}).get(host)
    if official_path is not None:
        return CanonicalEndpoint(api_base=f"{origin}{official_path}", origin=origin)

    if provider_name == "minimax" and host in _MINIMAX_HOSTS:
        return CanonicalEndpoint(api_base=f"{origin}/v1", origin=origin)

    if provider_name == "longcat" and host == "api.longcat.chat":
        raw_path = parsed.path.lower()
        protocol_path = "/anthropic" if raw_path.startswith("/anthropic") else "/openai"
        return CanonicalEndpoint(api_base=f"{origin}{protocol_path}", origin=origin)

    path = _strip_operation_path(parsed.path)
    return CanonicalEndpoint(api_base=f"{origin}{path}", origin=origin)


def _append_openai_operation(api_base: str, operation_path: str) -> str:
    base = api_base.rstrip("/")
    if base.endswith("/v1"):
        return f"{base}/{operation_path}"
    return f"{base}/v1/{operation_path}"


def build_operation_url(
    endpoint: CanonicalEndpoint,
    *,
    provider: str,
    operation: str,
) -> str:
    """Build one request URL from a canonical API base without persisting it."""
    base = endpoint.api_base.rstrip("/")
    if not base:
        return ""
    provider_name = (provider or "unknown").lower()
    op = operation.lower().replace("-", "_")

    if provider_name == "longcat":
        if base.endswith("/anthropic"):
            paths = {
                "chat": "v1/messages",
                "messages": "v1/messages",
                "models": "v1/models",
            }
        else:
            paths = {
                "chat": "v1/chat/completions",
                "messages": "v1/chat/completions",
                "models": "v1/models",
            }
        path = paths.get(op)
        return f"{base}/{path}" if path else ""

    explicit: dict[str, dict[str, str]] = {
        "anthropic": {"chat": "messages", "messages": "messages", "models": "models"},
        "deepseek": {
            "chat": "v1/chat/completions",
            "messages": "v1/chat/completions",
            "models": "v1/models",
            "balance": "user/balance",
        },
        "kimi": {
            "chat": "chat/completions",
            "messages": "chat/completions",
            "models": "models",
            "balance": "users/me/balance",
        },
        "minimax": {
            "chat": "chat/completions",
            "messages": "chat/completions",
            "models": "models",
            "plan": "token_plan/remains",
            "quota": "token_plan/remains",
        },
        "glm": {"chat": "chat/completions", "messages": "chat/completions", "models": "models"},
        "qwen": {"chat": "chat/completions", "messages": "chat/completions", "models": "models"},
    }
    provider_paths = explicit.get(provider_name)
    if provider_paths is not None:
        path = provider_paths.get(op)
        return f"{base}/{path}" if path else ""

    if op in {"chat", "messages"}:
        return _append_openai_operation(base, "chat/completions")
    if op == "models":
        return _append_openai_operation(base, "models")
    return ""
