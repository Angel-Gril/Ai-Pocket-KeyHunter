"""Settings read/write + hot-reload + FOFA/Shodan connectivity checks.

Scope is intentionally limited to FOFA / Shodan config (keys, base URLs, page
counts, concurrency) per the spec — NOT AI model config, and NEVER the web
password/JWT secret.

Writes persist to ``.env`` (preserving unrelated lines) and hot-reload the
module-level ``settings`` singleton by attribute assignment. ``Settings`` is a
plain (non-frozen) pydantic model, so assignment takes effect immediately — the
CLI already relies on this (``settings.gpt_fast = True``). Key/base-url changes
are safe to hot-reload because the clients read ``settings`` fresh on each call.
"""

from __future__ import annotations

import logging
from pathlib import Path

from aipocket.core.config import settings
from .errors import ApiError
from .masking import mask_keys_csv
from .schemas import (
    FofaCheckResponse,
    SettingsUpdate,
    SettingsUpdateResponse,
    SettingsView,
    ShodanCheckResponse,
    ShodanKeyInfo,
)

log = logging.getLogger(__name__)

# .env key name (uppercase) → Settings attribute (lowercase). Only these are
# editable through the web API.
_FIELD_TO_ENV = {
    "fofa_keys": "FOFA_KEYS",
    "fofa_base_url": "FOFA_BASE_URL",
    "fofa_page_size": "FOFA_PAGE_SIZE",
    "fofa_max_pages": "FOFA_MAX_PAGES",
    "fofa_timeout": "FOFA_TIMEOUT",
    "shodan_keys": "SHODAN_KEYS",
    "shodan_base_url": "SHODAN_BASE_URL",
    "shodan_max_pages": "SHODAN_MAX_PAGES",
    "shodan_timeout": "SHODAN_TIMEOUT",
    "shodan_page_delay": "SHODAN_PAGE_DELAY",
    "validate_concurrency": "VALIDATE_CONCURRENCY",
    "prober_concurrency": "PROBER_CONCURRENCY",
}

_SENSITIVE = {"fofa_keys", "shodan_keys"}

# These take effect on the next call that reads settings — no restart needed.
# (All current editable fields are read fresh per request by the clients.)
_HOT_RELOADABLE = set(_FIELD_TO_ENV.keys())


def _env_path() -> Path:
    """Path to the .env the app was configured from (project root)."""
    # config.py loads env_file=".env" relative to CWD. Match that.
    return Path(".env")


def current_view() -> SettingsView:
    """Editable settings with sensitive keys masked."""
    return SettingsView(
        fofa_keys=mask_keys_csv(settings.fofa_keys),
        fofa_base_url=settings.fofa_base_url,
        fofa_page_size=settings.fofa_page_size,
        fofa_max_pages=settings.fofa_max_pages,
        fofa_timeout=settings.fofa_timeout,
        shodan_keys=mask_keys_csv(settings.shodan_keys),
        shodan_base_url=settings.shodan_base_url,
        shodan_max_pages=settings.shodan_max_pages,
        shodan_timeout=settings.shodan_timeout,
        shodan_page_delay=settings.shodan_page_delay,
        validate_concurrency=settings.validate_concurrency,
        prober_concurrency=settings.prober_concurrency,
    )


def _is_masked_passthrough(field: str, value: str) -> bool:
    """A masked key value round-tripped from GET means 'leave unchanged'."""
    return field in _SENSITIVE and "****" in value


def _write_env(updates: dict[str, str]) -> None:
    """Persist updates to .env, preserving unrelated lines and comments."""
    path = _env_path()
    lines: list[str] = []
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()

    remaining = dict(updates)  # env_name -> value
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            out.append(line)
            continue
        name = stripped.split("=", 1)[0].strip()
        if name in remaining:
            out.append(f"{name}={remaining.pop(name)}")
        else:
            out.append(line)

    # Append any keys that weren't already present.
    for name, value in remaining.items():
        out.append(f"{name}={value}")

    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def update_settings(body: SettingsUpdate) -> SettingsUpdateResponse:
    """Validate, persist to .env, and hot-reload the settings singleton."""
    provided = body.model_dump(exclude_none=True)
    updated: list[str] = []
    hot: list[str] = []
    restart: list[str] = []
    env_updates: dict[str, str] = {}

    for field, value in provided.items():
        if field not in _FIELD_TO_ENV:
            continue  # ignore unknown / non-editable fields defensively
        if isinstance(value, str) and _is_masked_passthrough(field, value):
            continue  # masked round-trip → don't clobber the real key
        # Apply to the live singleton (hot reload).
        setattr(settings, field, value)
        env_updates[_FIELD_TO_ENV[field]] = str(value)
        updated.append(field)
        (hot if field in _HOT_RELOADABLE else restart).append(field)

    if env_updates:
        _write_env(env_updates)

    return SettingsUpdateResponse(
        updated=updated,
        hot_reloaded=hot,
        restart_required=restart,
        settings=current_view(),
    )


# ----------------------------------------------------------------------------
# Connectivity checks
# ----------------------------------------------------------------------------
def check_fofa() -> FofaCheckResponse:
    """Tiny live FOFA probe → three-state verdict. Consumes minimal quota.

    fofoapi.com's /info endpoint returns fake demo data, so the only reliable
    liveness signal is a real (minimal) query. ``FofaClient._request_page``
    already classifies the Chinese error strings; we infer state from whether we
    got rows back vs. the key being marked dead.
    """
    from aipocket.clients.fofa import FofaClient

    if not settings.keys:
        return FofaCheckResponse(status="invalid", message="no FOFA keys configured")

    try:
        with FofaClient() as client:
            rows = client.search('title="123"', pages=1, size=1)
            # A key marked dead means quota-exhausted / invalid-account / not-found.
            # Distinguishing quota vs. hard-invalid isn't always possible here (the
            # client logs the specific reason). Report the softer "quota_exhausted"
            # only when ALL keys died; a surviving key means we're still reachable.
            if client._dead and len(client._dead) >= len(client.keys):
                return FofaCheckResponse(
                    status="quota_exhausted",
                    message="all keys exhausted or invalid (see server log)",
                )
    except RuntimeError as e:
        return FofaCheckResponse(status="invalid", message=str(e))
    except Exception as e:  # noqa: BLE001 — any network/parse failure = not reachable
        return FofaCheckResponse(status="invalid", message=f"probe failed: {e}")

    if rows:
        return FofaCheckResponse(status="ok", message=f"reachable ({len(rows)} result)")
    # No rows and no dead key: reachable but empty — treat as ok (query matched nothing).
    return FofaCheckResponse(status="ok", message="reachable (no results for probe query)")


def check_shodan() -> ShodanCheckResponse:
    """Shodan connectivity + real remaining credits via /api-info (no quota cost)."""
    from aipocket.clients.shodan import ShodanClient

    if not settings.shodan_key_list:
        raise ApiError("no Shodan keys configured", code="bad_request")

    try:
        with ShodanClient() as client:
            info = client.info()
    except RuntimeError as e:
        raise ApiError(str(e), code="bad_request") from e

    if not info:
        return ShodanCheckResponse(n_keys=len(settings.shodan_key_list), n_dead=len(settings.shodan_key_list))

    keys = [
        ShodanKeyInfo(
            key_masked=str(k.get("_key_masked", "")),
            plan=str(k.get("plan", "")),
            query_credits=int(k.get("query_credits", 0) or 0),
            alive=True,
        )
        for k in info.get("keys", [])
    ]
    return ShodanCheckResponse(
        keys=keys,
        total_query_credits=int(info.get("total_query_credits", 0)),
        n_keys=int(info.get("n_keys", len(keys))),
        n_dead=int(info.get("n_dead", 0)),
    )
