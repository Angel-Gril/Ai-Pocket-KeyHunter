"""Real-time persistence of high-value official API keys.

High-value keys (OpenAI sk-proj-*, Claude sk-ant-*) that respond with
200 (valid) or 429 (rate-limited = alive) are persisted IMMEDIATELY
during validation — not buffered until the scan completes.

Storage format: JSONL (one JSON object per line) for append-friendliness.
Location: results/high_value_keys/keys.jsonl
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aipocket.core.config import settings
from aipocket.core.models import ValidationResult

log = logging.getLogger(__name__)

# Prefixes that qualify as high-value candidates from key shape alone.
# Broad Anthropic ``sk-ant-`` is intentionally excluded — ordinary API keys
# require confirmed org/admin scope or verified high-value model access.
HIGH_VALUE_PREFIXES = (
    "sk-proj-",  # OpenAI project keys
    "sk-admin-",  # OpenAI admin keys
    "sk-svcacct-",  # OpenAI service account keys
    "sk-ant-admin",  # Anthropic Admin API keys (org scope)
)

# Models that elevate a validated Anthropic API key to high-value.
_ANTHROPIC_HIGH_VALUE_MODELS = frozenset(
    {
        "claude-sonnet-4-6",
        "claude-sonnet-5",
        "claude-opus-4-8",
        "claude-opus-4-7",
        "claude-opus-4-6",
        "claude-fable-5",
        "anthropic/claude-sonnet-4",
        "anthropic/claude-opus-4",
        "anthropic/claude-opus-4.1",
        "anthropic/claude-sonnet-4.5",
    }
)

ALIVE_STATUS_CODES = {200}

# Thread-safe lock for file appending (validate_all uses asyncio.gather
# which runs in one thread, but prober runs in a thread pool).
_write_lock = threading.Lock()

# Dedup set for current session — avoid writing the same key twice.
_seen_keys: set[str] = set()


def _output_dir() -> Path:
    """Return (and create) the high_value_keys directory under results/."""
    d = settings.results_path / "high_value_keys"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _output_path() -> Path:
    return _output_dir() / "keys.jsonl"


def is_high_value_key(apikey: str) -> bool:
    """Return True if the key matches a high-value official prefix.

    Ordinary Anthropic API keys (``sk-ant-api…``) are not high-value by prefix
    alone — use :func:`should_save` which also checks org scope / model evidence.
    """
    return any(apikey.startswith(prefix) for prefix in HIGH_VALUE_PREFIXES)


def is_alive_status(status_code: int | None) -> bool:
    """Return True if the status code indicates the key is alive."""
    return status_code in ALIVE_STATUS_CODES


def _has_anthropic_high_value_evidence(result: ValidationResult) -> bool:
    """Admin/org scope confirmation or verified high-value model access."""
    if result.tier == "org:admin":
        return True
    models = set(result.provider_info.models_verified)
    if result.model_available:
        models.add(result.model_available)
    return bool(models & _ANTHROPIC_HIGH_VALUE_MODELS)


def should_save(result: ValidationResult) -> bool:
    """Determine whether this validation result should be saved as high-value.

    Never persists rate-limited quarantine. Accepts authenticated provider
    states, or legacy valid=True rows that never advanced past discovered.
    """
    state = result.validation_state
    if state == "rate_limited_unconfirmed" or result.suspicious:
        return False
    authenticated = state in {
        "final_verified",
        "authentication_confirmed",
        "scope_confirmed",
        "inference_verified",
        "no_auth_disproved",
    }
    legacy_valid = result.valid and state in {"discovered", "structurally_valid"}
    if not authenticated and not legacy_valid:
        return False
    if not is_alive_status(result.status_code):
        return False
    key = result.credential.apikey
    if is_high_value_key(key):
        return True
    # Anthropic ordinary API / OAuth keys need scope or model evidence.
    return key.startswith("sk-ant-") and _has_anthropic_high_value_evidence(result)


def save_high_value_key(result: ValidationResult, run_id: str | None = None) -> bool:
    """Persist a high-value key. Returns True if written (False if already seen).

    Thread-safe; deduplicates within the current process session. Writes to
    PostgreSQL (UPSERT on apikey, last write wins) and/or the JSONL file per the
    ``settings.pg_enabled`` / ``settings.write_jsonl`` flags. ``run_id`` is the
    enclosing scan's id (from the current_run_id ContextVar) for attribution.
    """
    key = result.credential.apikey

    with _write_lock:
        if key in _seen_keys:
            return False
        _seen_keys.add(key)

        entry = _build_entry(result, run_id)

        if settings.pg_enabled:
            _upsert_pg(entry)

        if settings.write_jsonl:
            line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
            path = _output_path()
            with path.open("a", encoding="utf-8") as f:
                f.write(line)

    log.info("high_value_key saved: %s…  status=%s", key[:16], result.status_code)
    return True


def _upsert_pg(entry: dict[str, Any]) -> None:
    """UPSERT one high-value entry into the high_value_keys table (last write wins)."""
    from psycopg.types.json import Jsonb

    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        conn.execute(
            """
            INSERT INTO high_value_keys (apikey, run_id, saved_at, record)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (apikey) DO UPDATE
              SET run_id = EXCLUDED.run_id,
                  saved_at = EXCLUDED.saved_at,
                  record = EXCLUDED.record
            """,
            (entry["apikey"], entry.get("run_id"), entry.get("saved_at"), Jsonb(entry)),
        )
        conn.commit()


def try_save(result: ValidationResult) -> None:
    """Check and save if the result qualifies. Call after each validation."""
    if should_save(result):
        from aipocket.core.db import current_run_id

        save_high_value_key(result, current_run_id.get())


def _build_entry(result: ValidationResult, run_id: str | None = None) -> dict[str, Any]:
    """Build the entry dict (JSONL line == PG record JSONB) from a ValidationResult."""
    return {
        "apikey": result.credential.apikey,
        "apiurl": result.credential.apiurl,
        "source": result.credential.source,
        "provider": result.provider_info.provider if result.provider_info else "",
        "status_code": result.status_code,
        "valid": result.valid,
        "tier": result.tier,
        "balance": result.balance,
        "gateway": result.gateway,
        "model_available": result.model_available,
        "error": result.error,
        "saved_at": datetime.now(UTC).isoformat(),
        "host": result.credential.host,
        "run_id": run_id,
    }


def load_all() -> list[dict[str, Any]]:
    """Load all high-value entries. Reads PG when enabled, else the JSONL file.

    The Web endpoint dedups by apikey (last write wins); PG already stores one
    row per apikey, and the JSONL reader returns every appended line (dedup
    happens downstream), so both back-ends preserve the existing contract.
    """
    if settings.pg_enabled:
        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn:
            rows = conn.execute(
                "SELECT record FROM high_value_keys ORDER BY saved_at DESC NULLS LAST"
            ).fetchall()
        return [r["record"] for r in rows]

    path = _output_path()
    if not path.exists():
        return []

    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            log.warning("Skipping malformed JSONL line: %s", line[:80])
    return entries


def reset_session() -> None:
    """Reset the session dedup set (for testing or new scan runs)."""
    _seen_keys.clear()


def reveal_apikey(masked: str, apiurl: str | None = None) -> dict[str, str]:
    """Recover ONE plaintext high-value apikey by matching the masked value.

    High-value keys are stored (PG or JSONL) with the plaintext apikey; the
    ``/high-value`` list endpoint masks them via :func:`mask_apikey`. This
    re-reads the store and matches each stored key's re-masking against
    ``masked`` (optionally disambiguated by ``apiurl``), returning the plaintext.

    Returns ``{"apikey": <plaintext>, "apiurl": ...}``. Raises if not found.
    """
    from aipocket.api.masking import mask_apikey

    for entry in load_all():
        apikey = str(entry.get("apikey", ""))
        if not apikey:
            continue
        if mask_apikey(apikey) != masked:
            continue
        entry_url = str(entry.get("apiurl", ""))
        if apiurl is not None and apiurl != "" and entry_url != apiurl:
            continue
        return {"apikey": apikey, "apiurl": entry_url}

    raise KeyError("high-value key not found")
