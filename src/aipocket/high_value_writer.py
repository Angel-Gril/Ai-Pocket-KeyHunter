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

from .config import settings
from .models import ValidationResult

log = logging.getLogger(__name__)

# Key prefixes that qualify as "high-value official" keys.
HIGH_VALUE_PREFIXES = (
    "sk-proj-",    # OpenAI project keys
    "sk-admin-",   # OpenAI admin keys
    "sk-svcacct-", # OpenAI service account keys
    "sk-ant-",     # Anthropic (Claude) keys
)

# Status codes that indicate the key is alive (worth saving).
ALIVE_STATUS_CODES = {200, 429}

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
    """Return True if the key matches a high-value official prefix."""
    return any(apikey.startswith(prefix) for prefix in HIGH_VALUE_PREFIXES)


def is_alive_status(status_code: int | None) -> bool:
    """Return True if the status code indicates the key is alive."""
    return status_code in ALIVE_STATUS_CODES


def should_save(result: ValidationResult) -> bool:
    """Determine whether this validation result should be saved as high-value."""
    key = result.credential.apikey
    status = result.status_code
    return is_high_value_key(key) and is_alive_status(status)


def save_high_value_key(result: ValidationResult) -> bool:
    """Append a high-value key to the JSONL file. Returns True if written.

    Thread-safe; deduplicates within the current process session.
    """
    key = result.credential.apikey

    with _write_lock:
        if key in _seen_keys:
            return False
        _seen_keys.add(key)

    entry = _build_entry(result)
    line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"

    path = _output_path()
    with _write_lock, path.open("a", encoding="utf-8") as f:
        f.write(line)

    log.info("high_value_key saved: %s…  status=%s", key[:16], result.status_code)
    return True


def try_save(result: ValidationResult) -> None:
    """Check and save if the result qualifies. Call after each validation."""
    if should_save(result):
        save_high_value_key(result)


def _build_entry(result: ValidationResult) -> dict[str, Any]:
    """Build the JSONL entry from a ValidationResult."""
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
    }


def load_all() -> list[dict[str, Any]]:
    """Load all entries from the high-value keys file."""
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
