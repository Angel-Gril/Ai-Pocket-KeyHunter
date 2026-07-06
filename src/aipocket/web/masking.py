"""API-key masking helpers.

List/detail endpoints return masked keys; plaintext is only ever exposed via the
dedicated reveal/export endpoints. Masking keeps a short recognizable prefix +
suffix so the UI can still tell keys apart, e.g. ``sk-proj-****mnop``.
"""

from __future__ import annotations


def mask_apikey(key: str | None) -> str:
    """Mask an API key, preserving a leading marker and the last 4 chars.

    Rules:
    * empty / very short (<= 8) → fully masked with ``****`` (never leak short keys)
    * keys with a ``sk-...-`` style prefix keep that prefix + ``****`` + last 4
    * otherwise keep first 4 + ``****`` + last 4
    """
    if not key:
        return ""
    k = key.strip()
    if len(k) <= 8:
        return "****"

    last4 = k[-4:]

    # Preserve a meaningful provider prefix like "sk-proj-", "sk-ant-", "AIza".
    prefix = ""
    if k.startswith("sk-"):
        # sk-proj-, sk-ant-api03-, sk-svcacct-, sk-  → keep up through 2nd dash
        parts = k.split("-")
        prefix = "-".join(parts[:2]) + "-" if len(parts) >= 3 else "sk-"
    elif k.startswith("AIza"):
        prefix = "AIza"
    else:
        prefix = k[:4]

    return f"{prefix}****{last4}"


def mask_keys_csv(csv: str | None) -> str:
    """Mask a comma-separated list of keys, masking each element."""
    if not csv:
        return ""
    return ", ".join(mask_apikey(k.strip()) for k in csv.split(",") if k.strip())
