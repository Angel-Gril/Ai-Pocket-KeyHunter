from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_origin(host: str, ip: str, port: str | int | None, protocol: str | None = None) -> str | None:
    host = (host or "").strip()
    ip = (ip or "").strip()
    protocol = (protocol or "").strip().lower() or None
    port_s = str(port).strip() if port not in (None, "") else ""

    candidate = host or ip
    if not candidate:
        return None

    if candidate.startswith(("http://", "https://")):
        parsed = urlparse(candidate)
        scheme = parsed.scheme
        netloc = parsed.netloc or parsed.path
        if not netloc:
            return None
        if ":" not in netloc and port_s and port_s not in ("80", "443"):
            netloc = f"{netloc}:{port_s}"
        return f"{scheme}://{netloc}".rstrip("/")

    scheme = protocol if protocol in {"http", "https"} else ("https" if port_s == "443" else "http")
    if ":" in candidate:
        return f"{scheme}://{candidate}".rstrip("/")
    if port_s and not ((scheme == "http" and port_s == "80") or (scheme == "https" and port_s == "443")):
        return f"{scheme}://{candidate}:{port_s}"
    return f"{scheme}://{candidate}"


_EMAIL_SAFE = re.compile(r"[^a-zA-Z0-9._-]+")


def safe_filename(email: str) -> str:
    base = _EMAIL_SAFE.sub("_", email.strip()) or "unknown"
    return base[:120]
