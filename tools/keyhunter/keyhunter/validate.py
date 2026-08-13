from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from keyhunter.normalize import jwt_payload
from keyhunter.util import write_json


def validate_cpa(obj: dict[str, Any]) -> dict[str, Any]:
    access = str(obj.get("access_token") or "")
    refresh = str(obj.get("refresh_token") or "")
    payload = jwt_payload(access) if access else None
    raw_exp = payload.get("exp") if payload else None
    exp: int | None = None
    invalid_exp = False
    if raw_exp is not None:
        try:
            exp = int(raw_exp)
        except (TypeError, ValueError):
            invalid_exp = True
    now = int(datetime.now(tz=UTC).timestamp())
    token_parseable = payload is not None
    expiry_known = exp is not None
    access_alive = bool(access) and token_parseable and expiry_known and exp > now
    result = {
        "email": obj.get("email"),
        "plan_type": obj.get("plan_type"),
        "has_access": bool(access),
        "has_refresh": bool(refresh),
        "token_parseable": token_parseable,
        "expiry_known": expiry_known,
        "access_alive": access_alive,
        "exp": raw_exp,
        "usable": access_alive or bool(refresh),
        "source_origin": obj.get("source_origin"),
    }
    if invalid_exp:
        result["reason"] = "invalid_exp"
    elif access and not token_parseable:
        result["reason"] = "unparseable_access_token"
    elif access and not expiry_known:
        result["reason"] = "unknown_expiry"
    return result


def validate_dir(artifacts_dir: Path, out_path: Path) -> dict[str, Any]:
    cpa_dir = artifacts_dir / "cpa"
    rows: list[dict[str, Any]] = []
    if cpa_dir.is_dir():
        for path in sorted(cpa_dir.glob("*.json")):
            try:
                obj = json.loads(path.read_text(encoding="utf-8"))
                row = validate_cpa(obj) if isinstance(obj, dict) else {"reason": "invalid_shape"}
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                row = {"usable": False, "access_alive": False, "reason": type(exc).__name__}
            row["file"] = str(path)
            rows.append(row)
    summary = {
        "total": len(rows),
        "usable": sum(1 for r in rows if r.get("usable")),
        "access_alive": sum(1 for r in rows if r.get("access_alive")),
        "with_refresh": sum(1 for r in rows if r.get("has_refresh")),
        "items": rows,
    }
    write_json(out_path, summary)
    return summary
