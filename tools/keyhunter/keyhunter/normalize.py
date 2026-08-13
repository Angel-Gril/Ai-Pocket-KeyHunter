from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from keyhunter.util import safe_filename, sha256_text, write_json


def _b64url_json(segment: str) -> dict[str, Any] | None:
    pad = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + pad)
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return None


def jwt_payload(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    return _b64url_json(parts[1])


def exp_to_iso(exp: float | None) -> str | None:
    if exp is None:
        return None
    try:
        return datetime.fromtimestamp(int(exp), tz=UTC).isoformat()
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def account_to_cpa(account: dict[str, Any], *, source_origin: str) -> dict[str, Any]:
    raw_creds = account.get("credentials")
    creds = raw_creds if isinstance(raw_creds, dict) else {}
    access = str(creds.get("access_token") or "")
    refresh = str(creds.get("refresh_token") or "")
    id_token = str(creds.get("id_token") or "")
    email = str(creds.get("email") or account.get("name") or account.get("email") or "")
    plan = str(creds.get("plan_type") or account.get("plan_type") or "")
    chatgpt_account_id = str(
        creds.get("chatgpt_account_id")
        or account.get("chatgpt_account_id")
        or account.get("account_id")
        or ""
    )

    payload = jwt_payload(access)
    if payload is None:
        payload = {}
    auth = payload.get("https://api.openai.com/auth")
    if isinstance(auth, dict):
        chatgpt_account_id = chatgpt_account_id or str(auth.get("chatgpt_account_id") or "")
        if not email and isinstance(payload.get("email"), str):
            email = payload["email"]

    exp = payload.get("exp")
    if account.get("expires_at") and not exp:
        exp = account.get("expires_at")
    expired = exp_to_iso(exp if isinstance(exp, (int, float)) else None)
    if not expired and isinstance(creds.get("expires_at"), str):
        expired = creds["expires_at"]

    return {
        "type": "codex",
        "email": email,
        "name": email or account.get("name") or "",
        "account_id": chatgpt_account_id,
        "chatgpt_account_id": chatgpt_account_id,
        "plan_type": plan,
        "chatgpt_plan_type": plan,
        "access_token": access,
        "refresh_token": refresh,
        "id_token": id_token,
        "expired": expired,
        "disabled": bool(account.get("disabled") or False),
        "source_origin": source_origin,
        "source_product": "sub2api",
    }


def finding_summary(cpa: dict[str, Any], artifact_rel: str) -> dict[str, Any]:
    access = cpa.get("access_token") or ""
    return {
        "product": cpa.get("source_product"),
        "origin": cpa.get("source_origin"),
        "email": cpa.get("email"),
        "plan_type": cpa.get("plan_type"),
        "has_refresh": bool(cpa.get("refresh_token")),
        "expired": cpa.get("expired"),
        "artifact": artifact_rel,
        "fingerprint": sha256_text(access) if access else None,
        "high_value": _high_value(cpa),
    }


def _high_value(cpa: dict[str, Any]) -> bool:
    plan = str(cpa.get("plan_type") or "").lower()
    if plan in {"pro", "team", "enterprise"}:
        return True
    if cpa.get("refresh_token"):
        return True
    expired = cpa.get("expired")
    if isinstance(expired, str) and expired:
        try:
            dt = datetime.fromisoformat(expired)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return (dt - datetime.now(tz=UTC)).total_seconds() > 7 * 86400
        except ValueError:
            return False
    return False


def normalize_export_file(raw_path: Path, out_dir: Path, origin_hint: str | None = None) -> dict[str, Any]:
    payload = json.loads(raw_path.read_text(encoding="utf-8"))
    origin = origin_hint or ""
    body = payload
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        body = payload["data"]
    accounts = body.get("accounts") if isinstance(body, dict) else None
    if not isinstance(accounts, list):
        # maybe newapi token list — skip CPA conversion
        return {
            "raw_path": str(raw_path),
            "ok": False,
            "reason": "no_accounts_array",
            "findings": [],
        }

    cpa_dir = out_dir / "cpa"
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for account in accounts:
        if not isinstance(account, dict):
            continue
        cpa = account_to_cpa(account, source_origin=origin)
        if not cpa.get("access_token") and not cpa.get("refresh_token"):
            continue
        fp = sha256_text(cpa.get("access_token") or cpa.get("refresh_token") or "")
        if fp in seen:
            continue
        seen.add(fp)
        name = safe_filename(str(cpa.get("email") or "account"))
        artifact_name = f"{name}-{fp[:12]}.json"
        rel = f"cpa/{artifact_name}"
        write_json(cpa_dir / artifact_name, cpa)
        findings.append(finding_summary(cpa, rel))

    index = {
        "raw_path": str(raw_path),
        "origin": origin,
        "ok": True,
        "count": len(findings),
        "high_value": sum(1 for f in findings if f.get("high_value")),
        "findings": findings,
    }
    write_json(out_dir / "index" / f"{safe_filename(raw_path.stem)}.json", index)
    return index


_SK_RE = re.compile(r"(?:sk-[A-Za-z0-9_\-]{16,}|sk-proj-[A-Za-z0-9_\-]{20,})")


def extract_api_keys(text: str) -> list[str]:
    return sorted(set(_SK_RE.findall(text)))


def normalize_newapi_exports(
    exports_dir: Path,
    out_dir: Path,
    product_id: str,
) -> dict[str, Any]:
    """Pull keys from NewAPI-family bundles while preserving product and origin."""
    out_dir.mkdir(parents=True, exist_ok=True)
    keys_dir = out_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = exports_dir / "raw"
    origin_by_path: dict[str, str] = {}
    index_path = exports_dir / "export_index.json"
    if index_path.is_file():
        index_payload = json.loads(index_path.read_text(encoding="utf-8"))
        if isinstance(index_payload, list):
            for item in index_payload:
                if isinstance(item, dict) and item.get("raw_path"):
                    path = Path(str(item["raw_path"]))
                    origin_by_path[str(path)] = str(item.get("origin") or "")
                    origin_by_path[str(path.resolve())] = str(item.get("origin") or "")

    all_keys: list[dict[str, Any]] = []
    seen: set[str] = set()
    files = sorted(raw_dir.glob("*.json")) if raw_dir.is_dir() else []
    for raw in files:
        text = raw.read_text(encoding="utf-8")
        origin = origin_by_path.get(str(raw), origin_by_path.get(str(raw.resolve()), ""))
        for key in extract_api_keys(text):
            fingerprint = sha256_text(key)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            item = {
                "apikey": key,
                "source_file": str(raw),
                "source_origin": origin,
                "fingerprint": fingerprint,
                "product": product_id,
            }
            all_keys.append(item)
            write_json(keys_dir / f"{fingerprint[:16]}.json", item)
    summary = {
        "product": product_id,
        "key_count": len(all_keys),
        "files": len(files),
        "keys": [
            {
                "fingerprint": item["fingerprint"],
                "prefix": item["apikey"][:8] + "...",
                "source_origin": item["source_origin"],
            }
            for item in all_keys
        ],
    }
    write_json(out_dir / "keys_summary.json", summary)
    return summary
