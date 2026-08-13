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


def fingerprint_one(
    origin: str,
    product: ProductProfile,
    settings: Settings,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    owns = http is None
    client = http or _client(settings)
    result: dict[str, Any] = {
        "origin": origin.rstrip("/"),
        "product": product.id,
        "alive": False,
        "matched": False,
        "evidence": [],
        "status": {},
    }
    try:
        markers = tuple(m.lower() for m in product.title_markers)
        product_evidence = False
        surface_evidence = False
        for path in product.fingerprint_paths:
            url = f"{result['origin']}{path}"
            try:
                resp = client.get(url)
            except httpx.HTTPError as exc:
                result["status"][path] = f"error:{type(exc).__name__}"
                continue
            result["status"][path] = resp.status_code
            result["alive"] = True
            text = (resp.text or "")[:12000]
            lowered = text.lower()
            if any(marker in lowered for marker in markers):
                product_evidence = True
                result["evidence"].append(f"marker@{path}")
            if product.required_json_markers and any(
                marker in text for marker in product.required_json_markers
            ):
                product_evidence = True
                result["evidence"].append(f"json_marker@{path}")
            if (
                path == product.login_path
                and resp.status_code < 500
                and resp.status_code != 404
            ):
                surface_evidence = True
                result["evidence"].append(f"login_route@{path}:{resp.status_code}")
            if path in {"/api/status", "/v1/models"} and resp.status_code == 200:
                surface_evidence = True
                result["evidence"].append(f"surface@{path}")
        if product.id == "sub2api":
            result["matched"] = product_evidence
        elif product.id in {"newapi", "oneapi"}:
            result["matched"] = product_evidence or surface_evidence
    finally:
        if owns:
            client.close()
    return result


def fingerprint_many(
    origins: list[str],
    product: ProductProfile,
    settings: Settings,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=settings.concurrency) as pool:
        futs = [
            pool.submit(fingerprint_one, origin, product, settings, None)
            for origin in origins
        ]
        for fut in as_completed(futs):
            out.append(fut.result())
    out.sort(key=lambda x: x["origin"])
    return out
