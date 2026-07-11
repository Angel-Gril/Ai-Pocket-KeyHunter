#!/usr/bin/env python3
"""Verify GPT-5.5 keys with actual chat/completions calls.

Tests each key against:
1. Its original apiurl (proxy) with model=gpt-5.5
2. For sk-proj- keys: also against api.openai.com directly

Outputs JSON with verification results.
"""

import asyncio
import json
import time
from pathlib import Path

import httpx

TARGETS_PATH = Path(__file__).parent / "verify_gpt55_targets.json"
OUTPUT_PATH = Path(__file__).parent.parent / "results" / "gpt55_verification.json"

# Models to test in priority order
GPT55_MODELS = ["gpt-5.5", "gpt-5.5-pro", "gpt-5.5-2026-04-23"]

TIMEOUT = 20  # seconds per request


async def test_chat(
    client: httpx.AsyncClient,
    key: str,
    base_url: str,
    model: str,
) -> dict:
    """Try a single chat/completions call. Return result dict."""
    url = base_url.rstrip("/")
    if not url.endswith("/v1/chat/completions"):
        if url.endswith("/v1"):
            url += "/chat/completions"
        else:
            url += "/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Say exactly: hello world"}],
        "max_tokens": 10,
        "stream": False,
    }

    try:
        r = await client.post(url, headers=headers, json=payload, timeout=TIMEOUT)
    except httpx.ConnectError as e:
        return {"status": "connect_error", "error": str(e), "url": url, "model": model}
    except httpx.TimeoutException:
        return {"status": "timeout", "url": url, "model": model}
    except httpx.HTTPError as e:
        return {"status": "http_error", "error": str(e), "url": url, "model": model}

    result = {
        "url": url,
        "model": model,
        "status_code": r.status_code,
    }

    try:
        body = r.json()
    except Exception:
        result["status"] = "non_json"
        result["body_preview"] = r.text[:200]
        return result

    if r.status_code == 200:
        # Check if it's a real chat completion
        if "choices" in body and isinstance(body.get("choices"), list):
            try:
                content = body["choices"][0]["message"]["content"]
                result["status"] = "SUCCESS"
                result["response"] = content[:200]
                result["model_used"] = body.get("model", "")
                # Check for zero-width steganography
                zwc_count = sum(
                    1 for c in content if c in "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff"
                )
                if zwc_count > 5:
                    result["warning"] = f"STEGANOGRAPHY_DETECTED: {zwc_count} zero-width chars"
                return result
            except (KeyError, IndexError):
                pass
        result["status"] = "200_but_not_chat"
        result["body_preview"] = json.dumps(body)[:200]

    elif r.status_code == 429:
        err_msg = ""
        if isinstance(body.get("error"), dict):
            err_msg = body["error"].get("message", "")
        elif isinstance(body.get("error"), str):
            err_msg = body["error"]
        result["status"] = "rate_limited"
        result["error_message"] = err_msg

    elif r.status_code in (401, 403):
        result["status"] = "unauthorized"
        err_msg = ""
        if isinstance(body.get("error"), dict):
            err_msg = body["error"].get("message", "")
        result["error_message"] = err_msg

    elif r.status_code == 404:
        result["status"] = "model_not_found"
        result["body_preview"] = json.dumps(body)[:200]

    else:
        result["status"] = f"http_{r.status_code}"
        result["body_preview"] = json.dumps(body)[:200]

    return result


async def verify_one(client: httpx.AsyncClient, target: dict) -> dict:
    """Verify one key across all its test URLs and models."""
    key = target["key"]
    test_urls = target["test_urls"]
    results = {
        "key": key[:30] + "...",
        "host": target["host"],
        "is_sk_proj": target["is_sk_proj"],
        "tests": [],
    }

    for url in test_urls:
        for model in GPT55_MODELS:
            r = await test_chat(client, key, url, model)
            results["tests"].append(r)
            # If we got a success, skip remaining models for this URL
            if r.get("status") == "SUCCESS":
                break
            # If unauthorized, skip remaining models for this URL
            if r.get("status") == "unauthorized":
                break
            # Small delay between requests
            await asyncio.sleep(0.5)

    # Determine overall verdict
    successes = [t for t in results["tests"] if t.get("status") == "SUCCESS"]
    if successes:
        results["verdict"] = "LIVE_GPT55"
        results["working_url"] = successes[0]["url"]
        results["working_model"] = successes[0]["model"]
    elif any(t.get("status") == "rate_limited" for t in results["tests"]):
        results["verdict"] = "RATE_LIMITED"
    elif any(t.get("status") == "unauthorized" for t in results["tests"]):
        results["verdict"] = "DEAD"
    elif any(t.get("status") == "model_not_found" for t in results["tests"]):
        results["verdict"] = "NO_GPT55_ACCESS"
    else:
        results["verdict"] = "UNKNOWN"

    return results


async def main():
    targets = json.loads(TARGETS_PATH.read_text())
    print(f"Testing {len(targets)} keys for GPT-5.5 access...")

    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Run with limited concurrency to avoid overwhelming
        sem = asyncio.Semaphore(3)

        async def limited(t):
            async with sem:
                return await verify_one(client, t)

        results = await asyncio.gather(*[limited(t) for t in targets])

    # Summary
    verdicts = {}
    for r in results:
        v = r["verdict"]
        verdicts[v] = verdicts.get(v, 0) + 1

    output = {
        "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": verdicts,
        "total_keys": len(targets),
        "results": results,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    print(f"\nResults written to {OUTPUT_PATH}")

    print(f"\n{'=' * 50}")
    print("SUMMARY:")
    print(f"{'=' * 50}")
    for v, count in sorted(verdicts.items()):
        print(f"  {v}: {count}")

    print("\nDetails:")
    for r in results:
        icon = "✅" if r["verdict"] == "LIVE_GPT55" else "❌" if r["verdict"] == "DEAD" else "⚠️"
        print(f"  {icon} {r['key']} → {r['verdict']}")
        if r["verdict"] == "LIVE_GPT55":
            print(f"     URL: {r['working_url']}")
            print(f"     Model: {r['working_model']}")
            s = [t for t in r["tests"] if t.get("status") == "SUCCESS"][0]
            print(f"     Response: {s.get('response', '')[:80]}")
            if s.get("warning"):
                print(f"     ⚠️ {s['warning']}")


if __name__ == "__main__":
    asyncio.run(main())
