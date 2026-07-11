from __future__ import annotations

import time

import httpx
import pytest
import respx

from aipocket.clients.fofa import FofaClient

BASE = "https://fofoapi.test"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)


def _client(keys: list[str] | None = None, **kw) -> FofaClient:
    return FofaClient(keys=keys or ["k1"], base_url=BASE, min_interval=0, **kw)


def _ok_response(rows, size=100, page=1):
    return {
        "error": False,
        "consumed_fpoint": 0,
        "required_fpoints": 0,
        "size": size,
        "page": page,
        "results": rows,
    }


@respx.mock
def test_search_single_page():
    rows = [["https://a.com", "1.1.1.1", "443", "hdr", "ban", "P", "T"]]
    respx.get(f"{BASE}/api/v1/search/all").mock(
        return_value=httpx.Response(200, json=_ok_response(rows, size=1))
    )

    with _client() as c:
        results = c.search('body="test"', pages=1, size=100)

    assert len(results) == 1
    assert results[0]["host"] == "https://a.com"


@respx.mock
def test_search_stops_when_page_smaller_than_size():
    page1_rows = [[f"h{i}", f"1.1.1.{i}", "443", "", "", "", ""] for i in range(100)]
    small_rows = [["last", "2.2.2.2", "443", "", "", "", ""]]

    route = respx.get(f"{BASE}/api/v1/search/all")
    route.side_effect = [
        httpx.Response(200, json=_ok_response(page1_rows, size=100, page=1)),
        httpx.Response(200, json=_ok_response(small_rows, size=1, page=2)),
    ]

    with _client() as c:
        results = c.search('body="test"', pages=5, size=100)

    assert len(results) == 101
    assert results[-1]["host"] == "last"


@respx.mock
def test_search_stops_on_empty_results():
    respx.get(f"{BASE}/api/v1/search/all").mock(
        return_value=httpx.Response(200, json=_ok_response([]))
    )

    with _client() as c:
        results = c.search('body="test"', pages=5)

    assert results == []


@respx.mock
def test_search_rotates_keys_on_error():
    route = respx.get(f"{BASE}/api/v1/search/all")
    route.side_effect = [
        httpx.Response(500, text="server error"),
        httpx.Response(200, json=_ok_response([["h", "1.1.1.1", "443", "", "", "", ""]])),
    ]

    with _client(["bad", "good"]) as c:
        results = c.search('body="t"', pages=1)

    assert len(results) == 1


@respx.mock
def test_search_retries_429_then_succeeds():
    route = respx.get(f"{BASE}/api/v1/search/all")
    route.side_effect = [
        httpx.Response(429, text="too many"),
        httpx.Response(429, text="too many"),
        httpx.Response(200, json=_ok_response([["h", "1.1.1.1", "443", "", "", "", ""]])),
    ]

    with _client(["k1"]) as c:
        results = c.search('body="t"', pages=1)

    assert len(results) == 1


@respx.mock
def test_search_stops_on_quota_exhausted():
    respx.get(f"{BASE}/api/v1/search/all").mock(
        return_value=httpx.Response(200, json={"error": True, "errmsg": "已用完"})
    )

    with _client(["k1", "k2", "k3"]) as c:
        results = c.search('body="t"', pages=1)

    assert results == []
    assert len(c._dead) == 3


@respx.mock
def test_search_skips_dead_key_and_uses_live():
    route = respx.get(f"{BASE}/api/v1/search/all")
    route.side_effect = [
        httpx.Response(200, json={"error": True, "errmsg": "已用完"}),
        httpx.Response(200, json=_ok_response([["h", "1.1.1.1", "443", "", "", "", ""]])),
    ]

    with _client(["dead", "live"]) as c:
        results = c.search('body="t"', pages=1)

    assert len(results) == 1
    assert "dead" in c._dead
    assert "live" not in c._dead


@respx.mock
def test_search_handles_network_error_then_success():
    route = respx.get(f"{BASE}/api/v1/search/all")
    route.side_effect = [
        httpx.ConnectError("boom"),
        httpx.Response(200, json=_ok_response([["h", "1.1.1.1", "443", "", "", "", ""]])),
    ]

    with _client(["k1", "k2"]) as c:
        results = c.search('body="t"', pages=1)

    assert len(results) == 1


@respx.mock
def test_search_non_json_response():
    respx.get(f"{BASE}/api/v1/search/all").mock(
        return_value=httpx.Response(200, text="<html>not json</html>")
    )

    with _client(["k1", "k2"]) as c:
        results = c.search('body="t"', pages=1)

    assert results == []


@respx.mock
def test_search_key_not_found():
    respx.get(f"{BASE}/api/v1/search/all").mock(
        return_value=httpx.Response(200, text='{"errmsg": "key 不存在"}')
    )

    with _client(["k1", "k2"]) as c:
        results = c.search('body="t"', pages=1)

    assert results == []
    assert len(c._dead) == 2


@respx.mock
def test_search_error_true_without_results_is_not_success():
    respx.get(f"{BASE}/api/v1/search/all").mock(
        return_value=httpx.Response(
            200, json={"error": True, "errmsg": "[-4] 未知错误", "results": None}
        )
    )

    with _client(["k1", "k2"]) as c:
        results = c.search('body="t"', pages=1)

    assert results == []


@respx.mock
def test_info_reports_remain_api_query():
    respx.get(f"{BASE}/api/v1/info/my").mock(
        return_value=httpx.Response(
            200,
            json={
                "error": False,
                "email": "a@b.com",
                "remain_api_query": 100,
                "remain_api_data": 1000,
                "vip_level": 1,
            },
        )
    )
    with _client() as c:
        info = c.info()
    assert info["total_remain_api_query"] == 100
    assert info["keys"][0]["vip_level"] == 1


def test_no_keys_raises():
    with pytest.raises(RuntimeError):
        FofaClient(keys=[])


def test_context_manager():
    c = _client()
    with c as ctx:
        assert ctx is c
    assert c._client.is_closed
