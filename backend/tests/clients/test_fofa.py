from __future__ import annotations

import httpx
import pytest
import respx

from aipocket.clients.fofa import FofaClient

BASE = "https://fofoapi.test"


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
    respx.get(f"{BASE}/api/v1/search/all").mock(return_value=httpx.Response(200, json=_ok_response(rows, size=1)))

    with FofaClient(keys=["k1"], base_url=BASE) as c:
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

    with FofaClient(keys=["k1"], base_url=BASE) as c:
        results = c.search('body="test"', pages=5, size=100)

    assert len(results) == 101
    assert results[-1]["host"] == "last"


@respx.mock
def test_search_stops_on_empty_results():
    respx.get(f"{BASE}/api/v1/search/all").mock(return_value=httpx.Response(200, json=_ok_response([])))

    with FofaClient(keys=["k1"], base_url=BASE) as c:
        results = c.search('body="test"', pages=5)

    assert results == []


@respx.mock
def test_search_rotates_keys_on_error():
    route = respx.get(f"{BASE}/api/v1/search/all")
    route.side_effect = [
        httpx.Response(500, text="server error"),
        httpx.Response(200, json=_ok_response([["h", "1.1.1.1", "443", "", "", "", ""]])),
    ]

    with FofaClient(keys=["bad", "good"], base_url=BASE) as c:
        results = c.search('body="t"', pages=1)

    assert len(results) == 1


@respx.mock
def test_search_stops_on_quota_exhausted():
    respx.get(f"{BASE}/api/v1/search/all").mock(
        return_value=httpx.Response(200, json={"error": True, "errmsg": "已用完"})
    )

    with FofaClient(keys=["k1", "k2", "k3"], base_url=BASE) as c:
        results = c.search('body="t"', pages=1)

    assert results == []


@respx.mock
def test_search_handles_network_error_then_success():
    route = respx.get(f"{BASE}/api/v1/search/all")
    route.side_effect = [
        httpx.ConnectError("boom"),
        httpx.Response(200, json=_ok_response([["h", "1.1.1.1", "443", "", "", "", ""]])),
    ]

    with FofaClient(keys=["k1", "k2"], base_url=BASE) as c:
        results = c.search('body="t"', pages=1)

    assert len(results) == 1


@respx.mock
def test_search_non_json_response():
    respx.get(f"{BASE}/api/v1/search/all").mock(return_value=httpx.Response(200, text="<html>not json</html>"))

    with FofaClient(keys=["k1", "k2"], base_url=BASE) as c:
        results = c.search('body="t"', pages=1)

    assert results == []


@respx.mock
def test_search_key_not_found():
    respx.get(f"{BASE}/api/v1/search/all").mock(
        return_value=httpx.Response(200, text='{"errmsg": "key 不存在"}')
    )

    with FofaClient(keys=["k1", "k2"], base_url=BASE) as c:
        results = c.search('body="t"', pages=1)

    assert results == []


def test_no_keys_raises():
    with pytest.raises(RuntimeError):
        FofaClient(keys=[])


def test_context_manager():
    c = FofaClient(keys=["k1"], base_url=BASE)
    with c as ctx:
        assert ctx is c
    assert c._client.is_closed
