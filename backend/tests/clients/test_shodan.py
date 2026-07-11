from __future__ import annotations

import time

import httpx
import pytest
import respx

from aipocket.clients.shodan import ShodanClient, map_match

BASE = "https://api.shodan.test"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Backoff/throttle sleeps must not slow the unit suite."""
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)


def _client(keys: list[str] | None = None, **kw) -> ShodanClient:
    # min_interval=0 keeps unit tests fast (production default enforces ≥1s).
    return ShodanClient(keys=keys or ["k1"], base_url=BASE, min_interval=0, **kw)


def _match(ip: str, port: int, **kw):
    m = {
        "ip_str": ip,
        "port": port,
        "product": "LiteLLM",
        "hostnames": ["ai.example.com"],
        "http": {
            "title": "LiteLLM API",
            "server": "uvicorn",
            "host": ip,
            "html": "<html>OPENAI_API_KEY=sk-proj-XXX</html>",
        },
        "data": "HTTP/1.1 200 OK\r\nServer: uvicorn\r\nauthorization: Bearer sk-proj-AAA\r\n",
        "ssl": {"cert": {"subject": [{"commonName": "ai.example.com"}]}},
    }
    m.update(kw)
    return m


@respx.mock
def test_search_single_page():
    respx.get(f"{BASE}/shodan/host/search").mock(
        return_value=httpx.Response(
            200, json={"total": 2, "matches": [_match("1.1.1.1", 4000), _match("2.2.2.2", 4000)]}
        )
    )
    with _client() as c:
        results = c.search("http.title:LiteLLM", pages=1)
    assert len(results) == 2
    # normalized into FOFA-shape fields the extractor consumes
    r = results[0]
    assert r["ip"] == "1.1.1.1"
    assert r["port"] == "4000"
    assert r["title"] == "LiteLLM API"
    assert "authorization: Bearer sk-proj-AAA" in r["header"]
    assert "OPENAI_API_KEY=sk-proj-XXX" in r["banner"]


@respx.mock
def test_search_paginates_and_stops_on_short_page():
    route = respx.get(f"{BASE}/shodan/host/search")
    full = [_match(f"1.1.1.{i}", 4000) for i in range(100)]
    route.side_effect = [
        httpx.Response(200, json={"total": 101, "matches": full}),
        httpx.Response(200, json={"total": 101, "matches": [_match("9.9.9.9", 4000)]}),
    ]
    with _client() as c:
        results = c.search("http.title:LiteLLM", pages=5)
    assert len(results) == 101


@respx.mock
def test_search_stops_on_empty_matches():
    respx.get(f"{BASE}/shodan/host/search").mock(
        return_value=httpx.Response(200, json={"total": 0, "matches": []})
    )
    with _client() as c:
        assert c.search("nothing", pages=3) == []


@respx.mock
def test_search_rotates_keys_on_401():
    route = respx.get(f"{BASE}/shodan/host/search")
    route.side_effect = [
        httpx.Response(401, text="invalid key"),
        httpx.Response(200, json={"total": 1, "matches": [_match("1.1.1.1", 4000)]}),
    ]
    with _client(["bad", "good"]) as c:
        results = c.search("http.title:LiteLLM", pages=1)
    assert len(results) == 1
    assert "bad" in c._dead


@respx.mock
def test_search_retries_429_on_same_live_key_after_dead_key():
    """Dead key must not consume the only retry slot for the live key."""
    route = respx.get(f"{BASE}/shodan/host/search")
    route.side_effect = [
        httpx.Response(401, text="invalid key"),
        httpx.Response(429, json={"error": "Rate limit reached"}),
        httpx.Response(429, json={"error": "Rate limit reached"}),
        httpx.Response(200, json={"total": 1, "matches": [_match("1.1.1.1", 4000)]}),
    ]
    with _client(["bad", "good"]) as c:
        results = c.search("http.title:LiteLLM", pages=1)
    assert len(results) == 1
    assert "bad" in c._dead
    assert "good" not in c._dead


@respx.mock
def test_search_marks_credits_exhausted_separately_from_invalid():
    route = respx.get(f"{BASE}/shodan/host/search")
    route.side_effect = [
        httpx.Response(
            401,
            text='{"error": "Insufficient query credits, please upgrade your API plan"}',
        ),
        httpx.Response(200, json={"total": 1, "matches": [_match("1.1.1.1", 4000)]}),
    ]
    with _client(["broke", "rich"]) as c:
        results = c.search("http.title:LiteLLM", pages=1)
    assert len(results) == 1
    assert "broke" in c._dead


@respx.mock
def test_search_handles_network_error_then_success():
    route = respx.get(f"{BASE}/shodan/host/search")
    route.side_effect = [
        httpx.ConnectError("boom"),
        httpx.Response(200, json={"total": 1, "matches": [_match("1.1.1.1", 4000)]}),
    ]
    with _client(["k1", "k2"]) as c:
        results = c.search("http.title:LiteLLM", pages=1)
    assert len(results) == 1


@respx.mock
def test_search_non_json_returns_empty():
    respx.get(f"{BASE}/shodan/host/search").mock(
        return_value=httpx.Response(200, text="<html>nope")
    )
    with _client(["k1", "k2"]) as c:
        assert c.search("http.title:LiteLLM", pages=1) == []


@respx.mock
def test_count_returns_total_without_consuming_credits():
    respx.get(f"{BASE}/shodan/host/count").mock(
        return_value=httpx.Response(200, json={"total": 4242, "matches": []})
    )
    with _client() as c:
        assert c.count("http.title:LiteLLM") == 4242


@respx.mock
def test_info_returns_plan_and_credits():
    respx.get(f"{BASE}/api-info").mock(
        return_value=httpx.Response(200, json={"plan": "edu", "query_credits": 192907})
    )
    with _client() as c:
        info = c.info()
    # info() now aggregates across all keys (each key's quota reported separately)
    assert info["total_query_credits"] == 192907
    assert info["n_keys"] == 1
    assert info["keys"][0]["plan"] == "edu"
    assert info["keys"][0]["query_credits"] == 192907


@respx.mock
def test_info_aggregates_across_multiple_keys():
    # Two keys with very different quotas — both must be reported, summed.
    route = respx.get(f"{BASE}/api-info")
    route.side_effect = [
        httpx.Response(200, json={"plan": "dev", "query_credits": 62}),
        httpx.Response(200, json={"plan": "edu", "query_credits": 192907}),
    ]
    with _client(["k1", "k2"]) as c:
        info = c.info()
    assert info["n_keys"] == 2
    assert info["total_query_credits"] == 62 + 192907
    assert len(info["keys"]) == 2
    plans = sorted(k["plan"] for k in info["keys"])
    assert plans == ["dev", "edu"]


@respx.mock
def test_info_marks_zero_credit_keys_dead():
    route = respx.get(f"{BASE}/api-info")
    route.side_effect = [
        httpx.Response(200, json={"plan": "dev", "query_credits": 0}),
        httpx.Response(200, json={"plan": "edu", "query_credits": 100}),
    ]
    with _client(["empty", "ok"]) as c:
        info = c.info()
        assert info["total_query_credits"] == 100
        assert "empty" in c._dead
        assert "ok" not in c._dead


@respx.mock
def test_count_returns_none_when_endpoint_fails():
    # count() returns None (not 0) on API failure so callers don't skip live queries.
    respx.get(f"{BASE}/shodan/host/count").mock(return_value=httpx.Response(500, text="boom"))
    with _client() as c:
        assert c.count("http.title:LiteLLM") is None


@respx.mock
def test_count_returns_zero_when_truly_empty():
    # count() returns 0 only when Shodan explicitly reports zero — safe to skip.
    respx.get(f"{BASE}/shodan/host/count").mock(return_value=httpx.Response(200, json={"total": 0}))
    with _client() as c:
        assert c.count("nothing") == 0


def test_no_keys_raises():
    with pytest.raises(RuntimeError):
        ShodanClient(keys=[])


def test_context_manager():
    c = _client()
    with c as ctx:
        assert ctx is c
    assert c._client.is_closed


def test_map_match_includes_nonstandard_port_in_host():
    mapped = map_match(_match("5.6.7.8", 9000))
    assert ":9000" in mapped["host"]


def test_map_match_standard_port_omits_port():
    mapped = map_match(_match("5.6.7.8", 443))
    assert mapped["protocol"] == "https"
    assert ":443" not in mapped["host"]


def test_map_match_falls_back_to_hostname_then_ip():
    # no http.host, no hostnames -> use ip
    m = _match("5.6.7.8", 443)
    m["http"] = {"title": "", "server": "", "host": "", "html": ""}
    m["hostnames"] = []
    mapped = map_match(m)
    assert mapped["host"] == "5.6.7.8"
