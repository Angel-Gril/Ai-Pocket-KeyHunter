from __future__ import annotations

from aipocket.extractor import _infer_base_url as infer_url
from aipocket.extractor import _scan_blob, extract_credentials

OPENAI_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
ANTHROPIC_KEY = "sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901"


def test_extract_openai_key_from_header():
    hits = [{
        "host": "https://ai.example.com",
        "ip": "1.2.3.4",
        "port": "443",
        "header": f"Authorization: Bearer {OPENAI_KEY}\r\nServer: nginx",
        "banner": "",
        "title": "",
        "product": "LiteLLM",
        "cert": "",
    }]
    creds = extract_credentials(hits)
    assert len(creds) == 1
    assert creds[0].apikey == OPENAI_KEY
    assert creds[0].source == "openai"
    assert creds[0].source_type == "header"
    assert creds[0].host == "https://ai.example.com"


def test_extract_anthropic_key_from_banner():
    hits = [{
        "host": "https://claude-proxy.xyz",
        "ip": "2.2.2.2",
        "port": "8443",
        "header": "",
        "banner": f"x-api-key: {ANTHROPIC_KEY}",
        "title": "",
        "product": "",
        "cert": "",
    }]
    creds = extract_credentials(hits)
    found = [c for c in creds if c.apikey == ANTHROPIC_KEY]
    assert len(found) == 1
    assert found[0].source == "anthropic"


def test_extract_generic_apikey_pattern():
    text = 'api_key: "akabcdefghijklmnopqrstuvwxyz1234567890BB"'
    hits = [{
        "host": "https://x.com",
        "ip": "",
        "port": "",
        "header": text,
        "banner": "",
        "title": "",
        "product": "",
        "cert": "",
    }]
    creds = extract_credentials(hits)
    assert any(c.apikey == "akabcdefghijklmnopqrstuvwxyz1234567890BB" for c in creds)


def test_extract_apiurl_from_header():
    hits = [{
        "host": "https://gateway.example.com",
        "ip": "3.3.3.3",
        "port": "443",
        "header": f"X-OpenAI-Base: https://api.openai.com/v1\r\nAuth: Bearer {OPENAI_KEY}",
        "banner": "",
        "title": "",
        "product": "",
        "cert": "",
    }]
    creds = extract_credentials(hits)
    assert len(creds) >= 1
    assert any("openai.com" in c.apiurl for c in creds)


def test_extract_dedupes_same_key_same_url():
    hits = [
        {"host": "https://a.com", "ip": "1.1.1.1", "port": "443", "header": f"Bearer {OPENAI_KEY}", "banner": "", "title": "", "product": "", "cert": ""},
        {"host": "https://a.com", "ip": "1.1.1.1", "port": "443", "header": f"Bearer {OPENAI_KEY}", "banner": "", "title": "", "product": "", "cert": ""},
    ]
    creds = extract_credentials(hits)
    assert len(creds) == 1


def test_extract_different_hosts_keeps_both():
    hits = [
        {"host": "https://a.com", "ip": "1.1.1.1", "port": "443", "header": f"Bearer {OPENAI_KEY}", "banner": "", "title": "", "product": "", "cert": ""},
        {"host": "https://b.com", "ip": "2.2.2.2", "port": "443", "header": f"Bearer {OPENAI_KEY}", "banner": "", "title": "", "product": "", "cert": ""},
    ]
    creds = extract_credentials(hits)
    assert len(creds) == 2


def test_extract_no_credentials_empty_hits():
    assert extract_credentials([]) == []
    assert extract_credentials([{"host": "", "ip": "", "port": "", "header": "", "banner": "", "title": "", "product": "", "cert": ""}]) == []


def test_scan_blob_finds_url_in_link():
    hit = {"host": "https://api.test.com", "link": "https://api.test.com/v1", "header": "", "banner": "", "title": "", "cert": ""}
    result = _scan_blob(hit)
    assert "https://api.test.com/v1" in result["api_urls"]


def test_infer_base_url_prefers_v1_url():
    hit = {"host": "https://gw.com", "protocol": "https"}
    urls = {"https://gw.com", "https://gw.com/v1"}
    assert infer_url(hit, urls) == "https://gw.com/v1"


def test_infer_base_url_uses_fingerprint_suffix():
    hit = {"host": "gw.litellm.io", "protocol": "https", "title": "LiteLLM Proxy", "header": "", "banner": ""}
    assert infer_url(hit, set()) == "https://gw.litellm.io/v1"


def test_infer_base_url_fallback_to_host():
    hit = {"host": "plain.example.com", "protocol": "http", "title": "", "header": "", "banner": ""}
    assert infer_url(hit, set()) == "http://plain.example.com"


def test_infer_base_url_empty_host():
    assert infer_url({"host": "", "protocol": "https"}, set()) == ""


def test_google_key_pattern():
    google_key = "AIzaSyA" + "B" * 32
    hits = [{"host": "https://g.com", "ip": "", "port": "", "header": f"key: {google_key}", "banner": "", "title": "", "product": "", "cert": ""}]
    creds = extract_credentials(hits)
    assert any(c.apikey == google_key for c in creds)
