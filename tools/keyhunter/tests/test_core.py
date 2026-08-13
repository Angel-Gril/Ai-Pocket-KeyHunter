from __future__ import annotations

import json
from pathlib import Path
from typing import Self

import httpx

from keyhunter.config import BROWSER_USER_AGENT, Settings
from keyhunter.export import _client as export_http_client
from keyhunter.export import export_sub2api_accounts
from keyhunter.fingerprint import _client as fingerprint_http_client
from keyhunter.fingerprint import fingerprint_one
from keyhunter.fofa import FofaClient
from keyhunter.normalize import (
    account_to_cpa,
    extract_api_keys,
    finding_summary,
    jwt_payload,
    normalize_export_file,
    normalize_newapi_exports,
)
from keyhunter.products import ProductProfile, get_product
from keyhunter.spray import _client as spray_http_client
from keyhunter.spray import spray_target
from keyhunter.util import normalize_origin, sha256_text, write_json
from keyhunter.validate import validate_cpa, validate_dir


def test_normalize_origin_basic() -> None:
    assert (
        normalize_origin("example.com", "1.2.3.4", "8080", "http")
        == "http://example.com:8080"
    )
    assert normalize_origin("https://a.b/c", "", None, None) == "https://a.b"
    assert normalize_origin("", "9.9.9.9", "443", None) == "https://9.9.9.9"


def test_account_to_cpa() -> None:
    import base64
    import json

    payload = {
        "exp": 2000000000,
        "https://api.openai.com/auth": {"chatgpt_account_id": "acc-1"},
        "email": "x@example.com",
    }
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    token = f"hdr.{seg}.sig"
    account = {
        "name": "x@example.com",
        "credentials": {
            "access_token": token,
            "refresh_token": "rt.demo",
            "plan_type": "pro",
        },
    }
    cpa = account_to_cpa(account, source_origin="http://h:8080")
    assert cpa["email"] == "x@example.com"
    assert cpa["chatgpt_account_id"] == "acc-1"
    assert cpa["plan_type"] == "pro"
    assert cpa["type"] == "codex"
    decoded = jwt_payload(token)
    assert decoded is not None
    assert decoded["exp"] == 2000000000
    assert sha256_text(token)


def test_products_loaded() -> None:
    sub = get_product("sub2api")
    assert sub.login_path.endswith("/login")
    assert sub.login_user_field == "email"
    assert sub.users()
    assert len(sub.passwords()) >= 400

    new = get_product("new-api")
    assert new.id == "newapi"
    assert new.login_path == "/api/user/login"
    assert new.login_user_field == "username"
    assert new.export_path == "/api/token/"
    assert new.idor_path == "/api/token/{id}"
    assert "/api/status" in new.fingerprint_paths
    assert new.credential_pairs()[0][0] in {"root", "admin"}

    one = get_product("oneapi")
    assert one.login_path == "/api/user/login"


def test_extract_api_keys() -> None:
    text = '{"key":"sk-abcdefghijklmnopqrstuvwxyz123456","x":"sk-proj-ABCDEFGHIJKLMNOPQRSTUV"}'
    keys = extract_api_keys(text)
    assert any(k.startswith("sk-") for k in keys)


def _settings(concurrency: int = 2) -> Settings:
    return Settings("", "", "https://fofa.info", 100, 3, None, 1, concurrency)


def test_default_http_clients_use_browser_user_agent() -> None:
    settings = _settings()
    fofa = FofaClient(settings)
    clients = [
        fofa.http,
        fingerprint_http_client(settings),
        spray_http_client(settings),
        export_http_client(settings),
    ]
    try:
        for client in clients:
            request = client.build_request("GET", "https://example.test")
            user_agent = request.headers["User-Agent"]
            assert user_agent == BROWSER_USER_AGENT
            assert user_agent.startswith("Mozilla/5.0 ")
            assert " Chrome/" in user_agent
            assert user_agent.endswith(" Safari/537.36")
            assert "hunter" not in user_agent.lower()
    finally:
        fofa.close()
        for client in clients[1:]:
            client.close()


class _FingerprintHttp:
    def __init__(self, responses: dict[str, httpx.Response]) -> None:
        self.responses = responses

    def get(self, url: str) -> httpx.Response:
        path = url.removeprefix("http://target")
        return self.responses.get(path, httpx.Response(404))


def test_sub2api_fingerprint_requires_product_evidence() -> None:
    generic = _FingerprintHttp({"/api/v1/auth/login": httpx.Response(405)})
    miss = fingerprint_one(
        "http://target", get_product("sub2api"), _settings(), generic
    )
    assert miss["alive"] is True
    assert miss["matched"] is False

    product = _FingerprintHttp(
        {"/api/v1/settings/public": httpx.Response(200, text='{"site_name":"Sub2API"}')}
    )
    hit = fingerprint_one("http://target", get_product("sub2api"), _settings(), product)
    assert hit["matched"] is True


class _SprayClient:
    def __init__(self, settings: Settings) -> None:
        self.calls: list[str] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def close(self) -> None:
        return None

    def post(self, url: str, json: dict[str, str]) -> httpx.Response:
        password = json["password"]
        self.calls.append(password)
        if password == "plain":
            return httpx.Response(
                200, json={"access_token": "user", "user": {"role": "user"}}
            )
        if password == "admin":
            return httpx.Response(
                200, json={"access_token": "admin", "user": {"role": "admin"}}
            )
        return httpx.Response(401, json={"detail": "bad credentials"})


def test_spray_continues_after_non_admin_and_defaults_to_all(
    monkeypatch, tmp_path: Path
) -> None:
    (tmp_path / "users.txt").write_text("operator\n", encoding="utf-8")
    (tmp_path / "passwords.txt").write_text("plain\nadmin\n", encoding="utf-8")
    product = ProductProfile(
        id="demo",
        fofa_queries=(),
        users_file="users.txt",
        passwords_file="passwords.txt",
        login_path="/login",
        login_user_field="username",
        export_path="/export",
        fingerprint_paths=("/",),
        title_markers=("demo",),
        use_shared_weak_passwords=False,
    )
    monkeypatch.setattr("keyhunter.products.DATA", tmp_path)
    client = _SprayClient(_settings())
    monkeypatch.setattr("keyhunter.spray._client", lambda settings: client)

    result = spray_target("http://target", product, _settings())

    assert result["ok"] is True
    assert result["admin"] is True
    assert result["attempts"] == 2
    assert result["non_admin_hits"] == 1


class _ExportClient:
    def __init__(self, settings: Settings) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def get(self, *args: object, **kwargs: object) -> httpx.Response:
        return httpx.Response(200, json={"message": "ok"})


def test_sub2api_export_rejects_unexpected_success_schema(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("keyhunter.export._client", _ExportClient)
    result = export_sub2api_accounts(
        "http://target", "token", _settings(), out_dir=tmp_path
    )
    assert result["ok"] is False
    assert result["reason"] == "unexpected_schema"


def test_normalize_preserves_same_email_accounts(tmp_path: Path) -> None:
    raw = tmp_path / "raw.json"
    write_json(
        raw,
        {
            "accounts": [
                {
                    "name": "same@example.com",
                    "credentials": {"access_token": "one.one.one"},
                },
                {
                    "name": "same@example.com",
                    "credentials": {"access_token": "two.two.two"},
                },
            ]
        },
    )
    out = tmp_path / "out"
    summary = normalize_export_file(raw, out, origin_hint="http://target")
    assert summary["count"] == 2
    assert len(list((out / "cpa").glob("same_example.com-*.json"))) == 2


def test_high_value_accepts_naive_iso_timestamp() -> None:
    summary = finding_summary(
        {"expired": "2999-01-01T00:00:00", "access_token": "token"},
        "cpa/x.json",
    )
    assert summary["high_value"] is True


def test_validate_rejects_unknown_or_invalid_exp_and_isolates_bad_files(
    tmp_path: Path,
) -> None:
    unknown = validate_cpa({"access_token": "not-a-jwt"})
    assert unknown["access_alive"] is False
    assert unknown["usable"] is False
    assert unknown["reason"] == "unparseable_access_token"

    invalid_token = "e30.eyJleHAiOiJub3QtYS10aW1lIn0.x"
    invalid = validate_cpa({"access_token": invalid_token})
    assert invalid["reason"] == "invalid_exp"

    cpa = tmp_path / "cpa"
    cpa.mkdir()
    (cpa / "bad.json").write_text("{", encoding="utf-8")
    write_json(cpa / "unknown.json", {"access_token": "not-a-jwt"})
    summary = validate_dir(tmp_path, tmp_path / "valid.json")
    assert summary["total"] == 2
    assert summary["usable"] == 0


def test_newapi_normalization_preserves_product_and_origin(tmp_path: Path) -> None:
    exports = tmp_path / "exports"
    raw = exports / "raw" / "target.json"
    key = "sk-abcdefghijklmnopqrstuvwxyz123456"
    write_json(raw, {"data": [{"key": key}]})
    write_json(
        exports / "export_index.json",
        [{"raw_path": str(raw), "origin": "http://target", "product": "oneapi"}],
    )
    out = tmp_path / "artifacts"
    summary = normalize_newapi_exports(exports, out, "oneapi")
    item = json.loads(next((out / "keys").glob("*.json")).read_text(encoding="utf-8"))
    assert summary["product"] == "oneapi"
    assert item["product"] == "oneapi"
    assert item["source_origin"] == "http://target"
