from __future__ import annotations

import httpx
import pytest
import respx

from aipocket.core.credentials import CredentialBundle, CredentialContext
from aipocket.core.models import Credential, ValidationResult
from aipocket.services.high_value_writer import is_high_value_key, should_save
from aipocket.services.providers.anthropic import (
    AnthropicCredentialKind,
    classify_anthropic_credential,
    validate_anthropic,
)
from aipocket.services.providers.registry import resolve_provider
from aipocket.services.validator import _forged_key_probe, _probe

BASE = "https://api.anthropic.com/v1"
API_KEY = "sk-ant-api03-" + "A" * 40
ADMIN_KEY = "sk-ant-admin-" + "A" * 40
OAUTH_TOKEN = "sk-ant-oat-" + "A" * 40


def _credential(key: str, *, organization: str = "", workspace: str = "") -> Credential:
    bundle = CredentialBundle.create(
        key,
        provider_hint="anthropic",
        endpoint_candidates=(BASE,),
        context=CredentialContext(organization=organization, workspace=workspace),
    )
    return Credential(apikey=key, apiurl=BASE, bundle=bundle)


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (API_KEY, AnthropicCredentialKind.API),
        (ADMIN_KEY, AnthropicCredentialKind.ADMIN),
        (OAUTH_TOKEN, AnthropicCredentialKind.OAUTH),
    ],
)
def test_classifies_anthropic_credential_kinds(key: str, expected: AnthropicCredentialKind) -> None:
    assert classify_anthropic_credential(_credential(key)) is expected
    assert resolve_provider(apikey=key).provider == "anthropic"


def test_unrelated_sk_key_is_not_classified_as_anthropic() -> None:
    credential = Credential(apikey="sk-" + "a" * 48, apiurl="https://gateway.example/v1")
    assert classify_anthropic_credential(credential) is None


@respx.mock
async def test_admin_key_calls_organizations_me_with_x_api_key_only() -> None:
    route = respx.get(f"{BASE}/organizations/me").mock(
        return_value=httpx.Response(
            200,
            json={"id": "org_123", "name": "Acme", "type": "organization"},
        )
    )
    messages = respx.post(f"{BASE}/messages").mock(return_value=httpx.Response(500))

    async with httpx.AsyncClient() as client:
        result = await validate_anthropic(client, _credential(ADMIN_KEY))

    assert result.valid is True
    assert result.credential_kind is AnthropicCredentialKind.ADMIN
    assert result.organization_id == "org_123"
    assert result.scope == "org:admin"
    assert route.called
    assert route.calls[0].request.headers["x-api-key"] == ADMIN_KEY
    assert "authorization" not in {k.lower() for k in route.calls[0].request.headers}
    assert not messages.called
    assert [call.request.method for call in respx.calls] == ["GET"]


@respx.mock
async def test_oauth_token_uses_bearer_for_organizations_me() -> None:
    route = respx.get(f"{BASE}/organizations/me").mock(
        return_value=httpx.Response(
            200,
            json={"id": "org_oauth", "name": "OAuth Org"},
        )
    )

    async with httpx.AsyncClient() as client:
        result = await validate_anthropic(client, _credential(OAUTH_TOKEN))

    assert result.valid is True
    assert result.credential_kind is AnthropicCredentialKind.OAUTH
    assert result.organization_id == "org_oauth"
    assert result.scope == "org:admin"
    assert route.calls[0].request.headers["authorization"] == f"Bearer {OAUTH_TOKEN}"
    assert "x-api-key" not in {k.lower() for k in route.calls[0].request.headers}


@respx.mock
async def test_api_key_uses_models_then_optional_messages_semantics() -> None:
    models = respx.get(f"{BASE}/models").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": "claude-sonnet-4-6"}, {"id": "claude-haiku-4-5-20251001"}]},
        )
    )
    messages = respx.post(f"{BASE}/messages").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "msg_1",
                "type": "message",
                "content": [{"type": "text", "text": "ok"}],
            },
        )
    )

    async with httpx.AsyncClient() as client:
        result = await validate_anthropic(client, _credential(API_KEY))

    assert result.valid is True
    assert result.credential_kind is AnthropicCredentialKind.API
    assert result.models == ("claude-sonnet-4-6", "claude-haiku-4-5-20251001")
    assert result.verified_model == "claude-sonnet-4-6"
    assert models.called
    assert messages.called
    assert messages.calls[0].request.headers["x-api-key"] == API_KEY
    assert messages.calls[0].request.headers["anthropic-version"] == "2023-06-01"
    body = messages.calls[0].request.content.decode()
    assert "claude-sonnet-4-6" in body
    assert "max_tokens" in body


@respx.mock
async def test_forged_key_probe_uses_anthropic_protocol_not_openai() -> None:
    route = respx.post(f"{BASE}/messages").mock(return_value=httpx.Response(401))
    openai = respx.post(f"{BASE}/chat/completions").mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient() as client:
        verdict = await _forged_key_probe(
            client,
            f"{BASE}/chat/completions",
            "claude-sonnet-4-6",
            provider="anthropic",
        )

    assert verdict == ""
    assert route.called
    assert not openai.called
    assert route.calls[0].request.headers["x-api-key"].startswith("sk-")


@respx.mock
async def test_probe_routes_admin_keys_through_adapter() -> None:
    respx.get(f"{BASE}/organizations/me").mock(
        return_value=httpx.Response(200, json={"id": "org_routed", "name": "Routed"})
    )
    respx.post(f"{BASE}/messages").mock(return_value=httpx.Response(500))

    async with httpx.AsyncClient() as client:
        result = await _probe(client, _credential(ADMIN_KEY))

    assert result.valid is True
    assert result.provider_info.provider == "anthropic"
    assert result.status_code == 200
    assert result.error == ""


def test_broad_sk_ant_prefix_alone_is_not_high_value() -> None:
    assert is_high_value_key(API_KEY) is False
    plain = ValidationResult(
        credential=Credential(apikey=API_KEY, apiurl=BASE),
        valid=True,
        status_code=200,
    )
    assert should_save(plain) is False


def test_admin_org_scope_or_high_value_model_qualifies() -> None:
    admin = ValidationResult(
        credential=_credential(ADMIN_KEY),
        valid=True,
        status_code=200,
        tier="org:admin",
    )
    assert should_save(admin) is True

    with_model = ValidationResult(
        credential=_credential(API_KEY),
        valid=True,
        status_code=200,
        model_available="claude-sonnet-4-6",
        provider_info={"provider": "anthropic", "models_verified": ["claude-sonnet-4-6"]},
    )
    assert should_save(with_model) is True
