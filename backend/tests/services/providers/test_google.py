from __future__ import annotations

import base64
import json
import time

import httpx
import pytest
import respx

from aipocket.core.credentials import CredentialBundle, CredentialContext
from aipocket.core.models import Credential
from aipocket.services.providers.gemini import validate_gemini
from aipocket.services.providers.registry import resolve_provider
from aipocket.services.providers.vertex import validate_vertex
from aipocket.services.validator import _probe

GEMINI_KEY = "AIza" + "A" * 35
VERTEX_MODELS = (
    "https://us-central1-aiplatform.googleapis.com/v1/projects/sample/locations/"
    "us-central1/publishers/google/models"
)


def _token(*, expires_at: int) -> str:
    payload = (
        base64.urlsafe_b64encode(json.dumps({"exp": expires_at}).encode()).decode().rstrip("=")
    )
    return f"header.{payload}.signature"


def _vertex(
    secret: str, *, kind: str = "token", project: str = "sample", location: str = "us-central1"
) -> Credential:
    bundle = CredentialBundle.create(
        secret,
        credential_kind=kind,
        provider_hint="vertex",
        context=CredentialContext(project=project, location=location),
    )
    return Credential(apikey=secret, bundle=bundle)


@pytest.mark.parametrize("key", ["AIza" + "A" * 34, "AIza" + "A" * 36, "AIza" + "-" * 35])
def test_gemini_requires_exact_api_key_shape(key: str) -> None:
    assert resolve_provider(apikey=key).provider == "unknown"


@respx.mock
async def test_gemini_uses_only_generativelanguage_models_endpoint() -> None:
    route = respx.get(
        "https://generativelanguage.googleapis.com/v1beta/models",
        params={"key": GEMINI_KEY},
    ).mock(return_value=httpx.Response(200, json={"models": [{"name": "models/gemini-2.0-flash"}]}))

    async with httpx.AsyncClient() as client:
        result = await validate_gemini(client, Credential(apikey=GEMINI_KEY))

    assert result.valid is True
    assert result.models == ("gemini-2.0-flash",)
    assert route.called
    assert [call.request.method for call in respx.calls] == ["GET"]


@pytest.mark.parametrize(
    ("project", "location", "error"),
    [("", "us-central1", "missing-project"), ("sample", "", "missing-location")],
)
async def test_vertex_requires_project_and_location(
    project: str, location: str, error: str
) -> None:
    async with httpx.AsyncClient() as client:
        result = await validate_vertex(client, _vertex("token", project=project, location=location))

    assert result.valid is False
    assert result.error == error


async def test_vertex_rejects_expired_bearer_without_api_request() -> None:
    async with httpx.AsyncClient() as client:
        result = await validate_vertex(client, _vertex(_token(expires_at=int(time.time()) - 60)))

    assert result.valid is False
    assert result.error == "expired-token"


@pytest.mark.parametrize(("status", "error"), [(401, "unauthorized"), (403, "forbidden")])
@respx.mock
async def test_vertex_classifies_authorization_failures(status: int, error: str) -> None:
    respx.get(VERTEX_MODELS).mock(return_value=httpx.Response(status))

    async with httpx.AsyncClient() as client:
        result = await validate_vertex(client, _vertex(_token(expires_at=int(time.time()) + 3600)))

    assert result.valid is False
    assert result.error == error
    assert all(
        "generativelanguage.googleapis.com" not in str(call.request.url) for call in respx.calls
    )


@respx.mock
async def test_vertex_bearer_reads_models_without_inference() -> None:
    route = respx.get(VERTEX_MODELS).mock(
        return_value=httpx.Response(
            200, json={"publisherModels": [{"name": "publishers/google/models/gemini-2.0-flash"}]}
        )
    )

    async with httpx.AsyncClient() as client:
        result = await validate_vertex(client, _vertex(_token(expires_at=int(time.time()) + 3600)))

    assert result.valid is True
    assert result.models == ("gemini-2.0-flash",)
    assert route.calls[0].request.headers["authorization"].startswith("Bearer ")
    assert [call.request.method for call in respx.calls] == ["GET"]


@respx.mock
async def test_service_account_exchanges_restricted_scope_then_reads_vertex(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = _vertex("private-key", kind="google_service_account")
    token_route = respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "access-token", "expires_in": 3600})
    )
    respx.get(VERTEX_MODELS).mock(return_value=httpx.Response(200, json={"publisherModels": []}))
    monkeypatch.setattr(
        "aipocket.services.providers.vertex._service_account_assertion",
        lambda _: "signed-assertion",
    )

    async with httpx.AsyncClient() as client:
        result = await validate_vertex(client, credential)

    form = token_route.calls[0].request.content.decode()
    assert result.valid is True
    assert "https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform.read-only" in form
    assert "cloud-platform&" not in form
    assert all(
        "generativelanguage.googleapis.com" not in str(call.request.url) for call in respx.calls
    )


@respx.mock
async def test_probe_routes_gemini_and_vertex_through_adapters() -> None:
    respx.get(
        "https://generativelanguage.googleapis.com/v1beta/models",
        params={"key": GEMINI_KEY},
    ).mock(return_value=httpx.Response(200, json={"models": [{"name": "models/gemini-2.0-flash"}]}))
    respx.get(VERTEX_MODELS).mock(
        return_value=httpx.Response(
            200, json={"publisherModels": [{"name": "publishers/google/models/gemini-2.0-flash"}]}
        )
    )
    openai_chat = respx.post(url__regex=r".*chat/completions.*").mock(
        return_value=httpx.Response(500)
    )

    async with httpx.AsyncClient() as client:
        gemini = await _probe(client, Credential(apikey=GEMINI_KEY))
        vertex = await _probe(
            client,
            _vertex(_token(expires_at=int(time.time()) + 3600)),
        )

    assert gemini.valid is True
    assert gemini.provider_info.provider == "google"
    assert gemini.validation_state == "authentication_confirmed"
    assert vertex.valid is True
    assert vertex.provider_info.provider == "vertex"
    assert vertex.validation_state == "authentication_confirmed"
    assert not openai_chat.called
