from __future__ import annotations

import base64
import json
import time
from typing import Final
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, ConfigDict

from aipocket.core.models import Credential

_READONLY_SCOPE: Final = "https://www.googleapis.com/auth/cloud-platform.read-only"
_TOKEN_URL: Final = "https://oauth2.googleapis.com/token"
_GENERATIVE_HOST: Final = "generativelanguage.googleapis.com"


class VertexValidation(BaseModel):
    model_config = ConfigDict(frozen=True)

    valid: bool
    status_code: int | None = None
    models: tuple[str, ...] = ()
    error: str = ""
    access_token_used: bool = False


def _context(credential: Credential) -> tuple[str, str, str]:
    context = credential.bundle.context if credential.bundle is not None else None
    project = context.project if context is not None else ""
    location = context.location if context is not None else ""
    email = context.service_account_email if context is not None else ""
    return project, location, email


def _models_url(project: str, location: str) -> str:
    return (
        f"https://{location}-aiplatform.googleapis.com/v1/projects/{project}/locations/"
        f"{location}/publishers/google/models"
    )


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _bearer_expired(token: str) -> bool:
    """Return True when a JWT-shaped bearer has an exp claim in the past."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return False
    exp = payload.get("exp")
    if not isinstance(exp, int | float):
        return False
    return float(exp) <= time.time()


def _model_name(raw: str) -> str:
    name = raw.strip()
    if "/models/" in name:
        return name.rsplit("/models/", 1)[-1]
    if name.startswith("models/"):
        return name.removeprefix("models/")
    return name


def _service_account_assertion(credential: Credential) -> str:
    """Build a JWT assertion for the OAuth token endpoint.

    Uses google-auth only for RSA signing; network I/O stays on httpx.
    """
    from google.auth import crypt, jwt

    project, _location, email = _context(credential)
    private_key = credential.apikey
    if credential.bundle is not None:
        private_key = credential.bundle.secret_value.reveal()
    if not email:
        raise ValueError("missing-service-account-email")

    now = int(time.time())
    payload = {
        "iss": email,
        "sub": email,
        "aud": _TOKEN_URL,
        "iat": now,
        "exp": now + 3600,
        "scope": _READONLY_SCOPE,
    }
    if project:
        payload["project_id"] = project
    signer = crypt.RSASigner.from_string(private_key)
    return jwt.encode(signer, payload)


async def _exchange_service_account_token(
    client: httpx.AsyncClient,
    credential: Credential,
) -> tuple[str | None, str]:
    try:
        assertion = _service_account_assertion(credential)
    except Exception:
        return None, "assertion-failed"

    body = urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
            "scope": _READONLY_SCOPE,
        }
    )
    response = await client.post(
        _TOKEN_URL,
        content=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if response.status_code != 200:
        return None, "token-exchange-failed"
    payload = response.json()
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        return None, "token-exchange-failed"
    return token, ""


def _extract_models(payload: object) -> tuple[str, ...]:
    if not isinstance(payload, dict):
        return ()
    for key in ("publisherModels", "models", "data"):
        items = payload.get(key)
        if not isinstance(items, list):
            continue
        names: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            raw = item.get("name") or item.get("id")
            if isinstance(raw, str) and raw:
                names.append(_model_name(raw))
        if names:
            return tuple(names)
    return ()


async def validate_vertex(
    client: httpx.AsyncClient,
    credential: Credential,
) -> VertexValidation:
    """Validate Vertex credentials with read-only model listing only.

    Never contacts generativelanguage.googleapis.com — that host is Gemini Developer API.
    """
    project, location, _email = _context(credential)
    if not project:
        return VertexValidation(valid=False, error="missing-project")
    if not location:
        return VertexValidation(valid=False, error="missing-location")

    kind = credential.bundle.credential_kind if credential.bundle is not None else "token"
    access_token = credential.apikey
    if kind == "google_service_account":
        token, error = await _exchange_service_account_token(client, credential)
        if token is None:
            return VertexValidation(valid=False, error=error)
        access_token = token
    else:
        if _bearer_expired(access_token):
            return VertexValidation(valid=False, error="expired-token")

    url = _models_url(project, location)
    if _GENERATIVE_HOST in url:
        return VertexValidation(valid=False, error="invalid-vertex-endpoint")

    response = await client.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if response.status_code == 401:
        return VertexValidation(valid=False, status_code=401, error="unauthorized")
    if response.status_code == 403:
        return VertexValidation(valid=False, status_code=403, error="forbidden")
    if response.status_code != 200:
        return VertexValidation(
            valid=False,
            status_code=response.status_code,
            error="models-read-failed",
        )

    models = _extract_models(response.json())
    return VertexValidation(
        valid=True,
        status_code=response.status_code,
        models=models,
        access_token_used=True,
    )
