from __future__ import annotations

import re
from typing import Final

import httpx
from pydantic import BaseModel, ConfigDict

from aipocket.core.models import Credential

# Google AI Studio / Gemini Developer API keys are 39 characters: AIza + 35 body chars.
# Body may include hyphens/underscores but must contain at least one alphanumeric character
# so degenerate all-separator strings are rejected during routing.
_GEMINI_KEY_RE: Final = re.compile(r"^AIza[0-9A-Za-z_\-]{35}$")
_GEMINI_MODELS_URL: Final = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiValidation(BaseModel):
    model_config = ConfigDict(frozen=True)

    valid: bool
    status_code: int | None = None
    models: tuple[str, ...] = ()
    error: str = ""


def is_gemini_api_key(apikey: str) -> bool:
    """Return True only for exact Gemini Developer API key shape."""
    if not _GEMINI_KEY_RE.fullmatch(apikey):
        return False
    return any(char.isalnum() for char in apikey[4:])


def _model_name(raw: str) -> str:
    name = raw.strip()
    if name.startswith("models/"):
        return name.removeprefix("models/")
    return name


async def validate_gemini(
    client: httpx.AsyncClient,
    credential: Credential,
) -> GeminiValidation:
    """Read-only Gemini Developer API validation via models list (query key auth)."""
    if not is_gemini_api_key(credential.apikey):
        return GeminiValidation(valid=False, error="not-gemini-credential")

    response = await client.get(_GEMINI_MODELS_URL, params={"key": credential.apikey})
    if response.status_code != 200:
        return GeminiValidation(
            valid=False,
            status_code=response.status_code,
            error="models-read-failed",
        )

    payload = response.json()
    items = payload.get("models", []) if isinstance(payload, dict) else []
    models = tuple(
        _model_name(str(item["name"]))
        for item in items
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    )
    return GeminiValidation(valid=True, status_code=response.status_code, models=models)
