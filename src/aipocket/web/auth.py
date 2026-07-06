"""JWT-based authentication for the web API.

A single global password (``settings.web_password``) is exchanged for a signed
JWT bearer token via ``POST /api/auth/login``. All other routes depend on
:func:`get_current_user`, which validates the token from the ``Authorization:
Bearer <token>`` header.

No users, no roles, no server-side session store — the token is self-contained
and stateless. Process restart doesn't invalidate tokens (they expire by ``exp``).
"""

from __future__ import annotations

import hmac
import logging
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..config import settings

log = logging.getLogger(__name__)

_ALGORITHM = "HS256"
_bearer = HTTPBearer(auto_error=False)


def verify_password(candidate: str) -> bool:
    """Constant-time comparison against the configured global password."""
    if not settings.web_password:
        return False
    return hmac.compare_digest(candidate.encode(), settings.web_password.encode())


def issue_token() -> tuple[str, int]:
    """Sign a new JWT. Returns ``(token, expires_in_seconds)``."""
    ttl = int(settings.web_token_ttl)
    now = datetime.now(UTC)
    payload = {
        "sub": "web-user",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
    }
    token = jwt.encode(payload, settings.web_jwt_secret, algorithm=_ALGORITHM)
    return token, ttl


def _decode(token: str) -> dict:
    return jwt.decode(token, settings.web_jwt_secret, algorithms=[_ALGORITHM])


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    """FastAPI dependency — require a valid bearer token, else 401."""
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="missing bearer token")
    try:
        payload = _decode(creds.credentials)
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail="token expired") from e
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail="invalid token") from e
    return str(payload.get("sub", "web-user"))
