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
import time
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from aipocket.core.config import settings

log = logging.getLogger(__name__)

_ALGORITHM = "HS256"
_bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Login rate limiting (in-memory, per client IP)
# ---------------------------------------------------------------------------
# The single global password is the only gate protecting plaintext-key export
# and scan control, so throttle brute-force attempts. This is process-local (not
# distributed) — sufficient for the single-process deployment; behind a proxy it
# keys on the proxy's IP. Dict mutations are safe on the single-threaded loop.
_LOGIN_WINDOW_SECONDS = 300.0
_LOGIN_MAX_FAILURES = 10
_login_failures: dict[str, list[float]] = {}


def _recent_failures(ip: str, now: float) -> list[float]:
    recent = [t for t in _login_failures.get(ip, []) if now - t < _LOGIN_WINDOW_SECONDS]
    if recent:
        _login_failures[ip] = recent
    else:
        _login_failures.pop(ip, None)
    return recent


def check_login_allowed(ip: str) -> None:
    """Raise 429 when this client has too many recent failed logins."""
    if len(_recent_failures(ip, time.monotonic())) >= _LOGIN_MAX_FAILURES:
        raise HTTPException(status_code=429, detail="too many login attempts, try again later")


def record_login_failure(ip: str) -> None:
    _login_failures.setdefault(ip, []).append(time.monotonic())


def reset_login_failures(ip: str) -> None:
    """Clear a client's failure counter after a successful login."""
    _login_failures.pop(ip, None)


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


def _verify(token: str) -> str:
    """Decode and validate a bearer token, returning the subject or raising 401."""
    try:
        payload = _decode(token)
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail="token expired") from e
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail="invalid token") from e
    return str(payload.get("sub", "web-user"))


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    """FastAPI dependency — require a valid bearer token, else 401."""
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="missing bearer token")
    return _verify(creds.credentials)


async def get_current_user_sse(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    token: str | None = Query(default=None),
) -> str:
    """Like :func:`get_current_user`, but also accepts the token via a ``token``
    query parameter.

    ``EventSource`` cannot set an ``Authorization`` header, so the SSE stream
    passes the JWT as a query param. The header still takes precedence when both
    are supplied.
    """
    candidate = creds.credentials if creds and creds.credentials else token
    if not candidate:
        raise HTTPException(status_code=401, detail="missing bearer token")
    return _verify(candidate)
