"""Authentication routes: login / logout."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..deps import (
    check_login_allowed,
    get_current_user,
    issue_token,
    record_login_failure,
    reset_login_failures,
    verify_password,
)
from ..errors import ApiError
from ..schemas import LoginRequest, LoginResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request) -> LoginResponse:
    ip = request.client.host if request.client else "unknown"
    check_login_allowed(ip)
    if not verify_password(body.password):
        record_login_failure(ip)
        raise ApiError("invalid password", status_code=401, code="unauthorized")
    reset_login_failures(ip)
    token, ttl = issue_token()
    return LoginResponse(token=token, expires_in=ttl)


@router.post("/logout")
async def logout(_: str = Depends(get_current_user)) -> dict:
    # Stateless JWT — nothing to revoke server-side; the client discards the token.
    return {"ok": True}
