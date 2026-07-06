"""Authentication routes: login / logout."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth import get_current_user, issue_token, verify_password
from ..errors import ApiError
from ..schemas import LoginRequest, LoginResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest) -> LoginResponse:
    if not verify_password(body.password):
        raise ApiError("invalid password", status_code=401, code="unauthorized")
    token, ttl = issue_token()
    return LoginResponse(token=token, expires_in=ttl)


@router.post("/logout")
async def logout(_: str = Depends(get_current_user)) -> dict:
    # Stateless JWT — nothing to revoke server-side; the client discards the token.
    return {"ok": True}
