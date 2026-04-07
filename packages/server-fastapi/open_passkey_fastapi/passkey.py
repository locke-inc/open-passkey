"""FastAPI router exposing WebAuthn registration, authentication, and optional session routes."""

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from open_passkey_server import PasskeyConfig, PasskeyError, PasskeyHandler
from open_passkey_server.session import build_clear_cookie_header, build_set_cookie_header, parse_cookie_token

from .models import (
    BeginAuthenticationRequest,
    BeginRegistrationRequest,
    FinishAuthenticationRequest,
    FinishRegistrationRequest,
)


def create_passkey_router(config: PasskeyConfig) -> APIRouter:
    """Create a FastAPI APIRouter with the WebAuthn endpoints (+ session routes when configured)."""
    router = APIRouter()
    handler = PasskeyHandler(config)

    @router.post("/register/begin")
    async def begin_registration(req: BeginRegistrationRequest):
        try:
            return handler.begin_registration(req.userId, req.username)
        except PasskeyError as e:
            raise HTTPException(e.status_code, str(e))

    @router.post("/register/finish")
    async def finish_registration(req: FinishRegistrationRequest):
        try:
            return handler.finish_registration(
                req.userId,
                req.credential.model_dump(),
                req.prfSupported is True,
            )
        except PasskeyError as e:
            raise HTTPException(e.status_code, str(e))

    @router.post("/login/begin")
    async def begin_authentication(req: BeginAuthenticationRequest = BeginAuthenticationRequest()):
        try:
            return handler.begin_authentication(req.userId or "")
        except PasskeyError as e:
            raise HTTPException(e.status_code, str(e))

    @router.post("/login/finish")
    async def finish_authentication(req: FinishAuthenticationRequest):
        try:
            result = handler.finish_authentication(req.userId, req.credential.model_dump())
        except PasskeyError as e:
            raise HTTPException(e.status_code, str(e))

        if config.session is not None and "sessionToken" in result:
            token = result.pop("sessionToken")
            response = JSONResponse(content=result)
            response.headers["Set-Cookie"] = build_set_cookie_header(token, config.session)
            return response

        return result

    if config.session is not None:
        @router.get("/session")
        async def get_session(request: Request):
            cookie_header = request.headers.get("cookie")
            token = parse_cookie_token(cookie_header, config.session)
            if not token:
                raise HTTPException(401, "no session cookie")
            try:
                data = handler.get_session_token_data(token)
            except (PasskeyError, ValueError):
                raise HTTPException(401, "invalid session")
            return {"userId": data.user_id, "authenticated": True}

        @router.post("/logout")
        async def logout():
            response = JSONResponse(content={"success": True})
            response.headers["Set-Cookie"] = build_clear_cookie_header(config.session)
            return response

    return router
