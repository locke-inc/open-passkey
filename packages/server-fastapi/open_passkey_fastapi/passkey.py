"""FastAPI router exposing 4 POST routes for WebAuthn registration and authentication."""

from fastapi import APIRouter, HTTPException

from open_passkey_server import PasskeyConfig, PasskeyError, PasskeyHandler

from .models import (
    BeginAuthenticationRequest,
    BeginRegistrationRequest,
    FinishAuthenticationRequest,
    FinishRegistrationRequest,
)


def create_passkey_router(config: PasskeyConfig) -> APIRouter:
    """Create a FastAPI APIRouter with the 4 WebAuthn endpoints."""
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
            return handler.finish_authentication(req.userId, req.credential.model_dump())
        except PasskeyError as e:
            raise HTTPException(e.status_code, str(e))

    return router
