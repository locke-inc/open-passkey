"""FastAPI router exposing 4 POST routes for WebAuthn registration and authentication."""

import json
import logging
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass

from fastapi import APIRouter, HTTPException

from open_passkey import verify_authentication, verify_registration

from .models import (
    BeginAuthenticationRequest,
    BeginRegistrationRequest,
    FinishAuthenticationRequest,
    FinishRegistrationRequest,
)
from .stores import (
    ChallengeStore,
    CredentialStore,
    MemoryChallengeStore,
    MemoryCredentialStore,
    PasskeyError,
    StoredCredential,
)

logger = logging.getLogger(__name__)


def _b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return urlsafe_b64decode(s)


@dataclass
class PasskeyConfig:
    rp_id: str
    rp_display_name: str
    origin: str
    challenge_store: ChallengeStore | None = None
    credential_store: CredentialStore | None = None
    challenge_length: int = 32
    challenge_timeout_seconds: float = 300.0

    def __post_init__(self):
        if not self.rp_id:
            raise ValueError("rp_id is required")
        if not self.origin:
            raise ValueError("origin is required")
        if "://" in self.rp_id or "/" in self.rp_id:
            raise ValueError(f"rp_id must be a bare domain (got {self.rp_id!r})")
        if not self.origin.startswith("https://") and not self.origin.startswith("http://"):
            raise ValueError(f"origin must start with https:// or http:// (got {self.origin!r})")
        if self.challenge_store is None:
            self.challenge_store = MemoryChallengeStore()
        if self.credential_store is None:
            self.credential_store = MemoryCredentialStore()


def create_passkey_router(config: PasskeyConfig) -> APIRouter:
    """Create a FastAPI APIRouter with the 4 WebAuthn endpoints."""
    router = APIRouter()

    @router.post("/register/begin")
    async def begin_registration(req: BeginRegistrationRequest):
        challenge_bytes = secrets.token_bytes(config.challenge_length)
        challenge = _b64url_encode(challenge_bytes)

        prf_salt = secrets.token_bytes(32)
        challenge_data = json.dumps({"challenge": challenge, "prfSalt": _b64url_encode(prf_salt)})
        config.challenge_store.store(req.userId, challenge_data, config.challenge_timeout_seconds)

        return {
            "challenge": challenge,
            "rp": {"id": config.rp_id, "name": config.rp_display_name},
            "user": {
                "id": _b64url_encode(req.userId.encode()),
                "name": req.username,
                "displayName": req.username,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -52},
                {"type": "public-key", "alg": -49},
                {"type": "public-key", "alg": -7},
            ],
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": "preferred",
            },
            "timeout": int(config.challenge_timeout_seconds * 1000),
            "attestation": "none",
            "extensions": {
                "prf": {"eval": {"first": _b64url_encode(prf_salt)}},
            },
        }

    @router.post("/register/finish")
    async def finish_registration(req: FinishRegistrationRequest):
        try:
            challenge_data = json.loads(config.challenge_store.consume(req.userId))
        except PasskeyError:
            raise HTTPException(400, "challenge not found or expired")

        try:
            result = verify_registration(
                rp_id=config.rp_id,
                expected_challenge=challenge_data["challenge"],
                expected_origin=config.origin,
                client_data_json=req.credential.response.clientDataJSON,
                attestation_object=req.credential.response.attestationObject,
            )
        except Exception as e:
            logger.warning("registration verification failed: %s", e)
            raise HTTPException(400, "registration verification failed")

        cred = StoredCredential(
            credential_id=result.credential_id,
            public_key_cose=result.public_key_cose,
            sign_count=result.sign_count,
            user_id=req.userId,
        )
        prf_enabled = req.prfSupported is True
        if prf_enabled:
            cred.prf_salt = _b64url_decode(challenge_data["prfSalt"])
            cred.prf_supported = True

        config.credential_store.store(cred)

        return {
            "credentialId": _b64url_encode(result.credential_id),
            "registered": True,
            "prfSupported": prf_enabled,
        }

    @router.post("/login/begin")
    async def begin_authentication(req: BeginAuthenticationRequest = BeginAuthenticationRequest()):
        challenge_bytes = secrets.token_bytes(config.challenge_length)
        challenge = _b64url_encode(challenge_bytes)

        challenge_key = req.userId if req.userId else challenge
        config.challenge_store.store(challenge_key, challenge, config.challenge_timeout_seconds)

        options: dict = {
            "challenge": challenge,
            "rpId": config.rp_id,
            "timeout": int(config.challenge_timeout_seconds * 1000),
            "userVerification": "preferred",
        }

        if req.userId:
            allow_credentials = []
            eval_by_credential = {}
            has_prf = False
            try:
                creds = config.credential_store.get_by_user(req.userId)
                for c in creds:
                    cred_id_encoded = _b64url_encode(c.credential_id)
                    allow_credentials.append({"type": "public-key", "id": cred_id_encoded})
                    if c.prf_supported and c.prf_salt:
                        eval_by_credential[cred_id_encoded] = {"first": _b64url_encode(c.prf_salt)}
                        has_prf = True
            except PasskeyError:
                pass
            options["allowCredentials"] = allow_credentials
            if has_prf:
                options["extensions"] = {"prf": {"evalByCredential": eval_by_credential}}

        return options

    @router.post("/login/finish")
    async def finish_authentication(req: FinishAuthenticationRequest):
        try:
            challenge = config.challenge_store.consume(req.userId)
        except PasskeyError:
            raise HTTPException(400, "challenge not found or expired")

        cred_id_bytes = _b64url_decode(req.credential.id)
        try:
            stored = config.credential_store.get(cred_id_bytes)
        except PasskeyError:
            raise HTTPException(400, "credential not found")

        if req.credential.response.userHandle:
            if _b64url_decode(req.credential.response.userHandle).decode() != stored.user_id:
                raise HTTPException(400, "userHandle does not match credential owner")

        try:
            result = verify_authentication(
                rp_id=config.rp_id,
                expected_challenge=challenge,
                expected_origin=config.origin,
                stored_public_key_cose=stored.public_key_cose,
                stored_sign_count=stored.sign_count,
                client_data_json=req.credential.response.clientDataJSON,
                authenticator_data=req.credential.response.authenticatorData,
                signature=req.credential.response.signature,
            )
        except Exception as e:
            logger.warning("authentication verification failed: %s", e)
            raise HTTPException(400, "authentication verification failed")

        stored.sign_count = result.sign_count
        config.credential_store.update(stored)

        resp: dict = {"userId": stored.user_id, "authenticated": True}
        if stored.prf_supported:
            resp["prfSupported"] = True
        return resp

    return router
