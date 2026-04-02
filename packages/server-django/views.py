"""Django class-based views exposing 4 POST endpoints for WebAuthn ceremonies."""

import json
import logging
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode

from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from open_passkey_core import verify_authentication, verify_registration

from .stores import PasskeyError, StoredCredential

logger = logging.getLogger(__name__)


def _b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return urlsafe_b64decode(s)


def _error(message: str, status: int = 400) -> JsonResponse:
    return JsonResponse({"error": message}, status=status)


# The config is injected at URL-wiring time via passkey_urls().
# Each view class stores a reference to the shared config object.

class _PasskeyConfig:
    """Runtime configuration, set once when urls are created."""
    rp_id: str = ""
    rp_display_name: str = ""
    origin: str = ""
    challenge_store = None
    credential_store = None
    challenge_length: int = 32
    challenge_timeout_seconds: float = 300.0


_config = _PasskeyConfig()


def configure(
    rp_id: str,
    rp_display_name: str,
    origin: str,
    challenge_store,
    credential_store,
    challenge_length: int = 32,
    challenge_timeout_seconds: float = 300.0,
):
    """Must be called before including passkey urls."""
    if not rp_id:
        raise ValueError("rp_id is required")
    if not origin:
        raise ValueError("origin is required")
    if "://" in rp_id or "/" in rp_id:
        raise ValueError(f"rp_id must be a bare domain (got {rp_id!r})")
    if not origin.startswith("https://") and not origin.startswith("http://"):
        raise ValueError(f"origin must start with https:// or http:// (got {origin!r})")
    _config.rp_id = rp_id
    _config.rp_display_name = rp_display_name
    _config.origin = origin
    _config.challenge_store = challenge_store
    _config.credential_store = credential_store
    _config.challenge_length = challenge_length
    _config.challenge_timeout_seconds = challenge_timeout_seconds


@method_decorator(csrf_exempt, name="dispatch")
class BeginRegistrationView(View):
    def post(self, request):
        body = json.loads(request.body)
        user_id = body.get("userId", "")
        username = body.get("username", "")
        if not user_id or not username:
            return _error("userId and username are required")

        challenge_bytes = secrets.token_bytes(_config.challenge_length)
        challenge = _b64url_encode(challenge_bytes)

        prf_salt = secrets.token_bytes(32)
        challenge_data = json.dumps({"challenge": challenge, "prfSalt": _b64url_encode(prf_salt)})
        _config.challenge_store.store(user_id, challenge_data, _config.challenge_timeout_seconds)

        return JsonResponse({
            "challenge": challenge,
            "rp": {"id": _config.rp_id, "name": _config.rp_display_name},
            "user": {
                "id": _b64url_encode(user_id.encode()),
                "name": username,
                "displayName": username,
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
            "timeout": int(_config.challenge_timeout_seconds * 1000),
            "attestation": "none",
            "extensions": {
                "prf": {"eval": {"first": _b64url_encode(prf_salt)}},
            },
        })


@method_decorator(csrf_exempt, name="dispatch")
class FinishRegistrationView(View):
    def post(self, request):
        body = json.loads(request.body)
        user_id = body.get("userId", "")
        credential = body.get("credential", {})
        prf_supported = body.get("prfSupported", False)

        try:
            challenge_data = json.loads(_config.challenge_store.consume(user_id))
        except PasskeyError:
            return _error("challenge not found or expired")

        try:
            result = verify_registration(
                rp_id=_config.rp_id,
                expected_challenge=challenge_data["challenge"],
                expected_origin=_config.origin,
                client_data_json=credential["response"]["clientDataJSON"],
                attestation_object=credential["response"]["attestationObject"],
            )
        except Exception as e:
            logger.warning("registration verification failed: %s", e)
            return _error("registration verification failed")

        cred = StoredCredential(
            credential_id=result.credential_id,
            public_key_cose=result.public_key_cose,
            sign_count=result.sign_count,
            user_id=user_id,
        )
        if prf_supported:
            cred.prf_salt = _b64url_decode(challenge_data["prfSalt"])
            cred.prf_supported = True

        _config.credential_store.store(cred)

        return JsonResponse({
            "credentialId": _b64url_encode(result.credential_id),
            "registered": True,
            "prfSupported": bool(prf_supported),
        })


@method_decorator(csrf_exempt, name="dispatch")
class BeginAuthenticationView(View):
    def post(self, request):
        body = json.loads(request.body) if request.body else {}
        user_id = body.get("userId", "")

        challenge_bytes = secrets.token_bytes(_config.challenge_length)
        challenge = _b64url_encode(challenge_bytes)

        challenge_key = user_id if user_id else challenge
        _config.challenge_store.store(challenge_key, challenge, _config.challenge_timeout_seconds)

        options = {
            "challenge": challenge,
            "rpId": _config.rp_id,
            "timeout": int(_config.challenge_timeout_seconds * 1000),
            "userVerification": "preferred",
        }

        if user_id:
            allow_credentials = []
            eval_by_credential = {}
            has_prf = False
            try:
                creds = _config.credential_store.get_by_user(user_id)
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

        return JsonResponse(options)


@method_decorator(csrf_exempt, name="dispatch")
class FinishAuthenticationView(View):
    def post(self, request):
        body = json.loads(request.body)
        user_id = body.get("userId", "")
        credential = body.get("credential", {})

        try:
            challenge = _config.challenge_store.consume(user_id)
        except PasskeyError:
            return _error("challenge not found or expired")

        cred_id_bytes = _b64url_decode(credential["id"])
        try:
            stored = _config.credential_store.get(cred_id_bytes)
        except PasskeyError:
            return _error("credential not found")

        user_handle = credential.get("response", {}).get("userHandle", "")
        if user_handle:
            if _b64url_decode(user_handle).decode() != stored.user_id:
                return _error("userHandle does not match credential owner")

        try:
            result = verify_authentication(
                rp_id=_config.rp_id,
                expected_challenge=challenge,
                expected_origin=_config.origin,
                stored_public_key_cose=stored.public_key_cose,
                stored_sign_count=stored.sign_count,
                client_data_json=credential["response"]["clientDataJSON"],
                authenticator_data=credential["response"]["authenticatorData"],
                signature=credential["response"]["signature"],
            )
        except Exception as e:
            logger.warning("authentication verification failed: %s", e)
            return _error("authentication verification failed")

        stored.sign_count = result.sign_count
        _config.credential_store.update(stored)

        resp = {"userId": stored.user_id, "authenticated": True}
        if stored.prf_supported:
            resp["prfSupported"] = True
        return JsonResponse(resp)
