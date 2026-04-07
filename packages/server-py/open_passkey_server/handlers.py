"""Framework-agnostic WebAuthn ceremony handlers that return plain dicts."""

import json
import logging
import secrets

from open_passkey import verify_authentication, verify_registration

from .base64url import b64url_decode, b64url_encode
from .config import PasskeyConfig
from .session import create_session_token, validate_session_token, SessionTokenData
from .stores import PasskeyError, StoredCredential

logger = logging.getLogger(__name__)


class PasskeyHandler:
    """Encapsulates all WebAuthn business logic. Returns plain dicts."""

    def __init__(self, config: PasskeyConfig):
        self.config = config

    def begin_registration(self, user_id: str, username: str) -> dict:
        if not user_id or not username:
            raise PasskeyError("userId and username are required")

        challenge_bytes = secrets.token_bytes(self.config.challenge_length)
        challenge = b64url_encode(challenge_bytes)

        prf_salt = secrets.token_bytes(32)
        challenge_data = json.dumps({"challenge": challenge, "prfSalt": b64url_encode(prf_salt)})
        self.config.challenge_store.store(user_id, challenge_data, self.config.challenge_timeout_seconds)

        return {
            "challenge": challenge,
            "rp": {"id": self.config.rp_id, "name": self.config.rp_display_name},
            "user": {
                "id": b64url_encode(user_id.encode()),
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
            "timeout": int(self.config.challenge_timeout_seconds * 1000),
            "attestation": "none",
            "extensions": {
                "prf": {"eval": {"first": b64url_encode(prf_salt)}},
            },
        }

    def finish_registration(self, user_id: str, credential: dict, prf_supported: bool = False) -> dict:
        challenge_data = json.loads(self.config.challenge_store.consume(user_id))

        try:
            result = verify_registration(
                rp_id=self.config.rp_id,
                expected_challenge=challenge_data["challenge"],
                expected_origin=self.config.origin,
                client_data_json=credential["response"]["clientDataJSON"],
                attestation_object=credential["response"]["attestationObject"],
            )
        except Exception as e:
            logger.warning("registration verification failed: %s", e)
            raise PasskeyError("registration verification failed")

        cred = StoredCredential(
            credential_id=b64url_decode(result.credential_id),
            public_key_cose=b64url_decode(result.public_key_cose),
            sign_count=result.sign_count,
            user_id=user_id,
        )
        if prf_supported:
            cred.prf_salt = b64url_decode(challenge_data["prfSalt"])
            cred.prf_supported = True

        self.config.credential_store.store(cred)

        return {
            "credentialId": result.credential_id,
            "registered": True,
            "prfSupported": bool(prf_supported),
        }

    def begin_authentication(self, user_id: str = "") -> dict:
        challenge_bytes = secrets.token_bytes(self.config.challenge_length)
        challenge = b64url_encode(challenge_bytes)

        challenge_key = user_id if user_id else challenge
        self.config.challenge_store.store(challenge_key, challenge, self.config.challenge_timeout_seconds)

        options: dict = {
            "challenge": challenge,
            "rpId": self.config.rp_id,
            "timeout": int(self.config.challenge_timeout_seconds * 1000),
            "userVerification": "preferred",
        }

        if user_id:
            allow_credentials = []
            eval_by_credential = {}
            has_prf = False
            try:
                creds = self.config.credential_store.get_by_user(user_id)
                for c in creds:
                    cred_id_encoded = b64url_encode(c.credential_id)
                    allow_credentials.append({"type": "public-key", "id": cred_id_encoded})
                    if c.prf_supported and c.prf_salt:
                        eval_by_credential[cred_id_encoded] = {"first": b64url_encode(c.prf_salt)}
                        has_prf = True
            except PasskeyError:
                pass
            options["allowCredentials"] = allow_credentials
            if has_prf:
                options["extensions"] = {"prf": {"evalByCredential": eval_by_credential}}

        return options

    def finish_authentication(self, user_id: str, credential: dict) -> dict:
        challenge = self.config.challenge_store.consume(user_id)

        cred_id_bytes = b64url_decode(credential["id"])
        stored = self.config.credential_store.get(cred_id_bytes)

        user_handle = credential.get("response", {}).get("userHandle", "")
        if user_handle:
            if b64url_decode(user_handle).decode() != stored.user_id:
                raise PasskeyError("userHandle does not match credential owner")

        try:
            result = verify_authentication(
                rp_id=self.config.rp_id,
                expected_challenge=challenge,
                expected_origin=self.config.origin,
                stored_public_key_cose=b64url_encode(stored.public_key_cose),
                stored_sign_count=stored.sign_count,
                client_data_json=credential["response"]["clientDataJSON"],
                authenticator_data=credential["response"]["authenticatorData"],
                signature=credential["response"]["signature"],
            )
        except PasskeyError:
            raise
        except Exception as e:
            logger.warning("authentication verification failed: %s", e)
            raise PasskeyError("authentication verification failed")

        stored.sign_count = result.sign_count
        self.config.credential_store.update(stored)

        resp: dict = {"userId": stored.user_id, "authenticated": True}
        if stored.prf_supported:
            resp["prfSupported"] = True
        if self.config.session is not None:
            resp["sessionToken"] = create_session_token(stored.user_id, self.config.session)
        return resp

    def get_session_token_data(self, token: str) -> SessionTokenData:
        """Validate a session token and return internal SessionTokenData."""
        if self.config.session is None:
            raise PasskeyError("session is not configured")
        return validate_session_token(token, self.config.session)
