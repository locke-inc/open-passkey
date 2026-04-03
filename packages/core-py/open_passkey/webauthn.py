"""Main WebAuthn verification functions."""

import hashlib
from dataclasses import dataclass

import cbor2

from .base64url import base64url_decode, base64url_encode
from .clientdata import verify_client_data
from .authdata import parse_authenticator_data, verify_rp_id_hash
from .cose import COSE_ALG_ES256, COSE_ALG_MLDSA65, COSE_ALG_COMPOSITE_MLDSA65_ES256
from .es256 import verify_es256_signature
from .mldsa65 import verify_mldsa65_signature
from .composite import verify_composite_signature
from .packed import verify_packed_self_attestation, verify_packed_full_attestation
from .errors import (
    UserPresenceRequiredError,
    UserVerificationRequiredError,
    InvalidBackupStateError,
    UnsupportedAttestationFormatError,
    InvalidAttestationStatementError,
    UnsupportedAlgorithmError,
    SignCountRollbackError,
)


@dataclass
class RegistrationResult:
    credential_id: str  # base64url
    public_key_cose: str  # base64url
    sign_count: int
    rp_id_hash: str  # base64url
    flags: int
    backup_eligible: bool
    backup_state: bool
    attestation_format: str


@dataclass
class AuthenticationResult:
    sign_count: int
    flags: int
    backup_eligible: bool
    backup_state: bool


def verify_registration(
    rp_id: str,
    expected_challenge: str,
    expected_origin: str,
    client_data_json: str,
    attestation_object: str,
    require_user_verification: bool = False,
) -> RegistrationResult:
    """Verify a WebAuthn registration ceremony.

    All binary inputs are base64url-encoded strings (no padding).
    """
    # Verify client data
    client_data_json_raw = verify_client_data(
        client_data_json, "webauthn.create", expected_challenge, expected_origin
    )

    # Decode CBOR attestation object
    att_obj_bytes = base64url_decode(attestation_object)
    att_obj = cbor2.loads(att_obj_bytes)

    fmt = att_obj.get("fmt", att_obj.get(b"fmt", ""))
    auth_data = att_obj.get("authData", att_obj.get(b"authData", b""))
    att_stmt_raw = att_obj.get("attStmt", att_obj.get(b"attStmt", {}))

    # Ensure fmt is a string
    if isinstance(fmt, bytes):
        fmt = fmt.decode("utf-8")

    # Ensure auth_data is bytes
    auth_data = bytes(auth_data)

    att_stmt = None
    if fmt == "none":
        pass
    elif fmt == "packed":
        # Normalize att_stmt keys
        normalized = {}
        for k, v in att_stmt_raw.items():
            key = k.decode("utf-8") if isinstance(k, bytes) else k
            normalized[key] = v

        alg = normalized.get("alg")
        sig = normalized.get("sig")
        if alg is None or sig is None:
            raise InvalidAttestationStatementError("missing alg or sig")
        att_stmt = {
            "alg": alg,
            "sig": sig,
        }
        x5c = normalized.get("x5c")
        if x5c is not None:
            att_stmt["x5c"] = x5c
    else:
        raise UnsupportedAttestationFormatError(fmt)

    # Parse authenticator data
    parsed = parse_authenticator_data(auth_data, True)

    # Verify RP ID hash
    verify_rp_id_hash(parsed.rp_id_hash, rp_id)

    # Verify UP flag
    if (parsed.flags & 0x01) == 0:
        raise UserPresenceRequiredError()

    # Verify UV flag if required
    if require_user_verification and (parsed.flags & 0x04) == 0:
        raise UserVerificationRequiredError()

    # BS must be 0 if BE is 0
    if (parsed.flags & 0x08) == 0 and (parsed.flags & 0x10) != 0:
        raise InvalidBackupStateError()

    # Verify packed attestation
    if fmt == "packed" and att_stmt is not None:
        client_data_hash = hashlib.sha256(client_data_json_raw).digest()
        x5c = att_stmt.get("x5c")
        if x5c and len(x5c) > 0:
            verify_packed_full_attestation(att_stmt, auth_data, client_data_hash)
        else:
            verify_packed_self_attestation(
                parsed.credential_key, auth_data, client_data_json_raw, bytes(att_stmt["sig"])
            )

    return RegistrationResult(
        credential_id=base64url_encode(parsed.credential_id),
        public_key_cose=base64url_encode(parsed.credential_key),
        sign_count=parsed.sign_count,
        rp_id_hash=base64url_encode(parsed.rp_id_hash),
        flags=parsed.flags,
        backup_eligible=(parsed.flags & 0x08) != 0,
        backup_state=(parsed.flags & 0x10) != 0,
        attestation_format=fmt,
    )


def verify_authentication(
    rp_id: str,
    expected_challenge: str,
    expected_origin: str,
    stored_public_key_cose: str,
    stored_sign_count: int,
    client_data_json: str,
    authenticator_data: str,
    signature: str,
    require_user_verification: bool = False,
) -> AuthenticationResult:
    """Verify a WebAuthn authentication ceremony.

    All binary inputs are base64url-encoded strings (no padding).
    """
    # Verify client data
    client_data_json_raw = verify_client_data(
        client_data_json, "webauthn.get", expected_challenge, expected_origin
    )

    # Decode authenticator data
    auth_data_raw = base64url_decode(authenticator_data)
    parsed = parse_authenticator_data(auth_data_raw, False)

    # Verify RP ID hash
    verify_rp_id_hash(parsed.rp_id_hash, rp_id)

    # Verify UP flag
    if (parsed.flags & 0x01) == 0:
        raise UserPresenceRequiredError()

    # Verify UV flag if required
    if require_user_verification and (parsed.flags & 0x04) == 0:
        raise UserVerificationRequiredError()

    # BS must be 0 if BE is 0
    if (parsed.flags & 0x08) == 0 and (parsed.flags & 0x10) != 0:
        raise InvalidBackupStateError()

    client_data_hash = hashlib.sha256(client_data_json_raw).digest()
    sig_bytes = base64url_decode(signature)

    # Decode stored public key to determine algorithm
    stored_key_bytes = base64url_decode(stored_public_key_cose)
    cose_key = cbor2.loads(stored_key_bytes)
    alg = cose_key.get(3)

    if alg == COSE_ALG_ES256:
        verify_es256_signature(stored_key_bytes, auth_data_raw, client_data_hash, sig_bytes)
    elif alg == COSE_ALG_MLDSA65:
        verify_mldsa65_signature(stored_key_bytes, auth_data_raw, client_data_hash, sig_bytes)
    elif alg == COSE_ALG_COMPOSITE_MLDSA65_ES256:
        verify_composite_signature(stored_key_bytes, auth_data_raw, client_data_hash, sig_bytes)
    else:
        raise UnsupportedAlgorithmError()

    # Sign count rollback detection
    if stored_sign_count > 0 and parsed.sign_count <= stored_sign_count:
        raise SignCountRollbackError()

    return AuthenticationResult(
        sign_count=parsed.sign_count,
        flags=parsed.flags,
        backup_eligible=(parsed.flags & 0x08) != 0,
        backup_state=(parsed.flags & 0x10) != 0,
    )
