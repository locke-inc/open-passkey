"""Authenticator data parsing and RP ID hash verification."""

import hashlib
import hmac
import struct
from dataclasses import dataclass

from .errors import RPIDMismatchError

MIN_AUTH_DATA_LEN = 37


@dataclass
class ParsedAuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes | None = None
    credential_key: bytes | None = None


def parse_authenticator_data(auth_data: bytes, expect_cred_data: bool) -> ParsedAuthData:
    """Parse authenticator data bytes."""
    if len(auth_data) < MIN_AUTH_DATA_LEN:
        raise ValueError("authenticator_data_too_short")

    rp_id_hash = auth_data[0:32]
    flags = auth_data[32]
    sign_count = struct.unpack(">I", auth_data[33:37])[0]

    result = ParsedAuthData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
    )

    if expect_cred_data:
        has_attested = (flags & 0x40) != 0
        if not has_attested:
            raise ValueError("no_attested_credential_data")

        if len(auth_data) < 55:
            raise ValueError("authenticator_data_too_short")

        offset = 37
        # AAGUID: 16 bytes
        offset += 16
        # Credential ID length: 2 bytes big-endian
        cred_id_len = struct.unpack(">H", auth_data[offset:offset + 2])[0]
        offset += 2

        if len(auth_data) < offset + cred_id_len:
            raise ValueError("authenticator_data_too_short")

        result.credential_id = auth_data[offset:offset + cred_id_len]
        offset += cred_id_len
        result.credential_key = auth_data[offset:]

    return result


def verify_rp_id_hash(auth_data_rp_id_hash: bytes, rp_id: str) -> None:
    """Verify that the RP ID hash matches SHA-256(rpId)."""
    expected = hashlib.sha256(rp_id.encode("utf-8")).digest()
    if not hmac.compare_digest(auth_data_rp_id_hash, expected):
        raise RPIDMismatchError()
