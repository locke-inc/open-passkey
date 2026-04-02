"""ES256 (ECDSA P-256 with SHA-256) signature verification."""

import hashlib

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

from .cose import COSE_ALG_ES256, COSE_KTY_EC2
from .errors import SignatureInvalidError, UnsupportedAlgorithmError


def verify_es256_signature(
    cose_key_bytes: bytes,
    auth_data_raw: bytes,
    client_data_hash: bytes,
    sig_bytes: bytes,
) -> None:
    """Verify an ES256 signature using a COSE key."""
    raw = cbor2.loads(cose_key_bytes)

    kty = raw.get(1)
    alg = raw.get(3)
    x = raw.get(-2)
    y = raw.get(-3)

    if kty != COSE_KTY_EC2 or alg != COSE_ALG_ES256:
        raise UnsupportedAlgorithmError()

    # Build uncompressed EC point: 0x04 || x || y
    uncompressed = b"\x04" + bytes(x) + bytes(y)

    pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), uncompressed
    )

    verify_data = auth_data_raw + client_data_hash

    try:
        pub_key.verify(bytes(sig_bytes), verify_data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SignatureInvalidError()


def verify_es256_signature_raw(
    ec_point_bytes: bytes,
    auth_data_raw: bytes,
    client_data_hash: bytes,
    sig_bytes: bytes,
) -> None:
    """Verify an ES256 signature given raw uncompressed EC point bytes (65 bytes)."""
    pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ec_point_bytes
    )

    verify_data = auth_data_raw + client_data_hash

    try:
        pub_key.verify(bytes(sig_bytes), verify_data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SignatureInvalidError()
