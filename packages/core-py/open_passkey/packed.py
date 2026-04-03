"""Packed attestation verification."""

import hashlib

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate

from .cose import COSE_ALG_ES256, COSE_KTY_EC2
from .errors import (
    SignatureInvalidError,
    UnsupportedAlgorithmError,
    InvalidAttestationStatementError,
)


def verify_packed_self_attestation(
    cose_key_bytes: bytes,
    auth_data_raw: bytes,
    client_data_json_raw: bytes,
    sig_bytes: bytes,
) -> None:
    """Verify packed self-attestation (no x5c): signature over authData || SHA256(clientDataJSON)."""
    raw = cbor2.loads(cose_key_bytes)
    kty = raw.get(1)
    alg = raw.get(3)

    if kty != COSE_KTY_EC2 or alg != COSE_ALG_ES256:
        raise UnsupportedAlgorithmError()

    x = raw.get(-2)
    y = raw.get(-3)

    uncompressed = b"\x04" + bytes(x) + bytes(y)
    pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), uncompressed
    )

    client_data_hash = hashlib.sha256(client_data_json_raw).digest()
    verify_data = auth_data_raw + client_data_hash

    try:
        pub_key.verify(bytes(sig_bytes), verify_data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SignatureInvalidError()


def verify_packed_full_attestation(
    att_stmt: dict,
    auth_data_raw: bytes,
    client_data_hash: bytes,
) -> None:
    """Verify packed full attestation (x5c present)."""
    x5c = att_stmt.get("x5c")
    if not x5c or len(x5c) == 0:
        raise InvalidAttestationStatementError("x5c is empty")

    cert_der = bytes(x5c[0])
    cert = load_der_x509_certificate(cert_der)
    pub_key = cert.public_key()

    verify_data = auth_data_raw + client_data_hash

    alg = att_stmt.get("alg")
    sig = att_stmt.get("sig")

    if alg == COSE_ALG_ES256:
        try:
            pub_key.verify(bytes(sig), verify_data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise SignatureInvalidError()
    else:
        raise UnsupportedAlgorithmError(f"attestation alg {alg}")
