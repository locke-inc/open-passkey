"""ML-DSA-65-ES256 composite (hybrid PQ) signature verification."""

import struct

import cbor2

from .cose import COSE_ALG_COMPOSITE_MLDSA65_ES256, COSE_KTY_COMPOSITE
from .errors import SignatureInvalidError, UnsupportedAlgorithmError
from .es256 import verify_es256_signature_raw
from .mldsa65 import verify_mldsa65_raw

# ML-DSA-65 public key size (FIPS 204)
MLDSA_PUB_KEY_SIZE = 1952
# Uncompressed EC P-256 point: 0x04 || x(32) || y(32)
ECDSA_UNCOMPRESSED_SIZE = 65


def verify_composite_signature(
    cose_key_bytes: bytes,
    auth_data_raw: bytes,
    client_data_hash: bytes,
    sig_bytes: bytes,
) -> None:
    """Verify an ML-DSA-65-ES256 composite signature."""
    raw = cbor2.loads(cose_key_bytes)

    kty = raw.get(1)
    alg = raw.get(3)
    composite_key = raw.get(-1)

    if kty != COSE_KTY_COMPOSITE or alg != COSE_ALG_COMPOSITE_MLDSA65_ES256:
        raise UnsupportedAlgorithmError()

    composite_key_bytes = bytes(composite_key)
    expected_key_len = MLDSA_PUB_KEY_SIZE + ECDSA_UNCOMPRESSED_SIZE
    if len(composite_key_bytes) != expected_key_len:
        raise UnsupportedAlgorithmError(
            f"composite public key wrong length: got {len(composite_key_bytes)}, want {expected_key_len}"
        )

    # Split composite key
    mldsa_pub_key = composite_key_bytes[:MLDSA_PUB_KEY_SIZE]
    ecdsa_pub_point = composite_key_bytes[MLDSA_PUB_KEY_SIZE:]

    # Split composite signature: 4-byte big-endian ML-DSA sig length || ML-DSA sig || ES256 DER sig
    if len(sig_bytes) < 4:
        raise SignatureInvalidError()

    mldsa_sig_len = struct.unpack(">I", sig_bytes[:4])[0]

    if len(sig_bytes) < 4 + mldsa_sig_len:
        raise SignatureInvalidError()

    mldsa_sig = sig_bytes[4:4 + mldsa_sig_len]
    ecdsa_sig = sig_bytes[4 + mldsa_sig_len:]

    # Both components verify over the same data: authData || SHA256(clientDataJSON)
    verify_data = auth_data_raw + client_data_hash

    # ML-DSA-65: signs the message directly (no additional hashing)
    verify_mldsa65_raw(mldsa_pub_key, verify_data, mldsa_sig)

    # ES256: verify using the raw EC point extracted from the composite key
    verify_es256_signature_raw(ecdsa_pub_point, auth_data_raw, client_data_hash, ecdsa_sig)
