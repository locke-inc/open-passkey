"""ML-DSA-65 (FIPS 204 / Dilithium3) signature verification."""

import cbor2

from .cose import COSE_ALG_MLDSA65, COSE_KTY_MLDSA
from .errors import SignatureInvalidError, UnsupportedAlgorithmError

# ML-DSA-65 public key size (FIPS 204)
MLDSA_PUB_KEY_SIZE = 1952


def _get_oqs():
    """Import oqs lazily so missing lib raises clear error."""
    try:
        import oqs
        return oqs
    except ImportError:
        raise ImportError(
            "ML-DSA-65 verification requires liboqs-python. "
            "Install with: pip install liboqs-python"
        )


def verify_mldsa65_signature(
    cose_key_bytes: bytes,
    auth_data_raw: bytes,
    client_data_hash: bytes,
    sig_bytes: bytes,
) -> None:
    """Verify an ML-DSA-65 signature using a COSE key."""
    raw = cbor2.loads(cose_key_bytes)

    kty = raw.get(1)
    alg = raw.get(3)
    pub = raw.get(-1)

    if kty != COSE_KTY_MLDSA or alg != COSE_ALG_MLDSA65:
        raise UnsupportedAlgorithmError()

    pub_bytes = bytes(pub)
    if len(pub_bytes) != MLDSA_PUB_KEY_SIZE:
        raise UnsupportedAlgorithmError(
            f"ML-DSA-65 public key wrong length: got {len(pub_bytes)}, want {MLDSA_PUB_KEY_SIZE}"
        )

    verify_data = auth_data_raw + client_data_hash

    oqs = _get_oqs()
    verifier = oqs.Signature("ML-DSA-65")
    valid = verifier.verify(verify_data, bytes(sig_bytes), pub_bytes)

    if not valid:
        raise SignatureInvalidError()


def verify_mldsa65_raw(
    pub_key_bytes: bytes,
    message: bytes,
    sig_bytes: bytes,
) -> None:
    """Verify an ML-DSA-65 signature given raw public key bytes."""
    oqs = _get_oqs()
    verifier = oqs.Signature("ML-DSA-65")
    valid = verifier.verify(message, sig_bytes, pub_key_bytes)

    if not valid:
        raise SignatureInvalidError()
