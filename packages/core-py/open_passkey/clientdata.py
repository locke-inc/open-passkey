"""Client data verification."""

import json

from .base64url import base64url_decode
from .errors import (
    TypeMismatchError,
    ChallengeMismatchError,
    OriginMismatchError,
    TokenBindingUnsupportedError,
)


def verify_client_data(
    client_data_json_b64: str,
    expected_type: str,
    expected_challenge: str,
    expected_origin: str,
) -> bytes:
    """Decode and verify clientDataJSON. Returns the raw bytes."""
    raw = base64url_decode(client_data_json_b64)
    cd = json.loads(raw.decode("utf-8"))

    if cd.get("type") != expected_type:
        raise TypeMismatchError()
    if cd.get("challenge") != expected_challenge:
        raise ChallengeMismatchError()
    if cd.get("origin") != expected_origin:
        raise OriginMismatchError()

    token_binding = cd.get("tokenBinding")
    if token_binding and token_binding.get("status") == "present":
        raise TokenBindingUnsupportedError()

    return raw
