"""Base64url encoding/decoding utilities (no padding)."""

import base64


def base64url_decode(s: str) -> bytes:
    """Decode a base64url-encoded string (no padding) to bytes."""
    # Add padding
    padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 != 0 else s
    # Convert base64url to base64
    b64 = padded.replace("-", "+").replace("_", "/")
    return base64.b64decode(b64)


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
