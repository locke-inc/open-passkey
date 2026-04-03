"""Base64url encoding/decoding helpers."""

from base64 import urlsafe_b64decode, urlsafe_b64encode


def b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return urlsafe_b64decode(s)
