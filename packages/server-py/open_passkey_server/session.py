"""Stateless HMAC-SHA256 session tokens with cookie helpers."""

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass, field

CLOCK_SKEW_GRACE_SECONDS = 10
MIN_SECRET_LENGTH = 32
DEFAULT_DURATION_SECONDS = 86400  # 24h
DEFAULT_COOKIE_NAME = "op_session"


@dataclass
class SessionConfig:
    secret: str
    duration_seconds: int = DEFAULT_DURATION_SECONDS
    clock_skew_grace_seconds: int = CLOCK_SKEW_GRACE_SECONDS
    cookie_name: str = DEFAULT_COOKIE_NAME
    cookie_path: str = "/"
    secure: bool = True
    same_site: str = "Lax"
    domain: str | None = None


@dataclass
class SessionTokenData:
    """Internal only — never serialized to HTTP responses."""
    user_id: str
    expires_at: int  # unix ms


def validate_session_config(config: SessionConfig) -> None:
    if len(config.secret) < MIN_SECRET_LENGTH:
        raise ValueError(f"session secret must be at least {MIN_SECRET_LENGTH} characters")


def _sign(payload: str, secret: str) -> str:
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def create_session_token(user_id: str, config: SessionConfig) -> str:
    expires_at = int(time.time() * 1000) + config.duration_seconds * 1000
    payload = f"{user_id}:{expires_at}"
    signature = _sign(payload, config.secret)
    return f"{payload}:{signature}"


def validate_session_token(token: str, config: SessionConfig) -> SessionTokenData:
    # Split from right — userId may contain colons
    last_colon = token.rfind(":")
    if last_colon == -1:
        raise ValueError("invalid session token")

    second_last_colon = token.rfind(":", 0, last_colon)
    if second_last_colon == -1:
        raise ValueError("invalid session token")

    user_id = token[:second_last_colon]
    expires_at_str = token[second_last_colon + 1:last_colon]
    provided_sig = token[last_colon + 1:]

    if not user_id or not expires_at_str or not provided_sig:
        raise ValueError("invalid session token")

    try:
        expires_at = int(expires_at_str)
    except ValueError:
        raise ValueError("invalid session token")

    # Timing-safe comparison
    payload = f"{user_id}:{expires_at_str}"
    expected_sig = _sign(payload, config.secret)

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise ValueError("invalid session token")

    # Expiry check with clock skew grace
    now_ms = int(time.time() * 1000)
    grace_ms = config.clock_skew_grace_seconds * 1000
    if now_ms > expires_at + grace_ms:
        raise ValueError("session expired")

    return SessionTokenData(user_id=user_id, expires_at=expires_at)


def build_set_cookie_header(token: str, config: SessionConfig) -> str:
    parts = [
        f"{config.cookie_name}={token}",
        "HttpOnly",
        f"Path={config.cookie_path}",
        f"Max-Age={config.duration_seconds}",
        f"SameSite={config.same_site}",
    ]
    if config.secure:
        parts.append("Secure")
    if config.domain:
        parts.append(f"Domain={config.domain}")
    return "; ".join(parts)


def build_clear_cookie_header(config: SessionConfig) -> str:
    parts = [
        f"{config.cookie_name}=",
        "HttpOnly",
        f"Path={config.cookie_path}",
        "Max-Age=0",
        f"SameSite={config.same_site}",
    ]
    if config.secure:
        parts.append("Secure")
    if config.domain:
        parts.append(f"Domain={config.domain}")
    return "; ".join(parts)


def parse_cookie_token(cookie_header: str | None, config: SessionConfig) -> str | None:
    if not cookie_header:
        return None
    prefix = f"{config.cookie_name}="
    for cookie in cookie_header.split(";"):
        trimmed = cookie.strip()
        if trimmed.startswith(prefix):
            value = trimmed[len(prefix):]
            return value or None
    return None
