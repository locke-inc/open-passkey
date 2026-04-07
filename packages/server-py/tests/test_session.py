import time
import hmac
import hashlib
import base64
import pytest
from open_passkey_server.session import (
    SessionConfig,
    SessionTokenData,
    validate_session_config,
    create_session_token,
    validate_session_token,
    build_set_cookie_header,
    build_clear_cookie_header,
    parse_cookie_token,
)

SECRET = "a]Vv3X!kP9#mW2$nQ7@rT5&jY0^uL8*dF"


def make_config(**kwargs):
    return SessionConfig(secret=SECRET, **kwargs)


# Token Logic
def test_create_token_format():
    token = create_session_token("user123", make_config())
    parts = token.rsplit(":", 2)
    assert len(parts) == 3  # userId may have colons, so rsplit with maxsplit
    # actually need to split from right properly
    last_colon = token.rfind(":")
    second_last = token.rfind(":", 0, last_colon)
    assert second_last > 0
    expires_str = token[second_last + 1:last_colon]
    assert int(expires_str) > int(time.time() * 1000)


def test_validate_fresh_token():
    token = create_session_token("user123", make_config())
    data = validate_session_token(token, make_config())
    assert data.user_id == "user123"
    assert data.expires_at > int(time.time() * 1000)


def test_reject_tampered_user_id():
    token = create_session_token("user123", make_config())
    tampered = token.replace("user123", "evil", 1)
    with pytest.raises(ValueError):
        validate_session_token(tampered, make_config())


def test_reject_tampered_expires():
    token = create_session_token("user123", make_config())
    last_colon = token.rfind(":")
    second_last = token.rfind(":", 0, last_colon)
    tampered = token[:second_last + 1] + "9999999999999" + token[last_colon:]
    with pytest.raises(ValueError):
        validate_session_token(tampered, make_config())


def test_reject_tampered_signature():
    token = create_session_token("user123", make_config())
    tampered = token[:-1] + ("b" if token[-1] == "a" else "a")
    with pytest.raises(ValueError):
        validate_session_token(tampered, make_config())


def test_reject_expired_token():
    config = make_config(duration_seconds=0, clock_skew_grace_seconds=0)
    # duration_seconds=0 means expires immediately
    token = create_session_token("user123", config)
    time.sleep(0.01)
    with pytest.raises(ValueError, match="session expired"):
        validate_session_token(token, config)


def test_reject_wrong_secret():
    token = create_session_token("user123", make_config())
    other = make_config(secret="z" * 32 + "ab")
    with pytest.raises(ValueError):
        validate_session_token(token, other)


def test_reject_malformed_token():
    config = make_config()
    with pytest.raises(ValueError):
        validate_session_token("", config)
    with pytest.raises(ValueError):
        validate_session_token("nocolons", config)
    with pytest.raises(ValueError):
        validate_session_token("one:colon", config)


def test_user_id_with_colons():
    token = create_session_token("urn:user:123", make_config())
    data = validate_session_token(token, make_config())
    assert data.user_id == "urn:user:123"


def test_clock_skew_grace_accepts_within():
    # Create token that expires in 1ms, with 10s grace
    config = make_config(duration_seconds=0, clock_skew_grace_seconds=10)
    token = create_session_token("user123", config)
    time.sleep(0.01)
    data = validate_session_token(token, config)
    assert data.user_id == "user123"


def test_clock_skew_grace_rejects_beyond():
    # Manually create a token expired 15s ago
    expires_at = int(time.time() * 1000) - 15_000
    payload = f"user123:{expires_at}"
    sig = base64.urlsafe_b64encode(
        hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    token = f"{payload}:{sig}"
    config = make_config(clock_skew_grace_seconds=10)
    with pytest.raises(ValueError, match="session expired"):
        validate_session_token(token, config)


# Cookie helpers
def test_build_set_cookie_header_defaults():
    header = build_set_cookie_header("tok", make_config())
    assert "op_session=tok" in header
    assert "HttpOnly" in header
    assert "Path=/" in header
    assert "Max-Age=86400" in header
    assert "SameSite=Lax" in header
    assert "Secure" in header


def test_build_set_cookie_header_secure_false():
    header = build_set_cookie_header("tok", make_config(secure=False))
    assert "Secure" not in header


def test_build_set_cookie_header_with_domain():
    header = build_set_cookie_header("tok", make_config(domain="example.com"))
    assert "Domain=example.com" in header


def test_build_clear_cookie_header():
    header = build_clear_cookie_header(make_config())
    assert "Max-Age=0" in header
    assert "op_session=" in header


def test_parse_cookie_token_found():
    assert parse_cookie_token("op_session=abc123", make_config()) == "abc123"


def test_parse_cookie_token_not_found():
    assert parse_cookie_token("other=x", make_config()) is None


def test_parse_cookie_token_empty():
    assert parse_cookie_token(None, make_config()) is None
    assert parse_cookie_token("", make_config()) is None


# Config
def test_reject_short_secret():
    with pytest.raises(ValueError):
        validate_session_config(SessionConfig(secret="short"))
