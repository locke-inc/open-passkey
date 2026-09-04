"""Discoverable finishAuthentication with the explicit challenge field."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from open_passkey_server.base64url import b64url_encode
from open_passkey_server.config import PasskeyConfig
from open_passkey_server.handlers import PasskeyHandler
from open_passkey_server.stores import (
    MemoryChallengeStore,
    MemoryCredentialStore,
    PasskeyError,
    StoredCredential,
)


def make_handler():
    cs = MemoryChallengeStore()
    creds = MemoryCredentialStore()
    handler = PasskeyHandler(
        PasskeyConfig(
            rp_id="example.com",
            rp_display_name="Example",
            origin="https://example.com",
            challenge_store=cs,
            credential_store=creds,
        )
    )
    creds.store(
        StoredCredential(
            credential_id=bytes([1]),
            public_key_cose=bytes([0]),
            sign_count=0,
            user_id="alice",
        )
    )
    return handler, cs


def fake_credential():
    return {
        "id": b64url_encode(bytes([1])),
        "rawId": b64url_encode(bytes([1])),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(b"clientData"),
            "authenticatorData": b64url_encode(b"authData"),
            "signature": b64url_encode(b"sig"),
        },
    }


def test_explicit_challenge_no_user_id_succeeds():
    handler, cs = make_handler()
    cs.store("ch-abc", "ch-abc", 300.0)
    with patch(
        "open_passkey_server.handlers.verify_authentication",
        return_value=SimpleNamespace(sign_count=1),
    ) as mocked:
        resp = handler.finish_authentication("", fake_credential(), "ch-abc")
    assert resp["authenticated"] is True
    assert resp["userId"] == "alice"
    assert mocked.call_count == 1
    assert mocked.call_args.kwargs["expected_challenge"] == "ch-abc"


def test_unknown_challenge_key_400s():
    handler, _ = make_handler()
    with pytest.raises(PasskeyError, match="challenge not found or expired") as exc_info:
        handler.finish_authentication("", fake_credential(), "no-such-challenge")
    assert exc_info.value.status_code == 400


def test_missing_key_400s():
    handler, _ = make_handler()
    with pytest.raises(PasskeyError, match="challenge not found or expired") as exc_info:
        handler.finish_authentication("", fake_credential(), "")
    assert exc_info.value.status_code == 400


def test_old_style_challenge_as_user_id_still_works():
    handler, cs = make_handler()
    cs.store("ch-abc", "ch-abc", 300.0)
    with patch(
        "open_passkey_server.handlers.verify_authentication",
        return_value=SimpleNamespace(sign_count=1),
    ):
        resp = handler.finish_authentication("ch-abc", fake_credential())
    assert resp["authenticated"] is True
    assert resp["userId"] == "alice"


def test_userhandle_mismatch_still_rejected():
    handler, cs = make_handler()
    cs.store("ch-abc", "ch-abc", 300.0)
    cred = fake_credential()
    cred["response"]["userHandle"] = b64url_encode(b"bob")
    with pytest.raises(PasskeyError, match="userHandle does not match credential owner"):
        handler.finish_authentication("", cred, "ch-abc")
