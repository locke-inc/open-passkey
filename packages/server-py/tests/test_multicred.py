import pytest
from open_passkey_server.config import PasskeyConfig
from open_passkey_server.handlers import PasskeyHandler
from open_passkey_server.stores import (
    MemoryChallengeStore,
    MemoryCredentialStore,
    PasskeyError,
    StoredCredential,
)


def make_handler(**kwargs):
    return PasskeyHandler(
        PasskeyConfig(
            rp_id="example.com",
            rp_display_name="Example",
            origin="https://example.com",
            **kwargs,
        )
    )


def fake_cred(user_id: str, cred_id: int = 1) -> StoredCredential:
    return StoredCredential(
        credential_id=bytes([cred_id]),
        public_key_cose=bytes([0]),
        sign_count=0,
        user_id=user_id,
    )


def test_409_when_user_has_credentials_default():
    store = MemoryCredentialStore()
    store.store(fake_cred("user-1"))
    handler = make_handler(credential_store=store)

    with pytest.raises(PasskeyError, match="user already registered") as exc_info:
        handler.begin_registration("user-1", "alice")
    assert exc_info.value.status_code == 409


def test_succeeds_with_allow_multiple_credentials():
    store = MemoryCredentialStore()
    store.store(fake_cred("user-1"))
    handler = make_handler(credential_store=store, allow_multiple_credentials=True)

    resp = handler.begin_registration("user-1", "alice")
    assert "challenge" in resp


def test_exclude_credentials_present_for_existing_user():
    store = MemoryCredentialStore()
    store.store(fake_cred("user-1", 1))
    store.store(fake_cred("user-1", 2))
    handler = make_handler(credential_store=store, allow_multiple_credentials=True)

    resp = handler.begin_registration("user-1", "alice")
    assert "excludeCredentials" in resp
    assert len(resp["excludeCredentials"]) == 2
    assert resp["excludeCredentials"][0]["type"] == "public-key"
    assert resp["excludeCredentials"][1]["type"] == "public-key"


def test_exclude_credentials_absent_for_new_user():
    handler = make_handler()
    resp = handler.begin_registration("new-user", "bob")
    assert "excludeCredentials" not in resp
