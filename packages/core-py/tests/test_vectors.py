"""Spec vector tests for core-py WebAuthn verification."""

import json
import os

import pytest

from open_passkey import verify_registration, verify_authentication, WebAuthnError

VECTOR_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "spec", "vectors")


def load_vectors(filename):
    with open(os.path.join(VECTOR_DIR, filename)) as f:
        return json.load(f)["vectors"]


# --- Registration vectors ---

@pytest.mark.parametrize("vector", load_vectors("registration.json"), ids=lambda v: v["name"])
def test_registration(vector):
    inp = vector["input"]
    credential = inp["credential"]
    response = credential["response"]

    if vector["expected"]["success"]:
        result = verify_registration(
            rp_id=inp["rpId"],
            expected_challenge=inp["expectedChallenge"],
            expected_origin=inp["expectedOrigin"],
            client_data_json=response["clientDataJSON"],
            attestation_object=response["attestationObject"],
        )

        expected = vector["expected"]
        if "credentialId" in expected:
            assert result.credential_id == expected["credentialId"]
        if "publicKeyCose" in expected:
            assert result.public_key_cose == expected["publicKeyCose"]
        if "signCount" in expected:
            assert result.sign_count == expected["signCount"]
        if "rpIdHash" in expected:
            assert result.rp_id_hash == expected["rpIdHash"]
    else:
        with pytest.raises(WebAuthnError) as exc_info:
            verify_registration(
                rp_id=inp["rpId"],
                expected_challenge=inp["expectedChallenge"],
                expected_origin=inp["expectedOrigin"],
                client_data_json=response["clientDataJSON"],
                attestation_object=response["attestationObject"],
            )
        assert exc_info.value.code == vector["expected"]["error"]


# --- Authentication vectors ---

@pytest.mark.parametrize("vector", load_vectors("authentication.json"), ids=lambda v: v["name"])
def test_authentication(vector):
    inp = vector["input"]
    credential = inp["credential"]
    response = credential["response"]

    if vector["expected"]["success"]:
        result = verify_authentication(
            rp_id=inp["rpId"],
            expected_challenge=inp["expectedChallenge"],
            expected_origin=inp["expectedOrigin"],
            stored_public_key_cose=inp["storedPublicKeyCose"],
            stored_sign_count=inp["storedSignCount"],
            client_data_json=response["clientDataJSON"],
            authenticator_data=response["authenticatorData"],
            signature=response["signature"],
        )

        if "signCount" in vector["expected"]:
            assert result.sign_count == vector["expected"]["signCount"]
    else:
        with pytest.raises(WebAuthnError) as exc_info:
            verify_authentication(
                rp_id=inp["rpId"],
                expected_challenge=inp["expectedChallenge"],
                expected_origin=inp["expectedOrigin"],
                stored_public_key_cose=inp["storedPublicKeyCose"],
                stored_sign_count=inp["storedSignCount"],
                client_data_json=response["clientDataJSON"],
                authenticator_data=response["authenticatorData"],
                signature=response["signature"],
            )
        assert exc_info.value.code == vector["expected"]["error"]


# --- Hybrid ML-DSA-65-ES256 authentication vectors ---

@pytest.mark.parametrize("vector", load_vectors("hybrid_authentication.json"), ids=lambda v: v["name"])
def test_hybrid_authentication(vector):
    inp = vector["input"]
    credential = inp["credential"]
    response = credential["response"]

    if vector["expected"]["success"]:
        result = verify_authentication(
            rp_id=inp["rpId"],
            expected_challenge=inp["expectedChallenge"],
            expected_origin=inp["expectedOrigin"],
            stored_public_key_cose=inp["storedPublicKeyCose"],
            stored_sign_count=inp["storedSignCount"],
            client_data_json=response["clientDataJSON"],
            authenticator_data=response["authenticatorData"],
            signature=response["signature"],
        )

        if "signCount" in vector["expected"]:
            assert result.sign_count == vector["expected"]["signCount"]
    else:
        with pytest.raises(WebAuthnError) as exc_info:
            verify_authentication(
                rp_id=inp["rpId"],
                expected_challenge=inp["expectedChallenge"],
                expected_origin=inp["expectedOrigin"],
                stored_public_key_cose=inp["storedPublicKeyCose"],
                stored_sign_count=inp["storedSignCount"],
                client_data_json=response["clientDataJSON"],
                authenticator_data=response["authenticatorData"],
                signature=response["signature"],
            )
        assert exc_info.value.code == vector["expected"]["error"]
