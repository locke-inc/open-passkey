# open-passkey

Core WebAuthn/FIDO2 protocol verification for Python. No HTTP, no sessions, no framework dependencies -- pure cryptographic verification of registration and authentication ceremonies.

## Install

```bash
pip install open-passkey
```

For post-quantum algorithm support (ML-DSA-65, ML-DSA-65-ES256 composite):

```bash
pip install open-passkey[pq]
```

This installs `liboqs-python`, which requires the `liboqs` C library on your system.

## Usage

```python
from open_passkey import verify_registration, verify_authentication

# Registration ceremony
result = verify_registration(
    rp_id="example.com",
    expected_challenge="<base64url>",
    expected_origin="https://example.com",
    client_data_json="<base64url>",
    attestation_object="<base64url>",
)
print(result.credential_id, result.public_key_cose)

# Authentication ceremony
result = verify_authentication(
    rp_id="example.com",
    expected_challenge="<base64url>",
    expected_origin="https://example.com",
    stored_public_key_cose="<base64url>",
    stored_sign_count=0,
    client_data_json="<base64url>",
    authenticator_data="<base64url>",
    signature="<base64url>",
)
print(result.sign_count)
```

All binary inputs and outputs are base64url-encoded strings (no padding).

## API

**Functions**

- `verify_registration(rp_id, expected_challenge, expected_origin, client_data_json, attestation_object, require_user_verification=False) -> RegistrationResult`
- `verify_authentication(rp_id, expected_challenge, expected_origin, stored_public_key_cose, stored_sign_count, client_data_json, authenticator_data, signature, require_user_verification=False) -> AuthenticationResult`

**Dataclasses**

- `RegistrationResult` -- `credential_id`, `public_key_cose`, `sign_count`, `rp_id_hash`, `flags`, `backup_eligible`, `backup_state`, `attestation_format`
- `AuthenticationResult` -- `sign_count`, `flags`, `backup_eligible`, `backup_state`

**Errors** (all subclass `WebAuthnError`)

`ChallengeMismatchError`, `OriginMismatchError`, `RPIDMismatchError`, `SignatureInvalidError`, `UnsupportedAlgorithmError`, `UnsupportedAttestationFormatError`, `InvalidAttestationStatementError`, `SignCountRollbackError`, `UserPresenceRequiredError`, `UserVerificationRequiredError`, `InvalidBackupStateError`

## Algorithms

| Algorithm | COSE alg | Notes |
|-----------|----------|-------|
| ES256 (ECDSA P-256) | -7 | Classical, all browsers |
| ML-DSA-65 | -49 | Post-quantum (FIPS 204), requires liboqs |
| ML-DSA-65-ES256 composite | -52 | Hybrid PQ, requires liboqs |

## Attestation

Supports `none` and `packed` (self-attestation and full x5c chain).

## Dependencies

- `cryptography>=41.0`
- `cbor2>=5.4`
- Optional: `liboqs-python>=0.14` (for ML-DSA-65; requires `liboqs` C library)

## Testing

```bash
pytest tests/
```

## Related Packages

- `open-passkey-server` -- framework-agnostic server logic built on this library
- `open-passkey-flask`, `open-passkey-fastapi`, `open-passkey-django` -- framework bindings
- `@open-passkey/sdk` (npm) -- browser SDK

## License

MIT
