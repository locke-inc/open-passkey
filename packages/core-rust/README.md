# open-passkey-core

Core WebAuthn/FIDO2 protocol verification library for Rust. Handles attestation parsing, signature verification, and client data validation with post-quantum algorithm support.

## Install

```bash
cargo add open-passkey-core
```

Or add to `Cargo.toml`:

```toml
[dependencies]
open-passkey-core = "0.1.3"
```

## Usage

### Registration

```rust
use open_passkey_core::{verify_registration, RegistrationInput};

let input = RegistrationInput {
    attestation_object: attestation_object_b64url,
    client_data_json: client_data_json_b64url,
    expected_challenge: challenge_b64url,
    expected_origin: "https://example.com".into(),
    rp_id: "example.com".into(),
    require_user_verification: true,
};

let result = verify_registration(input)?;
// result.credential_id, result.public_key_cose, result.sign_count
```

### Authentication

```rust
use open_passkey_core::{verify_authentication, AuthenticationInput};

let input = AuthenticationInput {
    authenticator_data: auth_data_b64url,
    client_data_json: client_data_json_b64url,
    signature: signature_b64url,
    expected_challenge: challenge_b64url,
    expected_origin: "https://example.com".into(),
    rp_id: "example.com".into(),
    stored_public_key_cose: stored_key_b64url,
    stored_sign_count: 0,
    require_user_verification: true,
};

let result = verify_authentication(input)?;
// result.sign_count, result.backup_eligible, result.backup_state
```

### Error Handling

Both functions return `Result<_, WebAuthnError>`. Each variant carries a machine-readable code:

```rust
use open_passkey_core::WebAuthnError;

match verify_registration(input) {
    Ok(result) => { /* success */ }
    Err(WebAuthnError::SignatureInvalid) => { /* bad sig */ }
    Err(WebAuthnError::RpIdMismatch) => { /* wrong RP */ }
    Err(e) => println!("{}", e.code()), // e.g. "challenge_mismatch"
}
```

## Algorithms

| Algorithm | COSE alg | Notes |
|-----------|----------|-------|
| ES256 (ECDSA P-256) | -7 | Classical, all browsers |
| ML-DSA-65 | -49 | Post-quantum, FIPS 204 |
| ML-DSA-65-ES256 | -52 | Composite hybrid PQ |

## Attestation Formats

- `none` -- no attestation
- `packed` -- self-attestation and full x5c chain

## Dependencies

- `p256` + `ecdsa` (ES256 verification)
- `fips204` (ML-DSA-65)
- `ciborium` (CBOR decoding)
- `sha2` (SHA-256 hashing)

## Test

```bash
cargo test
```

## Related Packages

- [server-axum](../server-axum) -- Axum integration using this library

## License

MIT
