# open-passkey-axum

Axum handlers for passkey (WebAuthn/FIDO2) authentication. Returns a configured `Router` with all registration and authentication endpoints.

## Install

```bash
cargo add open-passkey-axum
```

Or add to `Cargo.toml`:

```toml
[dependencies]
open-passkey-axum = "0.1.3"
```

## Usage

```rust
use open_passkey_axum::{
    passkey_router, PasskeyConfig, MemoryChallengeStore, MemoryCredentialStore,
};
use std::sync::Arc;

let config = PasskeyConfig {
    rp_id: "example.com".into(),
    rp_display_name: "Example".into(),
    origin: "https://example.com".into(),
    challenge_length: 32,
    challenge_timeout_seconds: 300,
    allow_multiple_credentials: false,
    session: None,
};

let challenges = Arc::new(MemoryChallengeStore::new());
let credentials = Arc::new(MemoryCredentialStore::new());
let app = passkey_router(config, challenges, credentials);

let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
axum::serve(listener, app).await.unwrap();
```

## Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/passkey/register/begin` | Start registration ceremony |
| POST | `/passkey/register/finish` | Complete registration |
| POST | `/passkey/login/begin` | Start authentication ceremony |
| POST | `/passkey/login/finish` | Complete authentication |
| GET | `/passkey/session` | Validate session (when enabled) |
| POST | `/passkey/logout` | Clear session (when enabled) |

## Pluggable Stores

Implement the `ChallengeStore` and `CredentialStore` traits for your database. In-memory defaults are provided for development.

```rust
pub trait ChallengeStore: Send + Sync {
    fn store(&self, key: &str, challenge: &str, timeout: Duration) -> Result<(), PasskeyError>;
    fn consume(&self, key: &str) -> Result<String, PasskeyError>;
}

pub trait CredentialStore: Send + Sync {
    fn store(&self, cred: StoredCredential) -> Result<(), PasskeyError>;
    fn get(&self, credential_id: &[u8]) -> Result<StoredCredential, PasskeyError>;
    fn get_by_user(&self, user_id: &str) -> Result<Vec<StoredCredential>, PasskeyError>;
    fn update(&self, cred: StoredCredential) -> Result<(), PasskeyError>;
    fn delete(&self, credential_id: &[u8]) -> Result<(), PasskeyError>;
}
```

## Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `rp_id` | -- | Relying party domain (required) |
| `rp_display_name` | -- | Display name shown to users |
| `origin` | -- | Expected origin URL (required) |
| `challenge_length` | 32 | Challenge byte length |
| `challenge_timeout_seconds` | 300 | Challenge expiry |
| `session` | `None` | Optional `SessionConfig` |

## Dependencies

- `axum` >= 0.7 (HTTP framework)
- `tokio` (async runtime)
- `open-passkey-core` (WebAuthn protocol verification)

## Test

```bash
cargo test
```

## Related Packages

- [core-rust](../core-rust) -- Core protocol library
- [sdk-js](../sdk-js) -- Browser SDK client

## License

MIT
