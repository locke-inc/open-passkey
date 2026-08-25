# open-passkey-server

Framework-agnostic server logic for passkey authentication. Handles challenge generation, credential storage, and ceremony orchestration. Session establishment belongs to the host application.

## Install

```bash
pip install open-passkey-server
```

## Usage

```python
from open_passkey_server import PasskeyConfig, PasskeyHandler
from open_passkey_server import MemoryChallengeStore, MemoryCredentialStore

config = PasskeyConfig(
    rp_id="example.com",
    rp_display_name="Example",
    origin="https://example.com",
    challenge_store=MemoryChallengeStore(),
    credential_store=MemoryCredentialStore(),
)

handler = PasskeyHandler(config)

# Registration
options = handler.begin_registration(user_id="user_123", username="alice")
# ... client performs navigator.credentials.create() ...
result = handler.finish_registration(user_id="user_123", credential={...})

# Authentication
options = handler.begin_authentication(user_id="user_123")
# ... client performs navigator.credentials.get() ...
result = handler.finish_authentication(user_id="user_123", credential={...})
```

## API

**PasskeyHandler(config: PasskeyConfig)** -- main class with four methods:

- `begin_registration(user_id, username) -> dict` -- returns WebAuthn creation options
- `finish_registration(user_id, credential, prf_supported=False) -> dict` -- verifies and stores credential
- `begin_authentication(user_id="") -> dict` -- returns WebAuthn request options (discoverable if no user_id)
- `finish_authentication(user_id, credential) -> dict` -- verifies assertion, updates sign count

**PasskeyConfig** -- dataclass:

- `rp_id` -- relying party domain (e.g. `"example.com"`)
- `rp_display_name` -- human-readable RP name
- `origin` -- expected origin (e.g. `"https://example.com"`)
- `challenge_store` -- implements `ChallengeStore` (default: `MemoryChallengeStore`)
- `credential_store` -- implements `CredentialStore` (default: `MemoryCredentialStore`)

**Store Protocols**

- `ChallengeStore` (ABC) -- `store(key, challenge, timeout_seconds)`, `consume(key) -> str`
- `CredentialStore` (ABC) -- `store(cred)`, `get(credential_id)`, `get_by_user(user_id)`, `update(cred)`, `delete(credential_id)`

Built-in implementations: `MemoryChallengeStore`, `MemoryCredentialStore` (thread-safe, in-memory, for development).

## Dependencies

- `open-passkey` (core verification)

## Testing

```bash
pytest tests/
```

## Related Packages

- `open-passkey` -- core WebAuthn verification (no HTTP)
- `open-passkey-flask`, `open-passkey-fastapi`, `open-passkey-django` -- framework bindings
- `@open-passkey/sdk` (npm) -- browser SDK

## License

MIT
