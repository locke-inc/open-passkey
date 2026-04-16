# open-passkey-flask

Flask blueprint for passkey (WebAuthn/FIDO2) authentication. Thin wrapper around `open-passkey-server` -- registers routes, parses requests, returns JSON responses.

## Install

```bash
pip install open-passkey-flask
```

## Quick Start

```python
from flask import Flask
from open_passkey_flask import (
    create_passkey_blueprint,
    PasskeyConfig,
    MemoryChallengeStore,
    MemoryCredentialStore,
)

app = Flask(__name__)

passkey_bp = create_passkey_blueprint(PasskeyConfig(
    rp_id="localhost",
    rp_display_name="My App",
    origin="http://localhost:5000",
    challenge_store=MemoryChallengeStore(),
    credential_store=MemoryCredentialStore(),
))

app.register_blueprint(passkey_bp, url_prefix="/passkey")
```

## With Sessions

```python
from open_passkey_server.session import SessionConfig

passkey_bp = create_passkey_blueprint(PasskeyConfig(
    rp_id="example.com",
    rp_display_name="Example",
    origin="https://example.com",
    session=SessionConfig(secret="your-32+-character-hmac-secret"),
))
```

When `session` is configured, two additional routes are registered and login/register responses set an HttpOnly session cookie automatically.

## Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/register/begin` | Start registration ceremony |
| POST | `/register/finish` | Complete registration |
| POST | `/login/begin` | Start authentication ceremony |
| POST | `/login/finish` | Complete authentication |
| GET | `/session` | Validate session cookie (session config required) |
| POST | `/logout` | Clear session cookie (session config required) |

## API

`create_passkey_blueprint(config: PasskeyConfig) -> Blueprint`

Returns a Flask `Blueprint` with the routes above. Mount it at any URL prefix.

## Dependencies

- `flask>=3.0`
- `open-passkey-server`

## Related Packages

- `open-passkey` -- core WebAuthn verification
- `open-passkey-server` -- shared server logic
- `open-passkey-fastapi`, `open-passkey-django` -- alternative framework bindings
- `@open-passkey/sdk` (npm) -- browser SDK

## License

MIT
