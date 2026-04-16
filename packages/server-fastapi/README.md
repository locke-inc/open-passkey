# open-passkey-fastapi

FastAPI router for passkey (WebAuthn/FIDO2) authentication. Thin wrapper around `open-passkey-server` -- registers async routes with Pydantic request validation.

## Install

```bash
pip install open-passkey-fastapi
```

## Quick Start

```python
from fastapi import FastAPI
from open_passkey_fastapi import (
    create_passkey_router,
    PasskeyConfig,
    MemoryChallengeStore,
    MemoryCredentialStore,
)

app = FastAPI()

passkey_router = create_passkey_router(PasskeyConfig(
    rp_id="localhost",
    rp_display_name="My App",
    origin="http://localhost:8000",
    challenge_store=MemoryChallengeStore(),
    credential_store=MemoryCredentialStore(),
))

app.include_router(passkey_router, prefix="/passkey")
```

## With Sessions

```python
from open_passkey_server.session import SessionConfig

passkey_router = create_passkey_router(PasskeyConfig(
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

`create_passkey_router(config: PasskeyConfig) -> APIRouter`

Returns a FastAPI `APIRouter` with the routes above. All route handlers are async. Request bodies are validated with Pydantic models.

## Dependencies

- `fastapi>=0.110`
- `pydantic>=2.0`
- `open-passkey-server`

## Related Packages

- `open-passkey` -- core WebAuthn verification
- `open-passkey-server` -- shared server logic
- `open-passkey-flask`, `open-passkey-django` -- alternative framework bindings
- `@open-passkey/sdk` (npm) -- browser SDK

## License

MIT
