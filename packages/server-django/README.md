# open-passkey-django

Django views for passkey (WebAuthn/FIDO2) authentication. Thin wrapper around `open-passkey-server` -- class-based views with CSRF exemption for JSON API endpoints.

## Install

```bash
pip install open-passkey-django
```

## Quick Start

In your settings:

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "open_passkey_django",
]
```

Configure and include the URL patterns:

```python
# urls.py
from django.urls import path, include
from open_passkey_django.views import configure
from open_passkey_server import MemoryChallengeStore, MemoryCredentialStore

configure(
    rp_id="localhost",
    rp_display_name="My App",
    origin="http://localhost:8000",
    challenge_store=MemoryChallengeStore(),
    credential_store=MemoryCredentialStore(),
)

urlpatterns = [
    path("passkey/", include("open_passkey_django.urls")),
]
```

## With Sessions

```python
from open_passkey_server.session import SessionConfig

configure(
    rp_id="example.com",
    rp_display_name="Example",
    origin="https://example.com",
    challenge_store=MemoryChallengeStore(),
    credential_store=MemoryCredentialStore(),
    session=SessionConfig(secret="your-32+-character-hmac-secret"),
)
```

When `session` is configured, the session and logout endpoints become active and login/register responses set an HttpOnly session cookie automatically.

## Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `register/begin` | Start registration ceremony |
| POST | `register/finish` | Complete registration |
| POST | `login/begin` | Start authentication ceremony |
| POST | `login/finish` | Complete authentication |
| GET | `session` | Validate session cookie (session config required) |
| POST | `logout` | Clear session cookie (session config required) |

## API

- `configure(rp_id, rp_display_name, origin, challenge_store, credential_store, ...)` -- must be called before URL inclusion
- URL patterns are defined in `open_passkey_django.urls` and use class-based views: `BeginRegistrationView`, `FinishRegistrationView`, `BeginAuthenticationView`, `FinishAuthenticationView`, `GetSessionView`, `LogoutView`

## Dependencies

- `django>=4.2`
- `open-passkey-server`

## Related Packages

- `open-passkey` -- core WebAuthn verification
- `open-passkey-server` -- shared server logic
- `open-passkey-flask`, `open-passkey-fastapi` -- alternative framework bindings
- `@open-passkey/sdk` (npm) -- browser SDK

## License

MIT
