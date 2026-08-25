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

## Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `register/begin` | Start registration ceremony |
| POST | `register/finish` | Complete registration |
| POST | `login/begin` | Start authentication ceremony |
| POST | `login/finish` | Complete authentication |

## API

- `configure(rp_id, rp_display_name, origin, challenge_store, credential_store, ...)` -- must be called before URL inclusion
- URL patterns are defined in `open_passkey_django.urls` and use class-based views for the four registration/authentication ceremony endpoints.

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
