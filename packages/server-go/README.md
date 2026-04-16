# server-go

HTTP handlers for passkey authentication in Go. Uses stdlib `net/http` -- no framework dependencies. Pluggable challenge and credential stores, optional stateless session cookies.

Wraps [core-go](../core-go) for all WebAuthn verification.

## Install

```bash
go get github.com/open-passkey/server-go
```

## Quick Start

```go
import "github.com/open-passkey/server-go/passkey"

p, err := passkey.New(passkey.Config{
    RPID:            "example.com",
    RPDisplayName:   "Example",
    Origin:          "https://example.com",
    ChallengeStore:  passkey.NewMemoryChallengeStore(),
    CredentialStore: passkey.NewMemoryCredentialStore(),
    Session: &passkey.SessionConfig{ // optional
        Secret:   "your-secret-at-least-32-characters-long",
        Duration: 24 * time.Hour,
    },
})
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("/passkey/", http.StripPrefix("/passkey", p.Handler()))
http.ListenAndServe(":8080", mux)
```

When `Session` is set, finish handlers set an `HttpOnly` cookie automatically and two extra routes are registered (`GET /session`, `POST /logout`). Omit `Session` for bring-your-own session management.

## Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/register/begin` | Generate challenge + credential creation options |
| POST | `/register/finish` | Verify registration response, store credential |
| POST | `/login/begin` | Generate challenge + credential request options |
| POST | `/login/finish` | Verify authentication response |
| GET | `/session` | Validate session cookie (requires session config) |
| POST | `/logout` | Clear session cookie (requires session config) |

## API

| Function / Method | Description |
|-------------------|-------------|
| `New(config Config) (*Passkey, error)` | Create a Passkey instance, validates config |
| `(*Passkey).Handler() http.Handler` | Returns an `http.Handler` with all routes |
| `(*Passkey).BeginRegistration(w, r)` | `http.HandlerFunc` for registration start |
| `(*Passkey).FinishRegistration(w, r)` | `http.HandlerFunc` for registration finish |
| `(*Passkey).BeginAuthentication(w, r)` | `http.HandlerFunc` for authentication start |
| `(*Passkey).FinishAuthentication(w, r)` | `http.HandlerFunc` for authentication finish |
| `(*Passkey).GetSession(w, r)` | `http.HandlerFunc` for session validation |
| `(*Passkey).Logout(w, r)` | `http.HandlerFunc` for session logout |

### Config

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `RPID` | `string` | yes | -- | Bare domain (e.g. `"example.com"`) |
| `RPDisplayName` | `string` | no | -- | Human-readable RP name |
| `Origin` | `string` | yes | -- | Full origin with scheme (e.g. `"https://example.com"`) |
| `ChallengeStore` | `ChallengeStore` | yes | -- | Challenge persistence backend |
| `CredentialStore` | `CredentialStore` | yes | -- | Credential persistence backend |
| `Session` | `*SessionConfig` | no | `nil` | Enables stateless HMAC-SHA256 session cookies |

### Store Interfaces

```go
type ChallengeStore interface {
    Store(key, challenge string, timeout time.Duration) error
    Consume(key string) (string, error)
}

type CredentialStore interface {
    Store(cred StoredCredential) error
    Get(credentialID []byte) (StoredCredential, error)
    GetByUser(userID string) ([]StoredCredential, error)
    Update(cred StoredCredential) error
    Delete(credentialID []byte) error
}
```

Built-in for dev/testing: `NewMemoryChallengeStore()` and `NewMemoryCredentialStore()` (in-memory, thread-safe).

### SessionConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Secret` | `string` | -- | HMAC key, 32+ characters (required) |
| `Duration` | `time.Duration` | `24h` | Session lifetime |
| `CookieName` | `string` | `"op_session"` | Cookie name |
| `Secure` | `*bool` | `true` | Set `Secure` flag on cookie |
| `SameSite` | `string` | `"Lax"` | `SameSite` cookie attribute |

## Test

```bash
go test ./... -v
```

## Related Packages

| Package | Description |
|---------|-------------|
| [core-go](../core-go) | Core WebAuthn verification (ES256, ML-DSA-65, ML-DSA-65-ES256) |
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK for passkey ceremonies |

## License

MIT
