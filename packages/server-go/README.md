# server-go

HTTP handlers for passkey authentication in Go. Uses stdlib `net/http` with pluggable challenge and credential stores. Session lifecycle is intentionally outside this package.

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
    OnAuthenticated: passkey.AuthenticationSuccessFunc(func(ctx context.Context, result passkey.AuthenticationResult) error {
        // Pass result.Principal to your session layer here.
        return nil
    }),
})
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("/passkey/", http.StripPrefix("/passkey", p.Handler()))
http.ListenAndServe(":8080", mux)
```

`FinishAuthentication` emits `AuthenticationResult` through `OnAuthenticated`; `FinishRegistration` can emit `RegistrationResult` through `OnRegistered`. Neither handler creates a session or sets a cookie.

## Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/register/begin` | Generate challenge + credential creation options |
| POST | `/register/finish` | Verify registration response, store credential |
| POST | `/login/begin` | Generate challenge + credential request options |
| POST | `/login/finish` | Verify authentication response |

## API

| Function / Method | Description |
|-------------------|-------------|
| `New(config Config) (*Passkey, error)` | Create a Passkey instance, validates config |
| `(*Passkey).Handler() http.Handler` | Returns an `http.Handler` with all routes |
| `(*Passkey).BeginRegistration(w, r)` | `http.HandlerFunc` for registration start |
| `(*Passkey).FinishRegistration(w, r)` | `http.HandlerFunc` for registration finish |
| `(*Passkey).BeginAuthentication(w, r)` | `http.HandlerFunc` for authentication start |
| `(*Passkey).FinishAuthentication(w, r)` | `http.HandlerFunc` for authentication finish |

### Config

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `RPID` | `string` | yes | -- | Bare domain (e.g. `"example.com"`) |
| `RPDisplayName` | `string` | no | -- | Human-readable RP name |
| `Origin` | `string` | yes | -- | Full origin with scheme (e.g. `"https://example.com"`) |
| `ChallengeStore` | `ChallengeStore` | yes | -- | Challenge persistence backend |
| `CredentialStore` | `CredentialStore` | yes | -- | Credential persistence backend |
| `OnAuthenticated` | `AuthenticationSuccessHandler` | no | `nil` | Receives a verified principal |
| `OnRegistered` | `RegistrationSuccessHandler` | no | `nil` | Receives a newly registered principal |

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
