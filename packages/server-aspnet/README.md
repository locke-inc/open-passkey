# OpenPasskey.AspNet

ASP.NET Core middleware for passkey (WebAuthn/FIDO2) authentication. Maps minimal API endpoints for registration and authentication ceremonies.

## Install

```bash
dotnet add package OpenPasskey.AspNet
```

## Usage

```csharp
using OpenPasskey.AspNet;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapPasskeyEndpoints(new PasskeyConfig
{
    RpId = "example.com",
    RpDisplayName = "Example",
    Origin = "https://example.com",
    // Optional: enable stateless sessions
    Session = new SessionConfig
    {
        Secret = "your-32-char-minimum-hmac-secret",
        DurationSeconds = 86400
    }
});

app.Run();
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

Implement `IChallengeStore` and `ICredentialStore` for your database. In-memory defaults (`MemoryChallengeStore`, `MemoryCredentialStore`) are provided for development.

```csharp
app.MapPasskeyEndpoints(new PasskeyConfig
{
    RpId = "example.com",
    Origin = "https://example.com",
    ChallengeStore = new RedisChallengeStore(redis),
    CredentialStore = new EfCredentialStore(dbContext)
});
```

## Configuration

| Property | Default | Description |
|----------|---------|-------------|
| `RpId` | -- | Relying party domain (required) |
| `RpDisplayName` | -- | Display name shown to users |
| `Origin` | -- | Expected origin URL (required) |
| `ChallengeStore` | `MemoryChallengeStore` | Challenge persistence |
| `CredentialStore` | `MemoryCredentialStore` | Credential persistence |
| `Session` | `null` | Session config (disabled by default) |

## Dependencies

- OpenPasskey.Core (WebAuthn protocol verification)
- Microsoft.AspNetCore.App framework reference

## Test

```bash
dotnet test
```

## Related Packages

- [core-dotnet](../core-dotnet) -- Core protocol library
- [sdk-js](../sdk-js) -- Browser SDK client

## License

MIT
