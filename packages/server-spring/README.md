# server-spring

Spring Boot starter for passkey (WebAuthn/FIDO2) authentication. Auto-configures REST endpoints for registration and authentication ceremonies.

## Install

```xml
<dependency>
    <groupId>com.openpasskey</groupId>
    <artifactId>open-passkey-spring</artifactId>
    <version>0.1.3</version>
</dependency>
```

## Configuration

Add to `application.yml`:

```yaml
open-passkey:
  rp-id: example.com
  rp-display-name: Example
  origin: https://example.com
  # Optional session support (disabled by default)
  session-secret: "your-32-char-minimum-hmac-secret"
  session-duration-seconds: 86400
```

All properties are bound via `PasskeyProperties` under the `open-passkey` prefix.

## Routes

The auto-configured controller exposes these endpoints (default prefix `/passkey`):

| Method | Path | Description |
|--------|------|-------------|
| POST | `/passkey/register/begin` | Start registration ceremony |
| POST | `/passkey/register/finish` | Complete registration |
| POST | `/passkey/login/begin` | Start authentication ceremony |
| POST | `/passkey/login/finish` | Complete authentication |
| GET | `/passkey/session` | Validate session (when enabled) |
| POST | `/passkey/logout` | Clear session (when enabled) |

## Pluggable Stores

Implement `ChallengeStore` and `CredentialStore` interfaces and register them as Spring beans. In-memory defaults are provided for development.

```java
@Bean
public ChallengeStore challengeStore() {
    return new RedisChallengeStore(redisTemplate);
}

@Bean
public CredentialStore credentialStore() {
    return new JpaCredentialStore(credentialRepository);
}
```

## Configuration Properties

| Property | Default | Description |
|----------|---------|-------------|
| `open-passkey.rp-id` | -- | Relying party domain (required) |
| `open-passkey.rp-display-name` | -- | Display name shown to users |
| `open-passkey.origin` | -- | Expected origin URL (required) |
| `open-passkey.challenge-length` | 32 | Challenge byte length |
| `open-passkey.challenge-timeout-seconds` | 300 | Challenge expiry |
| `open-passkey.session-secret` | -- | HMAC secret (enables sessions) |
| `open-passkey.session-duration-seconds` | 86400 | Session TTL |

## Dependencies

- `spring-boot-starter-web`
- `core-java` (WebAuthn protocol verification)

## Test

```bash
mvn test
```

## Related Packages

- [core-java](../core-java) -- Core protocol library
- [sdk-js](../sdk-js) -- Browser SDK client

## License

MIT
