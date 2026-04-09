# @open-passkey/nestjs

NestJS passkey (WebAuthn/FIDO2) authentication module with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/nestjs
```

## Usage

```typescript
import { Module } from "@nestjs/common";
import {
  PasskeyModule,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/nestjs";

@Module({
  imports: [
    PasskeyModule.register({
      rpId: "example.com",
      rpName: "My App",
      origin: "https://example.com",
      challengeStore: new MemoryChallengeStore(),
      credentialStore: new MemoryCredentialStore(),
    }),
  ],
})
export class AppModule {}
```

### With sessions

```typescript
PasskeyModule.register({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
  session: {
    secret: "your-32+-character-hmac-secret-here",
    duration: 86400000,
  },
})
```

## Routes

The module registers the following routes via `PasskeyController`:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/register/begin` | Start registration ceremony |
| POST | `/register/finish` | Complete registration |
| POST | `/login/begin` | Start authentication ceremony |
| POST | `/login/finish` | Complete authentication |
| GET | `/session` | Validate session (when sessions enabled) |
| POST | `/logout` | Clear session (when sessions enabled) |

## Exports

- `PasskeyModule` -- NestJS dynamic module
- `PasskeyController` -- route controller
- `PasskeyService` -- injectable service wrapping `Passkey`

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK |
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Framework-agnostic server logic |

## License

MIT
