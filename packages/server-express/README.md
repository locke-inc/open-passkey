# @open-passkey/express

Express.js passkey (WebAuthn/FIDO2) authentication middleware with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/express
```

## Usage

```typescript
import express from "express";
import {
  createPasskeyRouter,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/express";

const app = express();
app.use(express.json());

app.use("/passkey", createPasskeyRouter({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
}));

app.listen(3000);
```

### With sessions

```typescript
app.use("/passkey", createPasskeyRouter({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
  session: {
    secret: "your-32+-character-hmac-secret-here",
    duration: 86400000,
  },
}));
```

## Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/register/begin` | Start registration ceremony |
| POST | `/register/finish` | Complete registration |
| POST | `/login/begin` | Start authentication ceremony |
| POST | `/login/finish` | Complete authentication |
| GET | `/session` | Validate session (when sessions enabled) |
| POST | `/logout` | Clear session (when sessions enabled) |

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK |
| [@open-passkey/react](https://www.npmjs.com/package/@open-passkey/react) | React hooks |
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Framework-agnostic server logic |

## License

MIT
