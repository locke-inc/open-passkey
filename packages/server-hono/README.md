# @open-passkey/hono

Hono passkey (WebAuthn/FIDO2) authentication middleware with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/hono
```

## Usage

```typescript
import { Hono } from "hono";
import {
  createPasskeyApp,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/hono";

const app = new Hono();

const passkey = createPasskeyApp({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});

app.route("/passkey", passkey);

export default app;
```

## Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/register/begin` | Start registration ceremony |
| POST | `/register/finish` | Complete registration |
| POST | `/login/begin` | Start authentication ceremony |
| POST | `/login/finish` | Complete authentication |

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK |
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Framework-agnostic server logic |

## License

MIT
