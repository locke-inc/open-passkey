# @open-passkey/remix

Remix action handlers for passkey (WebAuthn/FIDO2) authentication with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/remix
```

## Usage

```typescript
// app/lib/passkey.server.ts
import {
  createPasskeyActions,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/remix";

export const passkey = createPasskeyActions({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});
```

```typescript
// app/routes/passkey.register.begin.ts
import { passkey } from "~/lib/passkey.server";
export const action = passkey.registerBegin;
```

```typescript
// app/routes/passkey.register.finish.ts
import { passkey } from "~/lib/passkey.server";
export const action = passkey.registerFinish;
```

```typescript
// app/routes/passkey.login.begin.ts
import { passkey } from "~/lib/passkey.server";
export const action = passkey.loginBegin;
```

```typescript
// app/routes/passkey.login.finish.ts
import { passkey } from "~/lib/passkey.server";
export const action = passkey.loginFinish;
```

### With sessions

```typescript
export const passkey = createPasskeyActions({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
  session: {
    secret: "your-32+-character-hmac-secret-here",
    duration: 86400000,
  },
});
```

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK |
| [@open-passkey/react](https://www.npmjs.com/package/@open-passkey/react) | React hooks |
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Framework-agnostic server logic |

## License

MIT
