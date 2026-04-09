# @open-passkey/astro

Astro API route handlers for passkey (WebAuthn/FIDO2) authentication with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/astro
```

## Usage

```typescript
// src/lib/passkey.ts
import {
  createPasskeyEndpoints,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/astro";

export const passkey = createPasskeyEndpoints({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});
```

```typescript
// src/pages/api/passkey/register/begin.ts
import { passkey } from "@/lib/passkey";
export const POST = passkey.registerBegin;
```

```typescript
// src/pages/api/passkey/register/finish.ts
import { passkey } from "@/lib/passkey";
export const POST = passkey.registerFinish;
```

```typescript
// src/pages/api/passkey/login/begin.ts
import { passkey } from "@/lib/passkey";
export const POST = passkey.loginBegin;
```

```typescript
// src/pages/api/passkey/login/finish.ts
import { passkey } from "@/lib/passkey";
export const POST = passkey.loginFinish;
```

### With sessions

```typescript
export const passkey = createPasskeyEndpoints({
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
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Framework-agnostic server logic |

## License

MIT
