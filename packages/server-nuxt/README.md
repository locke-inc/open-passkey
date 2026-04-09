# @open-passkey/nuxt

Nuxt 3 (Nitro) passkey (WebAuthn/FIDO2) authentication event handlers with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/nuxt
```

## Usage

```typescript
// server/utils/passkey.ts
import {
  createPasskeyHandlers,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/nuxt";

export const passkey = createPasskeyHandlers({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});
```

```typescript
// server/api/passkey/register/begin.post.ts
import { passkey } from "~/server/utils/passkey";
export default defineEventHandler(passkey.registerBegin);
```

```typescript
// server/api/passkey/register/finish.post.ts
import { passkey } from "~/server/utils/passkey";
export default defineEventHandler(passkey.registerFinish);
```

```typescript
// server/api/passkey/login/begin.post.ts
import { passkey } from "~/server/utils/passkey";
export default defineEventHandler(passkey.loginBegin);
```

```typescript
// server/api/passkey/login/finish.post.ts
import { passkey } from "~/server/utils/passkey";
export default defineEventHandler(passkey.loginFinish);
```

### With sessions

```typescript
export const passkey = createPasskeyHandlers({
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
| [@open-passkey/vue](https://www.npmjs.com/package/@open-passkey/vue) | Vue 3 composables |
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Framework-agnostic server logic |

## License

MIT
