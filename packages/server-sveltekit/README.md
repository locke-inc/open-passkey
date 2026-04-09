# @open-passkey/sveltekit

SvelteKit passkey (WebAuthn/FIDO2) authentication endpoint handlers with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/sveltekit
```

## Usage

```typescript
// src/lib/server/passkey.ts
import {
  createPasskeyHandlers,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/sveltekit";

export const passkey = createPasskeyHandlers({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});
```

```typescript
// src/routes/passkey/register/begin/+server.ts
import { passkey } from "$lib/server/passkey";
export const POST = passkey.registerBegin;
```

```typescript
// src/routes/passkey/register/finish/+server.ts
import { passkey } from "$lib/server/passkey";
export const POST = passkey.registerFinish;
```

```typescript
// src/routes/passkey/login/begin/+server.ts
import { passkey } from "$lib/server/passkey";
export const POST = passkey.loginBegin;
```

```typescript
// src/routes/passkey/login/finish/+server.ts
import { passkey } from "$lib/server/passkey";
export const POST = passkey.loginFinish;
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
| [@open-passkey/svelte](https://www.npmjs.com/package/@open-passkey/svelte) | Svelte stores |
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Framework-agnostic server logic |

## License

MIT
