# @open-passkey/nextjs

Next.js App Router passkey (WebAuthn/FIDO2) authentication handlers with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/nextjs
```

## Usage

```typescript
// lib/passkey.ts
import {
  createPasskeyHandlers,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/nextjs";

export const passkey = createPasskeyHandlers({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});
```

```typescript
// app/api/passkey/register/begin/route.ts
import { passkey } from "@/lib/passkey";
export const POST = passkey.registerBegin;
```

```typescript
// app/api/passkey/register/finish/route.ts
import { passkey } from "@/lib/passkey";
export const POST = passkey.registerFinish;
```

```typescript
// app/api/passkey/login/begin/route.ts
import { passkey } from "@/lib/passkey";
export const POST = passkey.loginBegin;
```

```typescript
// app/api/passkey/login/finish/route.ts
import { passkey } from "@/lib/passkey";
export const POST = passkey.loginFinish;
```

```typescript
// app/api/passkey/session/route.ts
import { passkey } from "@/lib/passkey";
export const GET = passkey.session;
```

```typescript
// app/api/passkey/logout/route.ts
import { passkey } from "@/lib/passkey";
export const POST = passkey.logout;
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
| [@open-passkey/react](https://www.npmjs.com/package/@open-passkey/react) | React hooks |
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Framework-agnostic server logic |

## License

MIT
