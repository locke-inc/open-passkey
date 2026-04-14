# @open-passkey/sdk

Framework-agnostic browser SDK for passkey (WebAuthn/FIDO2) authentication with post-quantum cryptography support.

This is the canonical browser-side client. It handles base64url encoding, `navigator.credentials` calls, PRF extension handling, and HTTP communication with your passkey server. All frontend framework packages (React, Vue, Svelte, Solid, Angular) wrap this SDK.

## Install

```bash
npm install @open-passkey/sdk
```

## Quick Start

You can add passkeys to your app **without running your own backend**. [Locke Gateway](https://gateway.locke.id) is a free hosted passkey server -- just point the SDK at it with your domain:

```typescript
import { PasskeyClient } from "@open-passkey/sdk";

const passkey = new PasskeyClient({
  provider: "locke-gateway",
  rpId: "example.com", // your domain
});
```

### Self-hosted

If you're running your own passkey server (e.g., with `@open-passkey/express` or `@open-passkey/nextjs`), point to it directly:

```typescript
import { PasskeyClient } from "@open-passkey/sdk";

const passkey = new PasskeyClient({ baseUrl: "/passkey" });
```

### Register a passkey

```typescript
const result = await passkey.register("user-id-123", "alice@example.com");
// { credentialId, registered, prfSupported }
```

### Authenticate

```typescript
// With a known user
const result = await passkey.authenticate("user-id-123");
// { userId, authenticated, prfSupported }

// Discoverable (usernameless)
const result = await passkey.authenticate();
```

### Sessions

```typescript
// Check current session (reads HttpOnly cookie)
const session = await passkey.getSession();
// { userId, authenticated } or null

// Logout (clears session cookie)
await passkey.logout();
```

### Script tag (IIFE bundle)

For server-rendered apps without a JS bundler:

```html
<script src="https://unpkg.com/@open-passkey/sdk/dist/open-passkey.iife.js"></script>
<script>
  const passkey = new OpenPasskey.PasskeyClient({ baseUrl: "/passkey" });
</script>
```

## API

| Method | Returns | Description |
|--------|---------|-------------|
| `register(userId, username)` | `Promise<RegistrationResult>` | Create a new passkey |
| `authenticate(userId?)` | `Promise<AuthenticationResult>` | Sign in with a passkey |
| `getSession()` | `Promise<AuthenticationResult \| null>` | Validate current session |
| `logout()` | `Promise<void>` | Clear session cookie |
| `vault()` | `Vault` | Get E2E encrypted vault (requires PRF-capable authenticator) |

### Vault (E2E Encrypted Key-Value Store)

After authenticating with a PRF-capable authenticator, you can use the vault for client-side encrypted storage. The encryption key is derived from the WebAuthn PRF output — the server only ever sees ciphertext.

```typescript
const result = await passkey.authenticate("user-id-123");
const vault = passkey.vault();

await vault.setItem("api-key", "sk_live_abc123");
const val = await vault.getItem("api-key");       // "sk_live_abc123"
await vault.removeItem("api-key");
const allKeys = await vault.keys();                // string[]
```

| Method | Returns | Description |
|--------|---------|-------------|
| `setItem(key, value)` | `Promise<void>` | Encrypt and store a value |
| `getItem(key)` | `Promise<string \| null>` | Retrieve and decrypt a value (null if not found) |
| `removeItem(key)` | `Promise<void>` | Delete a stored item |
| `keys()` | `Promise<string[]>` | List all stored keys |

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/react](https://www.npmjs.com/package/@open-passkey/react) | React hooks |
| [@open-passkey/vue](https://www.npmjs.com/package/@open-passkey/vue) | Vue 3 composables |
| [@open-passkey/svelte](https://www.npmjs.com/package/@open-passkey/svelte) | Svelte stores |
| [@open-passkey/solid](https://www.npmjs.com/package/@open-passkey/solid) | SolidJS primitives |
| [@open-passkey/angular](https://www.npmjs.com/package/@open-passkey/angular) | Angular components + service |
| [@open-passkey/express](https://www.npmjs.com/package/@open-passkey/express) | Express server |
| [@open-passkey/nextjs](https://www.npmjs.com/package/@open-passkey/nextjs) | Next.js server |

## License

MIT
