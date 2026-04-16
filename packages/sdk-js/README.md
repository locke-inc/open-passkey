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
| `persistKey()` | `Promise<void>` | Save encryption key to IndexedDB (survives page reload) |
| `Vault.restore(baseUrl)` | `Promise<Vault \| null>` | Restore a vault from a previously persisted key |
| `Vault.clear()` | `Promise<void>` | Remove persisted key from IndexedDB |

#### Server contract

The Vault class expects four endpoints on your server, all requiring session authentication:

| Method | Path | Request Body | Success Response |
|--------|------|-------------|-----------------|
| PUT | `{baseUrl}/vault/{key}` | `{ "value": "<base64url>" }` | 204 No Content |
| GET | `{baseUrl}/vault/{key}` | -- | `{ "value": "<base64url>" }` or 404 |
| DELETE | `{baseUrl}/vault/{key}` | -- | 204 No Content |
| GET | `{baseUrl}/vault` | -- | `{ "keys": ["key1", "key2"] }` |

Key constraints: 1-256 printable ASCII characters (0x20-0x7E). Values are opaque ciphertext -- the server should store and return them without interpretation. Return `{"keys": []}` (not `null`) for empty key lists.

[Locke Gateway](https://gateway.locke.id) implements these endpoints out of the box. For self-hosted deployments, implement the four routes with your own storage backend.

#### Security details

- **Encryption**: AES-256-GCM with a random 12-byte IV per `setItem` call. The key is derived via HKDF-SHA-256 from the WebAuthn PRF output and stored as a non-extractable `CryptoKey` — JavaScript can use it for encrypt/decrypt but cannot read the raw key bytes.
- **Post-quantum**: The entire vault key chain is symmetric (HMAC-SHA-256 PRF output → HKDF → AES-GCM). Grover's algorithm halves effective security to 128 bits, which remains safe. The WebAuthn credential itself (ES256) is not post-quantum, but the vault encryption is.
- **IV collision risk**: AES-GCM's 96-bit random IV has a birthday bound of ~2^32 encryptions per key before nonce collision becomes probable. We evaluated XChaCha20-Poly1305 (192-bit nonce, ~2^96 bound) but rejected it: Web Crypto doesn't support it, so the key would have to live in a plain `ArrayBuffer` instead of the browser's non-extractable key store — trading XSS key-theft resistance for nonce space that isn't needed. Each `setItem` is an HTTP round-trip; at one write per second, hitting 2^32 takes 136 years. Synthetic (counter-based) IVs were also considered but add persistent state management complexity for no practical benefit at vault-scale write volumes.
- **Logout**: `PasskeyClient.logout()` clears the session, nulls the PRF key, and calls `Vault.clear()` to wipe the IndexedDB-persisted encryption key.

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
