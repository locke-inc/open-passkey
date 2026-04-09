# @open-passkey/svelte

Svelte stores for passkey (WebAuthn/FIDO2) authentication with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/svelte @open-passkey/sdk
```

## Quick Start

Add passkeys to your Svelte app **without running your own backend**. [Locke Gateway](https://gateway.locke.id) is a free hosted passkey server:

```typescript
import { createPasskeyClient } from "@open-passkey/svelte";

const { registerStore, loginStore, sessionStore } = createPasskeyClient({
  provider: "locke-gateway",
  rpId: "example.com",
});
```

### Self-hosted

If you're running your own passkey server:

```typescript
const { registerStore, loginStore, sessionStore } = createPasskeyClient({
  baseUrl: "/passkey",
});
```

### Register

```svelte
<script>
  import { registerStore } from "$lib/passkey";

  function handleRegister() {
    registerStore.register("user-123", "alice@example.com");
  }
</script>

<button
  on:click={handleRegister}
  disabled={$registerStore.status === "pending"}
>
  {$registerStore.status === "pending" ? "Creating passkey..." : "Create Passkey"}
</button>

{#if $registerStore.status === "error"}
  <p>{$registerStore.error?.message}</p>
{/if}
```

### Login

```svelte
<script>
  import { loginStore } from "$lib/passkey";
</script>

<button
  on:click={() => loginStore.authenticate()}
  disabled={$loginStore.status === "pending"}
>
  Sign in with Passkey
</button>

{#if $loginStore.status === "success"}
  <p>Welcome, {$loginStore.result?.userId}</p>
{/if}
```

### Session

```svelte
<script>
  import { onMount } from "svelte";
  import { sessionStore } from "$lib/passkey";

  onMount(() => sessionStore.checkSession());
</script>

{#if $sessionStore.loading}
  <p>Loading...</p>
{:else if $sessionStore.session}
  <p>Logged in as {$sessionStore.session.userId}</p>
  <button on:click={() => sessionStore.logout()}>Logout</button>
{:else}
  <p>Not logged in</p>
{/if}
```

## Stores

`createPasskeyClient(config)` returns:

| Store | Methods | State |
|-------|---------|-------|
| `registerStore` | `register(userId, username)` | `{ status, result, error }` |
| `loginStore` | `authenticate(userId?)` | `{ status, result, error }` |
| `sessionStore` | `checkSession()`, `logout()` | `{ session, loading }` |

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK (peer dependency) |
| [@open-passkey/sveltekit](https://www.npmjs.com/package/@open-passkey/sveltekit) | SvelteKit server handlers |

## License

MIT
