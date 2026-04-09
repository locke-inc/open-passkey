# @open-passkey/vue

Vue 3 composables for passkey (WebAuthn/FIDO2) authentication with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/vue @open-passkey/sdk
```

## Quick Start

Add passkeys to your Vue app **without running your own backend**. [Locke Gateway](https://gateway.locke.id) is a free hosted passkey server:

```typescript
import { createApp } from "vue";
import { createPasskey } from "@open-passkey/vue";

const app = createApp(App);
app.use(createPasskey({ provider: "locke-gateway", rpId: "example.com" }));
app.mount("#app");
```

### Self-hosted

If you're running your own passkey server:

```typescript
app.use(createPasskey({ baseUrl: "/passkey" }));
```

### Register

```vue
<script setup>
import { usePasskeyRegister } from "@open-passkey/vue";

const { register, status, error } = usePasskeyRegister();
</script>

<template>
  <button
    @click="register('user-123', 'alice@example.com')"
    :disabled="status === 'pending'"
  >
    {{ status === "pending" ? "Creating passkey..." : "Create Passkey" }}
  </button>
  <p v-if="status === 'error'">{{ error?.message }}</p>
</template>
```

### Login

```vue
<script setup>
import { usePasskeyLogin } from "@open-passkey/vue";

const { authenticate, status, result, error } = usePasskeyLogin();
</script>

<template>
  <button @click="authenticate()" :disabled="status === 'pending'">
    Sign in with Passkey
  </button>
  <p v-if="status === 'success'">Welcome, {{ result?.userId }}</p>
</template>
```

### Session

```vue
<script setup>
import { onMounted } from "vue";
import { usePasskeySession } from "@open-passkey/vue";

const { session, loading, checkSession, logout } = usePasskeySession();
onMounted(() => checkSession());
</script>

<template>
  <p v-if="loading">Loading...</p>
  <div v-else-if="session">
    <p>Logged in as {{ session.userId }}</p>
    <button @click="logout">Logout</button>
  </div>
  <p v-else>Not logged in</p>
</template>
```

## Composables

| Composable | Returns | Description |
|------------|---------|-------------|
| `usePasskeyRegister()` | `{ register, status, result, error }` | Registration ceremony |
| `usePasskeyLogin()` | `{ authenticate, status, result, error }` | Authentication ceremony |
| `usePasskeySession()` | `{ session, loading, checkSession, logout }` | Session management |

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK (peer dependency) |
| [@open-passkey/nuxt](https://www.npmjs.com/package/@open-passkey/nuxt) | Nuxt 3 server handlers |

## License

MIT
