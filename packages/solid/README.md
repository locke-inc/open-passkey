# @open-passkey/solid

SolidJS primitives for passkey (WebAuthn/FIDO2) authentication with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/solid @open-passkey/sdk
```

## Quick Start

Add passkeys to your SolidJS app **without running your own backend**. [Locke Gateway](https://gateway.locke.id) is a free hosted passkey server:

```tsx
import { PasskeyProvider } from "@open-passkey/solid";

function App() {
  return (
    <PasskeyProvider provider="locke-gateway" rpId="example.com">
      <MyApp />
    </PasskeyProvider>
  );
}
```

### Self-hosted

If you're running your own passkey server:

```tsx
<PasskeyProvider baseUrl="/passkey">
  <MyApp />
</PasskeyProvider>
```
```

### Register

```tsx
import { createPasskeyRegister } from "@open-passkey/solid";

function RegisterButton() {
  const { register, status, error } = createPasskeyRegister();

  return (
    <div>
      <button
        onClick={() => register("user-123", "alice@example.com")}
        disabled={status() === "pending"}
      >
        {status() === "pending" ? "Creating passkey..." : "Create Passkey"}
      </button>
      {status() === "error" && <p>{error()?.message}</p>}
    </div>
  );
}
```

### Login

```tsx
import { createPasskeyLogin } from "@open-passkey/solid";

function LoginButton() {
  const { authenticate, status, result, error } = createPasskeyLogin();

  return (
    <div>
      <button
        onClick={() => authenticate()}
        disabled={status() === "pending"}
      >
        {status() === "pending" ? "Signing in..." : "Sign in with Passkey"}
      </button>
      {status() === "success" && <p>Welcome, {result()?.userId}</p>}
    </div>
  );
}
```

### Session

```tsx
import { createPasskeySession } from "@open-passkey/solid";
import { onMount, Show } from "solid-js";

function Dashboard() {
  const { session, loading, checkSession, logout } = createPasskeySession();

  onMount(() => checkSession());

  return (
    <Show when={!loading()} fallback={<p>Loading...</p>}>
      <Show when={session()} fallback={<p>Not logged in</p>}>
        <p>Logged in as {session()?.userId}</p>
        <button onClick={logout}>Logout</button>
      </Show>
    </Show>
  );
}
```

## Primitives

| Primitive | Returns | Description |
|-----------|---------|-------------|
| `createPasskeyRegister()` | `{ register, status, result, error }` | Registration ceremony |
| `createPasskeyLogin()` | `{ authenticate, status, result, error }` | Authentication ceremony |
| `createPasskeySession()` | `{ session, loading, checkSession, logout }` | Session management |

All return values (`status`, `result`, `error`, `session`, `loading`) are SolidJS signals (call as functions to read).

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK (peer dependency) |
| [@open-passkey/astro](https://www.npmjs.com/package/@open-passkey/astro) | Astro server handlers |

## License

MIT
