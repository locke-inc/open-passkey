# @open-passkey/react

React hooks for passkey (WebAuthn/FIDO2) authentication with post-quantum cryptography support.

## Install

```bash
npm install @open-passkey/react @open-passkey/sdk
```

## Quick Start

Add passkeys to your React app **without running your own backend**. [Locke Gateway](https://gateway.locke.id) is a free hosted passkey server:

```tsx
import { PasskeyProvider } from "@open-passkey/react";

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

### Register

```tsx
import { usePasskeyRegister } from "@open-passkey/react";

function RegisterButton() {
  const { register, status, error } = usePasskeyRegister();

  return (
    <div>
      <button
        onClick={() => register("user-123", "alice@example.com")}
        disabled={status === "pending"}
      >
        {status === "pending" ? "Creating passkey..." : "Create Passkey"}
      </button>
      {status === "error" && <p>{error?.message}</p>}
    </div>
  );
}
```

### Login

```tsx
import { usePasskeyLogin } from "@open-passkey/react";

function LoginButton() {
  const { authenticate, status, result, error } = usePasskeyLogin();

  return (
    <div>
      <button
        onClick={() => authenticate()}
        disabled={status === "pending"}
      >
        {status === "pending" ? "Signing in..." : "Sign in with Passkey"}
      </button>
      {status === "success" && <p>Welcome, {result?.userId}</p>}
      {status === "error" && <p>{error?.message}</p>}
    </div>
  );
}
```

### Session

```tsx
import { usePasskeySession } from "@open-passkey/react";
import { useEffect } from "react";

function Dashboard() {
  const { session, loading, checkSession, logout } = usePasskeySession();

  useEffect(() => { checkSession(); }, []);

  if (loading) return <p>Loading...</p>;
  if (!session) return <p>Not logged in</p>;

  return (
    <div>
      <p>Logged in as {session.userId}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

## Hooks

| Hook | Returns | Description |
|------|---------|-------------|
| `usePasskeyRegister()` | `{ register, status, result, error }` | Registration ceremony |
| `usePasskeyLogin()` | `{ authenticate, status, result, error }` | Authentication ceremony |
| `usePasskeySession()` | `{ session, loading, checkSession, logout }` | Session management |

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK (peer dependency) |
| [@open-passkey/nextjs](https://www.npmjs.com/package/@open-passkey/nextjs) | Next.js server handlers |
| [@open-passkey/express](https://www.npmjs.com/package/@open-passkey/express) | Express server middleware |

## License

MIT
