# open-passkey

An open-source library for adding passkey authentication to any app. Built on [WebAuthn](https://www.w3.org/TR/webauthn-3/) with hybrid post-quantum signature verification (ML-DSA-65-ES256). Available for Go, TypeScript, Python, Java, .NET, and Rust.

> **Status:** Production-ready for ES256 passkeys. Post-quantum algorithms verified but awaiting browser support.

## Hybrid Post-Quantum Support

open-passkey implements **ML-DSA-65-ES256** hybrid composite signatures ([draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/)), combining a NIST-standardized post-quantum algorithm with classical ECDSA in a single credential. Both signature components must verify independently. If either is broken, the other still protects you.

| Algorithm | COSE alg | Status | Go | TS | Python | Java | .NET | Rust |
|-----------|----------|--------|----|----|--------|------|------|------|
| **ML-DSA-65-ES256** (composite) | `-52` | IETF Draft | Yes | Yes | Yes | Yes | Yes | Yes |
| **ML-DSA-65** (PQ only) | `-49` | NIST FIPS 204 | Yes | Yes | Yes | Yes | Yes | Yes |
| **ES256** (ECDSA P-256) | `-7` | Generally Available | Yes | Yes | Yes | Yes | Yes | Yes |

During registration, the server advertises preferred algorithms in `pubKeyCredParams`. During authentication, the core libraries read the COSE `alg` field from the stored credential and dispatch to the correct verifier automatically. No application code changes needed when PQ support arrives in browsers.

## Quick Start

Pick your framework and add passkey auth in minutes. Every example is in `examples/`.

### Express (TypeScript)

```typescript
import express from "express";
import { createPasskeyRouter, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/express";

const app = express();
app.use(express.json());
app.use("/passkey", createPasskeyRouter({
  rpId: "localhost",
  rpDisplayName: "My App",
  origin: "http://localhost:3001",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
}));
app.listen(3001);
```

### Go (Fiber)

```go
import (
    passkey "github.com/locke-inc/open-passkey/packages/server-fiber"
    "github.com/gofiber/fiber/v2"
)

app := fiber.New()
p, _ := passkey.New(passkey.Config{
    RPID:            "localhost",
    RPDisplayName:   "My App",
    Origin:          "http://localhost:4004",
    ChallengeStore:  passkey.NewMemoryChallengeStore(),
    CredentialStore: passkey.NewMemoryCredentialStore(),
})
p.RegisterRoutes(app, "/passkey")
app.Listen(":4004")
```

### FastAPI (Python)

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from open_passkey_fastapi import create_passkey_router, PasskeyConfig

app = FastAPI()
app.include_router(
    create_passkey_router(PasskeyConfig(
        rp_id="localhost",
        rp_display_name="My App",
        origin="http://localhost:5002",
    )),
    prefix="/passkey",
)
```

### React (with Next.js)

```tsx
import { PasskeyProvider, usePasskeyRegister, usePasskeyLogin } from "@open-passkey/react";

function App() {
  return (
    <PasskeyProvider baseUrl="/api/passkey">
      <PasskeyDemo />
    </PasskeyProvider>
  );
}

function PasskeyDemo() {
  const { register, status: regStatus } = usePasskeyRegister();
  const { authenticate, status: authStatus, result } = usePasskeyLogin();
  return (
    <>
      <button onClick={() => register("user-1", "Alice")} disabled={regStatus === "pending"}>
        Register Passkey
      </button>
      <button onClick={() => authenticate("user-1")} disabled={authStatus === "pending"}>
        Sign In
      </button>
    </>
  );
}
```

### Angular

```typescript
// app.config.ts
import { provideHttpClient } from "@angular/common/http";
import { providePasskey } from "@open-passkey/angular";

export const appConfig = {
  providers: [provideHttpClient(), providePasskey({ baseUrl: "/passkey" })],
};

// app.component.ts — headless components with content projection
@Component({
  imports: [PasskeyRegisterComponent, PasskeyLoginComponent],
  template: `
    <passkey-register [userId]="userId" [username]="name" (registered)="onSuccess($event)" #reg>
      <button (click)="reg.register()" [disabled]="reg.loading()">Register</button>
    </passkey-register>
    <passkey-login [userId]="userId" (authenticated)="onAuth($event)" #login>
      <button (click)="login.login()" [disabled]="login.loading()">Sign In</button>
    </passkey-login>
  `,
})
export class AppComponent { /* ... */ }
```

See [all framework examples](#examples) below.

## Architecture

```
open-passkey/
├── spec/vectors/           # 31 shared JSON test vectors
├── packages/
│   ├── core-go/            # Go core protocol (ES256, ML-DSA-65, composite)
│   ├── core-ts/            # TypeScript core protocol
│   ├── core-py/            # Python core protocol
│   ├── core-java/          # Java core protocol
│   ├── core-dotnet/        # .NET core protocol
│   ├── core-rust/          # Rust core protocol
│   ├── server-ts/          # Shared TS server logic (Passkey class)
│   ├── server-go/          # Go HTTP bindings (stdlib)
│   ├── server-express/     # Express.js
│   ├── server-fastify/     # Fastify
│   ├── server-hono/        # Hono (edge-compatible)
│   ├── server-nestjs/      # NestJS
│   ├── server-nextjs/      # Next.js App Router
│   ├── server-nuxt/        # Nuxt 3 (Nitro)
│   ├── server-sveltekit/   # SvelteKit
│   ├── server-remix/       # Remix
│   ├── server-astro/       # Astro
│   ├── server-nethttp/     # Go net/http
│   ├── server-echo/        # Go Echo
│   ├── server-fiber/       # Go Fiber
│   ├── server-chi/         # Go Chi
│   ├── server-flask/       # Flask
│   ├── server-fastapi/     # FastAPI
│   ├── server-django/      # Django
│   ├── server-spring/      # Spring Boot
│   ├── server-aspnet/      # ASP.NET Core
│   ├── server-axum/        # Axum (Rust)
│   ├── sdk-js/             # Vanilla JS client (base for all frontend SDKs)
│   ├── react/              # React hooks + provider
│   ├── vue/                # Vue composables + plugin
│   ├── svelte/             # Svelte stores
│   ├── solid/              # SolidJS primitives
│   ├── angular/            # Angular components + service
│   └── authenticator-ts/   # Software authenticator for testing
├── examples/               # Working example for every framework
└── tools/vecgen/           # Test vector generator
```

The **core protocol** is pure WebAuthn/FIDO2 verification logic with no framework dependencies. **Framework bindings** are thin adapters (~50-80 lines). Adding passkey support to a new framework only requires writing an adapter, not reimplementing cryptography.

## Packages

### Core Protocol Libraries

Every core library passes the same 31 shared test vectors. Zero framework dependencies.

| Package | Language | Crypto (ES256) | PQ (ML-DSA-65) | CBOR |
|---------|----------|----------------|-----------------|------|
| `core-go` | Go | `crypto/ecdsa` | `cloudflare/circl` | `fxamacker/cbor` |
| `core-ts` | TypeScript | `node:crypto` | `@noble/post-quantum` | `cbor-x` |
| `core-py` | Python | `cryptography` | `oqs` (liboqs) | `cbor2` |
| `core-java` | Java | BouncyCastle | BouncyCastle bcpqc | Jackson CBOR |
| `core-dotnet` | C# | `System.Security.Cryptography` | BouncyCastle.Cryptography | `PeterO.Cbor` |
| `core-rust` | Rust | `p256` + `ecdsa` | `fips204` | `ciborium` |

### Server Bindings

All server bindings expose 4 POST endpoints:

| Endpoint | Purpose |
|----------|---------|
| `POST /passkey/register/begin` | Start registration ceremony |
| `POST /passkey/register/finish` | Complete registration |
| `POST /passkey/login/begin` | Start authentication ceremony |
| `POST /passkey/login/finish` | Complete authentication |

#### TypeScript (9 bindings)

All share `@open-passkey/server` — a framework-agnostic `Passkey` class with challenge management and store interfaces.

| Package | Framework | Init Pattern |
|---------|-----------|-------------|
| `@open-passkey/express` | Express.js | `app.use("/passkey", createPasskeyRouter(config))` |
| `@open-passkey/fastify` | Fastify | `fastify.register(passkeyPlugin, config)` |
| `@open-passkey/hono` | Hono | `app.route("/passkey", createPasskeyApp(config))` |
| `@open-passkey/nestjs` | NestJS | `PasskeyModule.forRoot(config)` |
| `@open-passkey/nextjs` | Next.js | `createPasskeyHandlers(config)` → route handlers |
| `@open-passkey/nuxt` | Nuxt 3 | `createPasskeyHandlers(config)` → Nitro handlers |
| `@open-passkey/sveltekit` | SvelteKit | `createPasskeyHandlers(config)` → `+server.ts` |
| `@open-passkey/remix` | Remix | `createPasskeyActions(config)` → action functions |
| `@open-passkey/astro` | Astro | `createPasskeyEndpoints(config)` → API routes |

#### Go (5 bindings)

Each is a separate Go module. Pluggable `ChallengeStore` and `CredentialStore` interfaces.

| Package | Framework | Init Pattern |
|---------|-----------|-------------|
| `server-go` | stdlib | `p.BeginRegistration` etc. as `http.HandlerFunc` |
| `server-nethttp` | net/http | `http.Handle("/passkey/", p.Handler())` |
| `server-echo` | Echo | `p.RegisterRoutes(e, "/passkey")` |
| `server-fiber` | Fiber | `p.RegisterRoutes(app, "/passkey")` |
| `server-chi` | Chi | `r.Mount("/passkey", p.Routes())` |

#### Python (3 bindings)

| Package | Framework | Init Pattern |
|---------|-----------|-------------|
| `server-flask` | Flask | `app.register_blueprint(create_passkey_blueprint(config))` |
| `server-fastapi` | FastAPI | `app.include_router(create_passkey_router(config))` |
| `server-django` | Django | `configure(...)` + `include(passkey_urls)` |

#### Other Languages

| Package | Framework | Init Pattern |
|---------|-----------|-------------|
| `server-spring` | Spring Boot | Auto-config via `application.properties` |
| `server-aspnet` | ASP.NET Core | `app.MapPasskeyEndpoints(config)` |
| `server-axum` | Axum (Rust) | `passkey_router(config, stores)` → Axum Router |

### Frontend SDKs

Client-side only. Call the browser WebAuthn API and communicate with any open-passkey server over HTTP.

| Package | Framework | API |
|---------|-----------|-----|
| `@open-passkey/sdk` | Vanilla JS | `new PasskeyClient({ baseUrl })` |
| `@open-passkey/react` | React | `usePasskeyRegister()`, `usePasskeyLogin()` |
| `@open-passkey/vue` | Vue 3 | `usePasskeyRegister()`, `usePasskeyLogin()` |
| `@open-passkey/svelte` | Svelte | `createPasskeyClient()` → stores |
| `@open-passkey/solid` | SolidJS | `createPasskeyRegister()`, `createPasskeyLogin()` |
| `@open-passkey/angular` | Angular | `PasskeyRegisterComponent`, `PasskeyLoginComponent` |

## Examples

Every framework binding has a working example in `examples/`. Each is a complete passkey registration + authentication demo.

```bash
# Pick any example:
cd examples/express && npm install && npm start
cd examples/fiber   && go run main.go
cd examples/fastapi && pip install -r requirements.txt && python app.py
```

| Example | Framework | Port | Frontend |
|---------|-----------|------|----------|
| `examples/express` | Express | 3001 | Vanilla JS |
| `examples/fastify` | Fastify | 3002 | Vanilla JS |
| `examples/hono` | Hono | 3003 | Vanilla JS |
| `examples/nestjs` | NestJS | 3009 | Vanilla JS |
| `examples/nextjs` | Next.js | 3004 | React SDK (`@open-passkey/react`) |
| `examples/nuxt` | Nuxt 3 | 3005 | Vue SDK (`@open-passkey/vue`) |
| `examples/sveltekit` | SvelteKit | 3006 | Svelte SDK (`@open-passkey/svelte`) |
| `examples/remix` | Remix | 3007 | React SDK (`@open-passkey/react`) |
| `examples/astro` | Astro | 3008 | Vanilla JS |
| `examples/gin` | Go (stdlib) | 4001 | Vanilla JS |
| `examples/nethttp` | Go net/http | 4002 | Vanilla JS |
| `examples/echo` | Go Echo | 4003 | Vanilla JS |
| `examples/fiber` | Go Fiber | 4004 | Vanilla JS |
| `examples/chi` | Go Chi | 4005 | Vanilla JS |
| `examples/flask` | Flask | 5001 | Vanilla JS |
| `examples/fastapi` | FastAPI | 5002 | Vanilla JS |
| `examples/django` | Django | 5003 | Vanilla JS |
| `examples/spring` | Spring Boot | 8080 | Vanilla JS |
| `examples/aspnet` | ASP.NET Core | 5000 | Vanilla JS |
| `examples/axum` | Axum (Rust) | 3000 | Vanilla JS |
| `examples/angular` | Angular | 4200+3010 | Angular SDK (`@open-passkey/angular`) |
| `examples/solid` | SolidJS | 3011+3012 | Solid SDK (`@open-passkey/solid`) |

## Features

- **Attestation:** `none` and `packed` (self-attestation + full x5c certificate chain)
- **Backup flags:** BE/BS exposed in results, spec conformance enforced (SS6.3.3)
- **PRF extension:** Salt generation, per-credential evaluation, output passthrough
- **userHandle:** Cross-checked against credential owner in discoverable flow
- **Sign count:** Rollback detection per SS7.2
- **Token binding:** `"present"` rejected, `"supported"` allowed
- **Algorithm negotiation:** ML-DSA-65-ES256 preferred, ML-DSA-65 second, ES256 fallback

## Testing

31 shared test vectors across 3 ceremony files, verified in Go, TypeScript, Python, Java, .NET, and Rust:

```bash
./scripts/test-all.sh
```

| Package | Tests | Description |
|---------|-------|-------------|
| core-go | 31 vectors | Spec vector verification |
| core-ts | 31 vectors | Same vectors, TypeScript |
| core-py | 31 vectors | Same vectors, Python |
| core-java | 31 vectors | Same vectors, Java |
| core-dotnet | 31 vectors | Same vectors, .NET |
| core-rust | 31 vectors | Same vectors, Rust |
| server-go | 31 tests | HTTP handlers, stores, userHandle |
| authenticator-ts | 7 tests | Round-trip creation/assertion |
| angular | 37 tests | Components, service, PRF |

## Development

**Prerequisites:** Go 1.21+, Node.js 18+. Optional: Python 3.10+, JDK 17+, .NET 8+, Rust 1.70+.

```bash
# Generate test vectors
cd tools/vecgen && go run main.go -out ../../spec/vectors

# Run all tests
./scripts/test-all.sh
```

## Roadmap

- [x] ES256 + ML-DSA-65 + ML-DSA-65-ES256 composite verification (6 languages)
- [x] 22 server framework bindings (9 TS, 5 Go, 3 Python, 1 Java, 1 .NET, 1 Rust)
- [x] 6 frontend SDKs (React, Vue, Svelte, Solid, Angular, vanilla JS)
- [x] Go HTTP server bindings with pluggable stores
- [x] Packed attestation (self + x5c)
- [x] Backup flags, userHandle verification, PRF extension
- [x] 31 shared cross-language test vectors
- [ ] Ruby + PHP core libraries
- [ ] Rails + Laravel server bindings
- [ ] Additional attestation formats (TPM, Android)

## Contributing

Strict TDD. To add a test case:

1. Update `tools/vecgen/main.go` and regenerate vectors
2. Run `./scripts/test-all.sh` — new vector should fail
3. Implement in each language until all pass

**New language:** Create `packages/core-{lang}/`, load `spec/vectors/*.json`, implement until all 31 vectors pass. Then write a thin server binding.

## License

MIT. Copyright 2025 Locke Identity Networks Inc.
