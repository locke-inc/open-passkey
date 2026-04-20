# open-passkey

An open-source library for adding passkey authentication to any app. Built on [WebAuthn](https://www.w3.org/TR/webauthn-3/) with hybrid post-quantum signature verification (ML-DSA-65-ES256). Available for Go, TypeScript, Python, Java, .NET, Rust, PHP, and Ruby.

> **Status:** Production-ready for ES256 passkeys. Post-quantum algorithms verified but awaiting browser support.

## Hybrid Post-Quantum Support

open-passkey implements **ML-DSA-65-ES256** hybrid composite signatures ([draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/)), combining a NIST-standardized post-quantum algorithm with classical ECDSA in a single credential. Both signature components must verify independently. If either is broken, the other still protects you.

| Algorithm | COSE alg | Status | Go | TS | Python | Java | .NET | Rust | PHP | Ruby |
|-----------|----------|--------|----|----|--------|------|------|------|-----|------|
| **ML-DSA-65-ES256** (composite) | `-52` | IETF Draft | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **ML-DSA-65** (PQ only) | `-49` | NIST FIPS 204 | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **ES256** (ECDSA P-256) | `-7` | Generally Available | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |

During registration, the server advertises preferred algorithms in `pubKeyCredParams`. During authentication, the core libraries read the COSE `alg` field from the stored credential and dispatch to the correct verifier automatically. No application code changes needed when PQ support arrives in browsers.

## Quick Start

Pick your framework and add passkey auth in minutes. Every example is in `examples/`.

### Hosted — No Server Needed

Use [Locke Gateway](https://gateway.locke.id) as a free hosted passkey backend with no registration and no API keys.

```typescript
// Any framework, just add your domain
new PasskeyClient({ provider: "locke-gateway", rpId: "app.example.com" })

// React
<PasskeyProvider provider="locke-gateway" rpId="app.example.com">

// Vue
createPasskey({ provider: "locke-gateway", rpId: "app.example.com" })

// Angular
providePasskey({ provider: "locke-gateway", rpId: "app.example.com" })
```

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

### Go (any framework)

```go
import (
    "net/http"
    passkey "github.com/locke-inc/open-passkey/packages/server-go"
)

p, _ := passkey.New(passkey.Config{
    RPID:            "localhost",
    RPDisplayName:   "My App",
    Origin:          "http://localhost:4001",
    ChallengeStore:  passkey.NewMemoryChallengeStore(),
    CredentialStore: passkey.NewMemoryCredentialStore(),
})
mux := http.NewServeMux()
mux.HandleFunc("POST /passkey/register/begin", p.BeginRegistration)
mux.HandleFunc("POST /passkey/register/finish", p.FinishRegistration)
mux.HandleFunc("POST /passkey/login/begin", p.BeginAuthentication)
mux.HandleFunc("POST /passkey/login/finish", p.FinishAuthentication)
http.ListenAndServe(":4001", mux)
```

Handlers are standard `http.HandlerFunc` — works directly with Chi, Gorilla, net/http, etc. For Echo and Fiber, see the examples for thin adapter wrappers.

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

### Rails (Ruby)

```ruby
# Gemfile
gem "open-passkey-rails"

# config/routes.rb
Rails.application.routes.draw do
  mount OpenPasskey::Engine => "/passkey"
end

# config/initializers/passkey.rb
OpenPasskey.configure do |c|
  c.rp_id = "localhost"
  c.rp_display_name = "My App"
  c.origin = "http://localhost:3005"
  c.session = OpenPasskey::SessionConfig.new(
    secret: ENV["PASSKEY_SESSION_SECRET"],
    secure: false,
  )
end
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

### Vanilla JS (any backend)

```html
<script src="https://unpkg.com/@open-passkey/sdk/dist/open-passkey.iife.js"></script>
<script>
  const passkey = new OpenPasskey.PasskeyClient({ baseUrl: "/passkey" });

  // Register
  const reg = await passkey.register("user-1", "Alice");

  // Authenticate
  const auth = await passkey.authenticate("user-1");
</script>
```

### Angular

```typescript
// app.config.ts
import { providePasskey } from "@open-passkey/angular";

export const appConfig = {
  providers: [providePasskey({ baseUrl: "/passkey" })],
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
│   ├── core-php/           # PHP core protocol
│   ├── core-ruby/          # Ruby core protocol
│   ├── server-ts/          # Shared TS server logic (Passkey class)
│   ├── server-go/          # Go HTTP bindings (stdlib http.HandlerFunc)
│   ├── server-express/     # Express.js
│   ├── server-fastify/     # Fastify
│   ├── server-hono/        # Hono (edge-compatible)
│   ├── server-nestjs/      # NestJS
│   ├── server-nextjs/      # Next.js App Router
│   ├── server-nuxt/        # Nuxt 3 (Nitro)
│   ├── server-sveltekit/   # SvelteKit
│   ├── server-remix/       # Remix
│   ├── server-astro/       # Astro
│   ├── server-py/          # Shared Python server logic (PasskeyHandler)
│   ├── server-flask/       # Flask (thin wrapper around server-py)
│   ├── server-fastapi/     # FastAPI (thin wrapper around server-py)
│   ├── server-django/      # Django (thin wrapper around server-py)
│   ├── server-php/         # Shared PHP server logic (PasskeyHandler)
│   ├── server-laravel/     # Laravel (thin wrapper around server-php)
│   ├── server-symfony/     # Symfony (thin wrapper around server-php)
│   ├── server-wordpress/   # WordPress plugin
│   ├── server-rails/       # Rails Engine
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

The **core protocol** is pure WebAuthn/FIDO2 verification logic with no framework dependencies. **Server packages** (`server-ts`, `server-go`, `server-py`, `server-php`) contain shared business logic; **framework bindings** are thin adapters (~50-80 lines). **Frontend SDKs** all wrap `@open-passkey/sdk` (`PasskeyClient`), which handles the browser WebAuthn API and HTTP calls — framework packages only add framework-specific state management (React hooks, Vue refs, Svelte stores, Angular DI). Adding passkey support to a new framework only requires writing an adapter, not reimplementing cryptography or client logic.

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
| `core-php` | PHP | `ext-openssl` | `ext-ffi` (liboqs) | Custom decoder |
| `core-ruby` | Ruby | `openssl` (stdlib) | `ffi` (liboqs) | Custom decoder |

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

#### Go (1 package, all frameworks)

Single Go module with standard `http.HandlerFunc` handlers. Pluggable `ChallengeStore` and `CredentialStore` interfaces. Works directly with any framework that accepts `http.HandlerFunc` (Chi, Gorilla, net/http). For Echo and Fiber, examples show thin adapter wrappers (~5 lines).

| Package | Init Pattern |
|---------|-------------|
| `server-go` | `p.BeginRegistration` etc. as `http.HandlerFunc`, or `p.Handler()` as `http.Handler` |

#### Python (3 bindings)

| Package | Framework | Init Pattern |
|---------|-----------|-------------|
| `server-flask` | Flask | `app.register_blueprint(create_passkey_blueprint(config))` |
| `server-fastapi` | FastAPI | `app.include_router(create_passkey_router(config))` |
| `server-django` | Django | `configure(...)` + `include(passkey_urls)` |

#### PHP (4 bindings)

All share `open-passkey/server` — a framework-agnostic `PasskeyHandler` class with challenge/credential store interfaces.

| Package | Framework | Init Pattern |
|---------|-----------|-------------|
| `server-php` | Any (shared logic) | `new PasskeyHandler($config)` |
| `server-laravel` | Laravel | Auto-discovery via `PasskeyServiceProvider` |
| `server-symfony` | Symfony | `OpenPasskeyBundle` registration |
| `server-wordpress` | WordPress | Plugin activation (admin settings UI included) |

> **WordPress distribution:** The plugin zip is published on the [GitHub Releases](https://github.com/locke-inc/open-passkey/releases) page for easy installation via WP Admin → Plugins → Upload.

#### Ruby (1 binding)

| Package | Framework | Init Pattern |
|---------|-----------|-------------|
| `server-rails` | Rails | `mount OpenPasskey::Engine => "/passkey"` |

Rails Engine with pluggable stores (`MemoryChallengeStore`, `RailsCacheChallengeStore`, `MemoryCredentialStore`). Session support via HMAC-SHA256 stateless cookies.

#### Other Languages

| Package | Framework | Init Pattern |
|---------|-----------|-------------|
| `server-spring` | Spring Boot | Auto-config via `application.properties` |
| `server-aspnet` | ASP.NET Core | `app.MapPasskeyEndpoints(config)` |
| `server-axum` | Axum (Rust) | `passkey_router(config, stores)` → Axum Router |

### Frontend SDKs

Client-side only. All wrap `@open-passkey/sdk` (`PasskeyClient`), which handles the browser WebAuthn API, base64url encoding, PRF extension decoding, and HTTP calls to any open-passkey server. Framework packages add only framework-specific state management.

| Package | Framework | API | Wraps |
|---------|-----------|-----|-------|
| `@open-passkey/sdk` | Vanilla JS / `<script>` tag | `new PasskeyClient({ baseUrl })` | — (canonical) |
| `@open-passkey/react` | React | `usePasskeyRegister()`, `usePasskeyLogin()` | PasskeyClient |
| `@open-passkey/vue` | Vue 3 | `usePasskeyRegister()`, `usePasskeyLogin()` | PasskeyClient |
| `@open-passkey/svelte` | Svelte | `createPasskeyClient()` → stores | PasskeyClient |
| `@open-passkey/solid` | SolidJS | `createPasskeyRegister()`, `createPasskeyLogin()` | PasskeyClient |
| `@open-passkey/angular` | Angular | `PasskeyRegisterComponent`, `PasskeyLoginComponent` | PasskeyClient |

The SDK also ships an IIFE bundle (`dist/open-passkey.iife.js`) for use via `<script>` tag — all server-only examples (Go, Python, Rust, .NET, Java, Node.js) use this.

## Examples

Every framework binding has a working example in `examples/`. Each is a complete passkey registration + authentication demo.

```bash
# Pick any example:
cd examples/express && npm install && npm start
cd examples/fiber   && go run main.go
cd examples/fastapi && pip install -r requirements.txt && python app.py
cd examples/rails   && bundle install && bundle exec rackup -p 3005
```

**Frontend examples** (use [Locke Gateway](https://gateway.locke.id) — no server to run):

| Example | Framework | Port | Frontend SDK |
|---------|-----------|------|--------------|
| `examples/react` | React | 3015 | `@open-passkey/react` |
| `examples/vue` | Vue 3 | 3013 | `@open-passkey/vue` |
| `examples/angular` | Angular | 4200 | `@open-passkey/angular` |
| `examples/solid` | SolidJS | 3011 | `@open-passkey/solid` |

**Full-stack examples** (self-hosted, in-memory stores):

| Example | Framework | Port | Frontend |
|---------|-----------|------|----------|
| `examples/express` | Express | 3001 | SDK (`<script>`) |
| `examples/fastify` | Fastify | 3002 | SDK (`<script>`) |
| `examples/hono` | Hono | 3003 | SDK (`<script>`) |
| `examples/nestjs` | NestJS | 3009 | SDK (`<script>`) |
| `examples/nextjs` | Next.js | 3004 | React SDK (`@open-passkey/react`) |
| `examples/nuxt` | Nuxt 3 | 3005 | Vue SDK (`@open-passkey/vue`) |
| `examples/sveltekit` | SvelteKit | 3006 | Svelte SDK (`@open-passkey/svelte`) |
| `examples/remix` | Remix | 3007 | React SDK (`@open-passkey/react`) |
| `examples/astro` | Astro | 3008 | SDK (`<script>`) |
| `examples/gin` | Go (stdlib) | 4001 | SDK (`<script>`) |
| `examples/nethttp` | Go net/http | 4002 | SDK (`<script>`) |
| `examples/echo` | Go Echo | 4003 | SDK (`<script>`) |
| `examples/fiber` | Go Fiber | 4004 | SDK (`<script>`) |
| `examples/chi` | Go Chi | 4005 | SDK (`<script>`) |
| `examples/flask` | Flask | 5001 | SDK (`<script>`) |
| `examples/fastapi` | FastAPI | 5002 | SDK (`<script>`) |
| `examples/django` | Django | 5003 | SDK (`<script>`) |
| `examples/spring` | Spring Boot | 8080 | SDK (`<script>`) |
| `examples/aspnet` | ASP.NET Core | 5000 | SDK (`<script>`) |
| `examples/axum` | Axum (Rust) | 3000 | SDK (`<script>`) |
| `examples/php` | PHP (vanilla) | 8000 | SDK (`<script>`) |
| `examples/laravel` | Laravel | 8001 | SDK (`<script>`) |
| `examples/rails` | Rails | 3005 | SDK (`<script>`) |

## Features

- **Attestation:** `none` and `packed` (self-attestation + full x5c certificate chain)
- **Backup flags:** BE/BS exposed in results, spec conformance enforced (SS6.3.3)
- **PRF extension:** Salt generation, per-credential evaluation, output passthrough
- **E2E Encrypted Vault:** `localStorage`-style API — see [Vault (PRF)](#vault-prf) below
- **userHandle:** Cross-checked against credential owner in discoverable flow
- **Sign count:** Rollback detection per SS7.2
- **Token binding:** `"present"` rejected, `"supported"` allowed
- **Algorithm negotiation:** ML-DSA-65-ES256 preferred, ML-DSA-65 second, ES256 fallback

## Vault (PRF)

open-passkey includes an end-to-end encrypted key-value store powered by the WebAuthn [PRF extension](https://w3c.github.io/webauthn/#prf-extension). The server only ever sees ciphertext — encryption keys are derived on the client from the authenticator's hardware secret and never leave the browser.

```javascript
const passkey = new PasskeyClient({ baseUrl: "/passkey" });

// userId is REQUIRED for vault — see "Why userId is required" below
const result = await passkey.authenticate("alice@example.com");

const vault = passkey.vault();
await vault.setItem("secret", "hunter2");
const value = await vault.getItem("secret"); // "hunter2"

// Persist the encryption key so the vault survives page refreshes
await vault.persistKey(); // stores non-extractable CryptoKey in IndexedDB
```

On subsequent page loads, restore the vault without re-authenticating:

```javascript
const vault = await Vault.restore("/passkey");
if (vault) {
  const value = await vault.getItem("secret"); // works immediately
}
```

### How it works

1. During registration, the server generates a random 32-byte PRF salt and stores it with the credential
2. During authentication, the server sends the salt back in the WebAuthn request options (`extensions.prf.evalByCredential`)
3. The authenticator evaluates `HMAC(credentialSecret, salt)` and returns a 32-byte PRF output
4. The SDK derives an AES-256-GCM key via `HKDF-SHA256(prfOutput, salt="open-passkey-vault", info="aes-256-gcm")`
5. `setItem` encrypts with a random 12-byte IV; `getItem` decrypts. The server stores opaque ciphertext

### Why userId is required

PRF salts must be included in the WebAuthn request options *before* `navigator.credentials.get()` is called. To include the correct salt, the server must look up the user's credentials — which requires knowing the userId upfront.

When `authenticate()` is called without a userId (discoverable credentials / OS passkey picker), the server cannot include PRF salts because it doesn't know which credential will be selected. The authentication succeeds, but `prf.results.first` is `undefined` and `vault()` will throw.

**Rule of thumb:** if your app uses the vault, always pass userId to `authenticate()`.

### Persistence

The derived CryptoKey is non-extractable — even JavaScript cannot read the raw key bytes. When stored in IndexedDB via `persistKey()`, it can only be used for encrypt/decrypt operations through the Web Crypto API. Call `Vault.clear()` on logout to remove it.

| Method | Description |
|--------|-------------|
| `vault.persistKey()` | Store the derived CryptoKey in IndexedDB |
| `Vault.restore(baseUrl, sessionToken?)` | Load a persisted vault (returns `null` if not found) |
| `Vault.clear()` | Remove the persisted key (call on logout) |

## Testing

31 shared test vectors across 3 ceremony files, verified in Go, TypeScript, Python, Java, .NET, Rust, PHP, and Ruby:

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
| core-php | 31 vectors | Same vectors, PHP |
| core-ruby | 31 vectors | Same vectors, Ruby |
| server-go | 31 tests | HTTP handlers, stores, userHandle |
| authenticator-ts | 7 tests | Round-trip creation/assertion |
| angular | 19 tests | Components, service (wraps SDK) |

## Development

**Prerequisites:** Go 1.21+, Node.js 18+. Optional: Python 3.10+, JDK 17+, .NET 10+, Rust 1.70+, PHP 8.1+, Ruby 3.1+.

```bash
# Generate test vectors
cd tools/vecgen && go run main.go -out ../../spec/vectors

# Run all tests
./scripts/test-all.sh
```

## Roadmap

- [x] ES256 + ML-DSA-65 + ML-DSA-65-ES256 composite verification (8 languages)
- [x] 23 server packages covering 25 frameworks (9 TS, 5 Go, 3 Python, 4 PHP, Rails, Spring, ASP.NET, Axum)
- [x] 6 frontend SDKs (React, Vue, Svelte, Solid, Angular, vanilla JS)
- [x] Go HTTP server bindings with pluggable stores
- [x] Packed attestation (self + x5c)
- [x] Backup flags, userHandle verification, PRF extension
- [x] 31 shared cross-language test vectors
- [x] Ruby core library + Rails server binding
- [ ] Additional attestation formats (TPM, Android)

## Contributing

Strict TDD. To add a test case:

1. Update `tools/vecgen/main.go` and regenerate vectors
2. Run `./scripts/test-all.sh` — new vector should fail
3. Implement in each language until all pass

**New language:** Create `packages/core-{lang}/`, load `spec/vectors/*.json`, implement until all 31 vectors pass. Then write a thin server binding.

## License

MIT. Copyright 2025 Locke Identity Networks Inc.
