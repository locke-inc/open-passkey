# CLAUDE.md — open-passkey

Development reference for Claude Code when working in this repository.

## Project Overview

open-passkey is an open-source, post-quantum-ready library for implementing passkey (WebAuthn/FIDO2) authentication. The architecture strictly separates the **Core Protocol** (raw WebAuthn cryptography and verification) from **Framework Bindings** (Go HTTP handlers, Angular components, React hooks, etc.).

## Monorepo Structure

```
open-passkey/
├── spec/vectors/              # 31 shared JSON test vectors (registration, authentication)
├── packages/
│   ├── core-go/               # Go: Core protocol (ES256, ML-DSA-65, ML-DSA-65-ES256)
│   ├── core-ts/               # TypeScript: Core protocol
│   ├── core-py/               # Python: Core protocol
│   ├── core-java/             # Java: Core protocol
│   ├── core-dotnet/           # .NET: Core protocol
│   ├── core-rust/             # Rust: Core protocol
│   ├── server-go/             # Go: HTTP handler bindings (stdlib http.HandlerFunc)
│   ├── server-ts/             # Shared TS server logic (Passkey class)
│   ├── server-{express,fastify,hono,nestjs,nextjs,nuxt,sveltekit,remix,astro}/
│   ├── server-py/             # Shared Python server logic (PasskeyHandler class)
│   ├── server-flask/          # Flask thin wrapper (src-layout: open_passkey_flask/)
│   ├── server-fastapi/        # FastAPI thin wrapper (src-layout: open_passkey_fastapi/)
│   ├── server-django/         # Django thin wrapper (src-layout: open_passkey_django/)
│   ├── server-{spring,aspnet,axum}/
│   ├── sdk-js/                # Canonical browser SDK — PasskeyClient class + IIFE bundle
│   ├── react/                 # React hooks wrapping PasskeyClient
│   ├── vue/                   # Vue composables wrapping PasskeyClient
│   ├── svelte/                # Svelte stores wrapping PasskeyClient
│   ├── solid/                 # SolidJS primitives wrapping PasskeyClient
│   ├── angular/               # Angular components + service wrapping PasskeyClient
│   └── authenticator-ts/      # Software WebAuthn authenticator for testing
├── examples/                  # Working example for every framework (22 total)
│   └── shared/                # IIFE bundle (passkey.js) + style.css for server-only examples
└── tools/vecgen/              # Go tool to generate spec/vectors/ JSON files
```

## Cryptographic Algorithms

### Supported
| Algorithm | COSE alg | COSE kty | Implementation | Notes |
|-----------|----------|----------|----------------|-------|
| ML-DSA-65-ES256 (composite) | -52 | 9 (Composite) | Go, TS, Python, Java, .NET, Rust | Hybrid PQ, draft-ietf-jose-pq-composite-sigs |
| ML-DSA-65 (Dilithium3) | -49 | 8 (MLDSA) | Go, TS, Python, Java, .NET, Rust | Post-quantum, FIPS 204 |
| ES256 (ECDSA P-256) | -7 | 2 (EC2) | Go, TS, Python, Java, .NET, Rust | Classical, all browsers support |

### Algorithm Negotiation
All server bindings send `pubKeyCredParams` with ML-DSA-65-ES256 first (preferred), ML-DSA-65 second, and ES256 third (classical fallback). The authenticator picks the first algorithm it supports. During authentication, the core libraries read the COSE `alg` field from the stored key and dispatch to the correct verifier (ES256, ML-DSA-65, or ML-DSA-65-ES256 composite).

### ML-DSA-65 COSE Key Format
```
CBOR Map {
  1 (kty): 8        // KtyMLDSA
  3 (alg): -49      // AlgMLDSA65
  -1 (pub): bytes   // Raw ML-DSA-65 public key (1952 bytes)
}
```

### ML-DSA-65-ES256 Composite COSE Key Format
Per draft-ietf-jose-pq-composite-sigs, the composite public key concatenates components:
```
CBOR Map {
  1 (kty): 9        // KtyComposite
  3 (alg): -52      // AlgCompositeMLDSA65ES256
  -1 (pub): bytes   // ML-DSA-65 public key (1952 bytes) || ECDSA P-256 uncompressed point (65 bytes)
}
```

### ML-DSA-65-ES256 Composite Signature Format
The composite signature concatenates components with a length prefix:
- `4-byte big-endian ML-DSA sig length || ML-DSA-65 sig (3309 bytes) || ES256 DER sig`
- Both components sign over the same verification data: `authData || SHA256(clientDataJSON)`
- Both must verify independently for the composite to be valid

### ML-DSA-65 Signature Verification
Unlike ES256 (which hashes then signs), ML-DSA signs the message directly:
- Verification data: `authData || SHA256(clientDataJSON)` (same as ES256)
- ML-DSA-65 signs this data directly (no additional hashing)
- Go: `cloudflare/circl/sign/mldsa/mldsa65.Verify(pubKey, message, nil, signature)`
- TypeScript: `ml_dsa65.verify(signature, message, publicKey)` from `@noble/post-quantum/ml-dsa.js` (note: signature-first argument order)

## Key Architectural Decisions

- **Shared test vectors**: `spec/vectors/*.json` contains protocol-level test cases that every language implementation loads and runs against. This is the cross-language contract.
- **Isolated framework tests**: Framework bindings (HTTP handlers, UI components) have their own idiomatic test suites.
- **Single browser SDK**: `packages/sdk-js` (`PasskeyClient`) is the single source of truth for all browser-side WebAuthn logic (base64url encoding, credential creation/assertion, PRF extension handling, HTTP calls). All frontend framework packages (React, Vue, Svelte, Solid, Angular) wrap `PasskeyClient` — they add only framework-specific state management, never reimplementing ceremony logic.
- **IIFE bundle**: `sdk-js` builds an IIFE bundle (`dist/open-passkey.iife.js`) exposing `window.OpenPasskey.PasskeyClient`. Server-only examples (Go, Python, Rust, .NET, Java, Node.js) serve this via `examples/shared/passkey.js` for `<script>` tag usage.
- **Python server architecture**: `server-py` (`open_passkey_server`) contains shared business logic (`PasskeyHandler`, stores, config, base64url helpers). Framework packages (`server-flask`, `server-fastapi`, `server-django`) are thin wrappers that delegate to `PasskeyHandler`. Each uses src-layout for editable installs.
- **core-py CI / liboqs**: `liboqs-python` (the Python wrapper) requires a C `liboqs` shared library. The wrapper's auto-install is broken (tries to clone a non-existent tag), so CI builds liboqs from source pinned to a specific commit. When upgrading `liboqs-python` in `pyproject.toml`, update the commit SHA and cache key in `.github/workflows/ci.yml`.
- **core-go dependencies**: Go stdlib `crypto` + `fxamacker/cbor/v2` (CBOR) + `cloudflare/circl` (ML-DSA-65).
- **core-ts dependencies**: Node `crypto` + `cbor-x` (CBOR) + `@noble/post-quantum` (ML-DSA-65). Import with `.js` extension: `from "@noble/post-quantum/ml-dsa.js"`.
- **authenticator-ts role**: Software authenticator for testing/CI. Produces `attestationObject`, `clientDataJSON`, `authenticatorData`, and `signature` outputs. Not a core protocol library — it *generates* WebAuthn responses rather than *verifying* them.
- **TDD workflow**: Write/update vectors first, then implement until tests pass.

## Commands

### Generate test vectors
```bash
cd tools/vecgen
go run main.go -out ../../spec/vectors
```

### Run core-go tests (shared vector tests)
```bash
cd packages/core-go
go test ./webauthn/ -v
```

### Run server-go tests (HTTP handler tests)
```bash
cd packages/server-go
go test ./... -v
```

### Run core-ts tests (shared vector tests)
```bash
cd packages/core-ts
npm test
```

### Run authenticator-ts tests (round-trip tests)
```bash
cd packages/authenticator-ts
npm test
```

### Run angular tests (isolated component/service tests)
```bash
cd packages/angular
npm test
```

### Build sdk-js (ESM + IIFE bundle)
```bash
cd packages/sdk-js
npm run build
# Produces dist/index.js (ESM) and dist/open-passkey.iife.js (IIFE)
```

### Run all tests
```bash
./scripts/test-all.sh
```

## Terminology

- **Registration ceremony** = `navigator.credentials.create()` — creating a new passkey
- **Authentication ceremony** = `navigator.credentials.get()` — signing in with a passkey
- **RP** = Relying Party (the website/app)
- **Attestation** = Proof of authenticator identity during registration
- **Assertion** = Proof of credential ownership during authentication
- **ML-DSA** = Module-Lattice Digital Signature Algorithm (FIPS 204, formerly Dilithium)
- **ML-DSA-65-ES256** = Composite hybrid algorithm combining ML-DSA-65 + ECDSA P-256 (draft-ietf-jose-pq-composite-sigs, COSE alg -52)

## Test Vector Format

Vectors in `spec/vectors/` follow this structure:
- `name`: Machine-readable test case identifier (e.g., `valid_registration_none_attestation`)
- `description`: Human-readable explanation
- `input`: All fields needed to call the verifier (rpId, challenge, origin, credential response)
- `expected.success`: Whether verification should pass
- `expected.error`: Error code string for failure cases (e.g., `rp_id_mismatch`, `challenge_mismatch`, `signature_invalid`)

All binary data in vectors is base64url-encoded (no padding).

## Current Status / TODOs

### Completed
- [x] 31 shared test vectors (13 registration + 12 ES256 auth + 6 hybrid ML-DSA-65-ES256 auth)
- [x] Core protocol libraries: Go, TypeScript, Python, Java, .NET, Rust — all 31 vectors passing
- [x] ES256, ML-DSA-65, and ML-DSA-65-ES256 composite signature verification in all 6 languages
- [x] 18 server packages covering 20 frameworks (9 TS + server-ts, server-go for 5 Go frameworks, 3 Python + server-py, Spring, ASP.NET, Axum)
- [x] `server-go`: HTTP handlers, pluggable stores, config validation, discoverable credentials, userHandle verification
- [x] Python server packages: src-layout refactor (`open_passkey_flask/`, `open_passkey_fastapi/`, `open_passkey_django/`), editable installs working
- [x] `sdk-js`: `PasskeyClient` class — single source of truth for browser-side WebAuthn logic
- [x] `sdk-js`: IIFE bundle (`dist/open-passkey.iife.js`) for `<script>` tag usage
- [x] All frontend SDKs wrap `PasskeyClient`: React, Vue, Svelte, Solid, Angular
- [x] `angular`: Headless components (content projection, signal-based), thin service wrapping PasskeyClient, 19 Jest tests
- [x] `authenticator-ts`: Software authenticator for testing — 7 Vitest tests
- [x] 22 working examples (Go examples use thin adapter wrappers over server-go) (all use `@open-passkey/sdk` for client-side logic)
- [x] Attestation: `none` and `packed` (self-attestation + full x5c)
- [x] Backup flags (BE/BS), PRF extension, userHandle cross-check, sign count rollback detection

### Backlog
- [ ] Ruby + PHP core libraries
- [ ] Rails + Laravel server bindings
- [ ] `spec/schema/` — JSON Schema for vector file validation
- [ ] Additional attestation formats (TPM, Android)
- [ ] Backup flags enforcement policies (RequireSingleDevice, RequireBackupEligible)
