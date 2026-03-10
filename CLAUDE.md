# CLAUDE.md — open-passkey

Development reference for Claude Code when working in this repository.

## Project Overview

open-passkey is an open-source library for effortlessly implementing passkey (WebAuthn/FIDO2) authentication in any app. The architecture strictly separates the **Core Protocol** (raw WebAuthn cryptography and verification) from **Framework Bindings** (Go HTTP handlers, Angular components, React hooks, etc.).

## Monorepo Structure

```
open-passkey/
├── spec/                    # Language-agnostic test vectors and schemas
│   ├── vectors/             # JSON test vectors (registration, authentication)
│   └── schema/              # JSON Schema definitions for vector format
├── packages/
│   ├── core-go/             # Go: Core WebAuthn protocol library (zero framework deps)
│   │   └── webauthn/        # Registration + authentication verification
│   ├── server-go/           # Go: HTTP handler bindings (Gin, net/http)
│   ├── core-ts/             # TypeScript: Core WebAuthn protocol library
│   └── angular/             # Angular: Headless components + PasskeyService
│       └── src/lib/         # Config, service, register/login components
└── tools/
    └── vecgen/              # Go tool to generate spec/vectors/ JSON files
```

## Key Architectural Decisions

- **Shared test vectors**: `spec/vectors/*.json` contains protocol-level test cases that every language implementation loads and runs against. This is the cross-language contract.
- **Isolated framework tests**: Framework bindings (HTTP handlers, UI components) have their own idiomatic test suites.
- **Minimal dependencies**: `core-go` should only depend on Go stdlib + `fxamacker/cbor/v2` for CBOR decoding.
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

### Run angular tests (isolated component/service tests)
```bash
cd packages/angular
npm test
```

### Run all tests
```bash
cd packages/core-go && go test ./... && cd ../server-go && go test ./... && cd ../core-ts && npm test && cd ../angular && npm test
```

## Terminology

- **Registration ceremony** = `navigator.credentials.create()` — creating a new passkey
- **Authentication ceremony** = `navigator.credentials.get()` — signing in with a passkey
- **RP** = Relying Party (the website/app)
- **Attestation** = Proof of authenticator identity during registration
- **Assertion** = Proof of credential ownership during authentication

## CBOR Library

We use `github.com/fxamacker/cbor/v2` — the most widely adopted Go CBOR library (used by Kubernetes, Cilium). Its only transitive dependency is `x448/float16`. No other third-party dependencies should be added to core-go without discussion.

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
- [x] Repository scaffolding and monorepo structure
- [x] Shared test vector generation tooling (`tools/vecgen/`)
- [x] 10 test vectors: 5 registration + 5 authentication ceremonies
- [x] `core-go`: `webauthn.VerifyRegistration()` + `webauthn.VerifyAuthentication()` — all 10 spec vectors passing
- [x] `server-go`: HTTP handlers (`BeginRegistration`, `FinishRegistration`, `BeginAuthentication`, `FinishAuthentication`)
- [x] `server-go`: `ChallengeStore` interface + `MemoryChallengeStore` (single-use, time-limited)
- [x] `server-go`: `CredentialStore` interface + `MemoryCredentialStore`
- [x] `server-go`: Config validation, challenge generation, discoverable credentials support
- [x] 16 isolated httptest-based tests for server-go (all passing)
- [x] `core-ts`: TypeScript port — `verifyRegistration()` + `verifyAuthentication()` — all 10 spec vectors passing
- [x] `core-ts`: Uses Node `crypto` for ECDSA verification, `cbor-x` for CBOR decoding
- [x] Cross-language vector architecture proven (Go + TypeScript pass same 10 vectors)
- [x] `angular`: Headless `PasskeyRegisterComponent` + `PasskeyLoginComponent` (content projection, signal-based)
- [x] `angular`: `PasskeyService` — injectable service wrapping browser WebAuthn API + HTTP calls to server-go
- [x] `angular`: `providePasskey()` provider function with configurable `baseUrl`
- [x] `angular`: 28 isolated Jest tests (4 util, 11 service, 6 register component, 7 login component)

### Next: Frontend Bindings
- [ ] `packages/react/` — React hooks and components

### Backlog
- [ ] `spec/schema/` — JSON Schema for vector file validation
- [ ] Additional attestation formats beyond "none" (packed, TPM, Android)
- [ ] Additional COSE algorithms beyond ES256 (RS256, EdDSA)
- [ ] User presence / user verification flag enforcement options
- [ ] Sign count rollback detection
