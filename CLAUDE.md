# CLAUDE.md — open-passkey

Development reference for Claude Code when working in this repository.

## Project Overview

open-passkey is an open-source, post-quantum-ready library for implementing passkey (WebAuthn/FIDO2) authentication. The architecture strictly separates the **Core Protocol** (raw WebAuthn cryptography and verification) from **Framework Bindings** (Go HTTP handlers, Angular components, React hooks, etc.).

## Monorepo Structure

```
open-passkey/
├── spec/                    # Language-agnostic test vectors and schemas
│   ├── vectors/             # JSON test vectors (registration, authentication)
│   └── schema/              # JSON Schema definitions for vector format
├── packages/
│   ├── core-go/             # Go: Core WebAuthn protocol library (ES256, ML-DSA-65, ML-DSA-65-ES256)
│   │   └── webauthn/        # Registration + authentication verification
│   ├── server-go/           # Go: HTTP handler bindings (Gin, net/http)
│   ├── core-ts/             # TypeScript: Core WebAuthn protocol library (ES256, ML-DSA-65, ML-DSA-65-ES256)
│   └── angular/             # Angular: Headless components + PasskeyService
│       └── src/lib/         # Config, service, register/login components
└── tools/
    └── vecgen/              # Go tool to generate spec/vectors/ JSON files
```

## Cryptographic Algorithms

### Supported
| Algorithm | COSE alg | COSE kty | Implementation | Notes |
|-----------|----------|----------|----------------|-------|
| ML-DSA-65-ES256 (composite) | -52 | 9 (Composite) | Go + TypeScript | Hybrid PQ, draft-ietf-jose-pq-composite-sigs |
| ML-DSA-65 (Dilithium3) | -49 | 8 (MLDSA) | Go + TypeScript | Post-quantum, FIPS 204 |
| ES256 (ECDSA P-256) | -7 | 2 (EC2) | Go + TypeScript | Classical, all browsers support |

### Algorithm Negotiation
`server-go` sends `pubKeyCredParams` with ML-DSA-65 first (preferred) and ES256 second (fallback). The authenticator picks the first algorithm it supports. During authentication, the core libraries read the COSE `alg` field from the stored key and dispatch to the correct verifier (ES256, ML-DSA-65, or ML-DSA-65-ES256 composite).

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
- **core-go dependencies**: Go stdlib `crypto` + `fxamacker/cbor/v2` (CBOR) + `cloudflare/circl` (ML-DSA-65).
- **core-ts dependencies**: Node `crypto` + `cbor-x` (CBOR) + `@noble/post-quantum` (ML-DSA-65). Import with `.js` extension: `from "@noble/post-quantum/ml-dsa.js"`.
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
- [x] Repository scaffolding and monorepo structure
- [x] Shared test vector generation tooling (`tools/vecgen/`)
- [x] 16 test vectors: 5 registration + 5 ES256 authentication + 6 hybrid ML-DSA-65-ES256 authentication
- [x] `core-go`: `webauthn.VerifyRegistration()` + `webauthn.VerifyAuthentication()` — all 16 spec vectors passing
- [x] `core-go`: ES256, ML-DSA-65, and ML-DSA-65-ES256 composite signature verification
- [x] `core-go`: Algorithm dispatch — reads COSE `alg` from stored key, verifies with correct algorithm
- [x] `server-go`: HTTP handlers (`BeginRegistration`, `FinishRegistration`, `BeginAuthentication`, `FinishAuthentication`)
- [x] `server-go`: `ChallengeStore` interface + `MemoryChallengeStore` (single-use, time-limited)
- [x] `server-go`: `CredentialStore` interface + `MemoryCredentialStore`
- [x] `server-go`: Config validation, challenge generation, discoverable credentials support
- [x] `server-go`: PQ-preferred `pubKeyCredParams` (ML-DSA-65 first, ES256 fallback)
- [x] 16 isolated httptest-based tests for server-go (all passing)
- [x] `core-ts`: TypeScript port — `verifyRegistration()` + `verifyAuthentication()` — all 16 spec vectors passing
- [x] `core-ts`: ES256 via Node `crypto`, ML-DSA-65 via `@noble/post-quantum`, composite ML-DSA-65-ES256
- [x] `core-ts`: COSE algorithm constants exported (`COSE_ALG_ES256`, `COSE_ALG_MLDSA65`, `COSE_ALG_COMPOSITE_MLDSA65_ES256`)
- [x] Cross-language vector architecture proven (Go + TypeScript pass same 16 vectors)
- [x] `angular`: Headless `PasskeyRegisterComponent` + `PasskeyLoginComponent` (content projection, signal-based)
- [x] `angular`: `PasskeyService` — injectable service wrapping browser WebAuthn API + HTTP calls to server-go
- [x] `angular`: `providePasskey()` provider function with configurable `baseUrl`
- [x] `angular`: 28 isolated Jest tests (4 util, 11 service, 6 register component, 7 login component)

### Next
- [ ] Hybrid-preferred algorithm negotiation in `server-go` (ML-DSA-65-ES256 as first `pubKeyCredParams` entry)
- [ ] `packages/react/` — React hooks and components

### Backlog
- [ ] `spec/schema/` — JSON Schema for vector file validation
- [ ] Additional attestation formats beyond "none" (packed, TPM, Android)
- [ ] User presence / user verification flag enforcement options
- [ ] Sign count rollback detection
