# Changelog

All notable changes to this project will be documented in this file.

## [0.1.3] - 2026-04-14

### Added
- **Vault (E2E encrypted key-value store)**: Client-side AES-256-GCM encryption powered by WebAuthn PRF extension. `Vault` class in sdk-js with `setItem`, `getItem`, `removeItem`, `keys`. Key derived via HKDF-SHA-256 from PRF output, stored as non-extractable `CryptoKey` in IndexedDB
- **Vault key persistence**: `persistKey()`, `Vault.restore()`, and `Vault.clear()` for IndexedDB-backed key survival across page reloads
- **Bearer token auth**: SDK prefers `Authorization: Bearer` header when a session token is available, falls back to cookie-based `credentials: "include"`
- **Logout clears vault key**: `PasskeyClient.logout()` now nulls the PRF key and calls `Vault.clear()` to wipe the IndexedDB-persisted encryption key

### Fixed
- Python server config validation and pyproject.toml metadata
- CI test failures from version inconsistencies across packages
- Error messages improved across SDK

### Dependencies
- Bump actions/setup-dotnet 4 → 5, actions/cache 4 → 5
- Bump vitest 4.0.18 → 4.1.4 (sdk-js, authenticator-ts, core-ts)
- Bump pytest >=7.0 → >=9.0.3 (core-py)
- Bump @types/node 25.5.0 → 25.6.0 (core-ts)

## [0.1.2] - 2026-04-08

### Added
- README.md files for all TypeScript/JavaScript packages
- npm publish script (`scripts/publish.sh`) and version sync (`scripts/sync-versions.sh`)
- Angular Jest configuration fix

## [0.1.1] - 2026-04-05

### Added
- **Session support**: HMAC-SHA-256 stateless session cookies across all 6 server languages and all 18 framework bindings
  - Core: `session.ts/go/py/java/cs/rs` — token create/validate, cookie helpers, config validation (32+ char secret minimum, timing-safe comparison)
  - Server: session cookie set on `/login/finish`, new `GET /session` and `POST /logout` endpoints
  - Client: `getSession()` and `logout()` in sdk-js + React/Vue/Svelte/Solid/Angular session hooks
- Examples updated to include session configuration
- Frontend examples updated to use free Locke Gateway

### Changed
- Go version bumped to 1.25
- Vue example added
- Express E2E test now builds TypeScript before running
- liboqs pinned to main branch commit hash for reproducible core-py CI

## [0.1.0] - 2026-04-03

### Added
- Core protocol libraries for 6 languages: Go, TypeScript, Python, Java, .NET, Rust
- ES256 (ECDSA P-256), ML-DSA-65, and ML-DSA-65-ES256 composite signature verification
- 31 shared cross-language test vectors (13 registration + 12 ES256 auth + 6 hybrid ML-DSA-65-ES256 auth)
- 18 server framework bindings: Express, Fastify, Hono, NestJS, Next.js, Nuxt, SvelteKit, Remix, Astro, Go (stdlib/Gin/Echo/Fiber/Chi), Flask, FastAPI, Django, Spring Boot, ASP.NET, Axum
- Browser SDK (`@open-passkey/sdk`) with IIFE bundle for script tag usage
- Frontend framework SDKs: React, Vue, Svelte, Solid, Angular
- Software authenticator for testing (`@open-passkey/authenticator`)
- 22 working examples covering all framework bindings
- Attestation formats: `none` and `packed` (self-attestation + full x5c)
- Backup flags (BE/BS), PRF extension, userHandle cross-check, sign count rollback detection
- GitHub Actions CI with cross-language test matrix
- Dependabot configuration for all package ecosystems

### Security
- Post-quantum ready: ML-DSA-65 (FIPS 204) and ML-DSA-65-ES256 composite (draft-ietf-jose-pq-composite-sigs)
- All cryptographic operations use audited libraries: cloudflare/circl (Go), @noble/post-quantum (TS), liboqs (Python), BouncyCastle (Java), fips204 (Rust)
