# Changelog

All notable changes to this project will be documented in this file.

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
