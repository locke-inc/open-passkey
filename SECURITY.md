# Security

## Threat Model

open-passkey is a cryptographic verification library for WebAuthn/FIDO2 ceremonies. This document defines what the library protects against and what is the caller's responsibility.

### In Scope

The library guarantees:

- **Correct cryptographic verification** of WebAuthn registration and authentication ceremonies for ES256, ML-DSA-65, and hybrid ML-DSA-65-ES256 composite signatures.
- **Both components of a composite signature must independently verify.** There is no code path where a single-component verification is sufficient.
- **Algorithm dispatch integrity.** The COSE key's `alg` field determines which verification path runs, and each decoder independently validates both `kty` and `alg`, preventing cross-algorithm confusion.
- **Challenge, origin, RP ID, and type verification** during both registration and authentication ceremonies.
- **Sign count rollback detection.** If the stored sign count is non-zero and the authenticator's reported count is not greater, authentication is rejected (detects cloned authenticators per WebAuthn spec section 7.2 step 21).
- **Cross-language consistency.** Go and TypeScript implementations produce identical results for identical inputs, verified by shared test vectors.

### Out of Scope (Caller Responsibility)

- **Secure storage of `publicKeyCOSE`.** The library treats the stored COSE key as trusted input from your database. If an attacker can modify stored keys, they can downgrade from composite (ML-DSA-65-ES256) to classical (ES256) verification. Protect credential store integrity with authenticated encryption or HMAC.
- **TLS enforcement.** The library does not verify that the origin uses HTTPS. WebAuthn requires HTTPS in production; enforce this at your web server layer.
- **Rate limiting.** The library does not throttle authentication attempts. Implement rate limiting in your application to prevent brute-force attacks.
- **Credential-to-user binding.** The library verifies that a signature is valid for a given public key, but does not enforce that a credential belongs to a specific user. That is the `CredentialStore` implementation's responsibility.
- **Session management.** Post-authentication token issuance and session handling are entirely the consumer's responsibility.
- **Request body limits.** The `server-go` HTTP handlers enforce a 128KB body limit. If you use `core-go` directly, enforce limits at your HTTP layer.
- **Error message filtering.** The `server-go` handlers return generic error messages to HTTP clients and log details server-side. If you use `core-go` directly, do not expose its error strings (e.g., `rp_id_mismatch`, `signature_invalid`) to end users, as they provide an oracle for attackers to refine forged credentials.
- **Panic recovery.** Add panic recovery middleware to your HTTP server. While the library handles malformed input gracefully, defense-in-depth dictates that unexpected panics should produce a generic 500 response rather than exposing stack traces.
- **CORS.** The `server-go` handlers do not set CORS headers. Configure CORS middleware appropriate to your deployment.

### Known Properties

- **ECDSA signature malleability.** For any valid ECDSA signature `(r, s)`, the signature `(r, n-s)` is also mathematically valid. Both Go's `crypto/ecdsa` and Node.js's `crypto` module accept high-S signatures. This is not exploitable in WebAuthn because signatures are verified and discarded (never stored, compared, or used as identifiers), and challenges are single-use.
- **ML-DSA-65 is non-malleable by design.** Both `cloudflare/circl` and `@noble/post-quantum` enforce FIPS 204's strict coefficient checks.

## Dependencies

Security-critical runtime dependencies:

| Package | Language | Purpose | Notes |
|---------|----------|---------|-------|
| `cloudflare/circl` | Go | ML-DSA-65 | Maintained by Cloudflare cryptography team |
| `fxamacker/cbor/v2` | Go | CBOR decoding | Extensively fuzz-tested, configured to reject duplicate map keys |
| `@noble/post-quantum` | TypeScript | ML-DSA-65 | By paulmillr (noble crypto suite). Pinned to exact version. |
| `cbor-x` | TypeScript | CBOR decoding | Pinned to exact version |

The library has no other runtime dependencies beyond language standard libraries (`crypto/ecdsa`, `crypto/sha256`, `node:crypto`).

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly by emailing connor@lockeidentity.com. Do not open a public GitHub issue for security vulnerabilities.
