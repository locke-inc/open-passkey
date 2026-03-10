# open-passkey Security Audit Plan

Red team analysis plan for the open-passkey library. Each section is a self-contained audit area with specific files to review, attack vectors to test, and what "fixed" looks like.

Run each section as an independent task. Read every file referenced before drawing conclusions.

---

## 1. Composite Signature Verification Logic

**Goal:** Confirm that the hybrid ML-DSA-65-ES256 path cannot be tricked into accepting a credential where only one component is valid.

**Files:**
- `packages/core-go/webauthn/webauthn.go` — `verifySignatureComposite()`, `decodeCompositePublicKey()`
- `packages/core-ts/src/authentication.ts` — `verifyCompositeSignature()`
- `spec/vectors/hybrid_authentication.json`

**Attack vectors:**
- **Component stripping:** Can an attacker submit only the ML-DSA-65 signature (dropping the ES256 portion) or vice versa? The 4-byte length prefix is attacker-controlled — verify that truncated or zero-length components cause rejection, not a pass.
- **Length prefix overflow:** What happens if the 4-byte ML-DSA sig length exceeds the total signature buffer? Check for integer overflow on 32-bit systems (Go `uint32` + 4 could wrap).
- **Length prefix pointing into ES256 portion:** If the length prefix claims a larger ML-DSA sig than actually present, the ES256 "sig" becomes a truncated or empty slice. Does verification still reject?
- **Empty signature components:** Pass `mldsaSigLen = 0` (so ML-DSA sig is empty, entire blob is treated as ES256). Does ML-DSA verification of an empty byte slice return false, or panic/error in a way that skips the check?
- **Cross-algorithm confusion:** Can a stored composite key (kty=9, alg=-52) be fed to the standalone ML-DSA-65 path, or vice versa? Confirm the dispatch switch is exclusive and the inner decoders reject wrong kty/alg combinations.

**What to verify:**
- Both Go and TypeScript reject every malformed case above with `signature_invalid`, not a panic or uncaught exception.
- There is no code path where only one component verifying is sufficient.

---

## 2. COSE Key Parsing and Algorithm Dispatch

**Goal:** Ensure an attacker cannot influence which verification path runs by manipulating the stored COSE key.

**Files:**
- `packages/core-go/webauthn/webauthn.go` — `identifyCOSEAlgorithm()`, all `decode*PublicKey()` functions
- `packages/core-ts/src/authentication.ts` — `identifyCOSEAlgorithm()`, COSE decoding blocks

**Attack vectors:**
- **Algorithm downgrade via COSE key manipulation:** If an attacker can modify the stored `publicKeyCOSE` (e.g., change alg from -52 to -7), they could potentially strip the PQ component. This is a storage-layer concern, but the library should document that `storedPublicKeyCOSE` must be treated as trusted input from your own database.
- **CBOR duplicate keys:** What happens if a COSE key CBOR map contains `alg` twice (e.g., `3: -7` and `3: -52`)? Does `fxamacker/cbor` or `cbor-x` use the first or last value? Could this cause the dispatcher to choose one algorithm while the decoder uses another?
- **Extra fields in COSE keys:** Confirm that unexpected fields in the CBOR map don't cause panics or alter behavior.
- **Negative/zero kty values:** Does passing `kty: 0` or `kty: -1` hit any unexpected code path?

**What to verify:**
- `identifyCOSEAlgorithm()` and the inner decoders always agree on which algorithm is in use.
- Invalid or ambiguous CBOR is rejected, not silently misinterpreted.

---

## 3. Signature Malleability

**Goal:** Confirm that signature malleability cannot be exploited.

**Files:**
- `packages/core-go/webauthn/webauthn.go` — `verifySignatureES256()`, `verifySignatureMLDSA65()`
- `packages/core-ts/src/authentication.ts` — `verifyES256Signature()`, `verifyMLDSA65Signature()`

**Attack vectors:**
- **ECDSA signature malleability:** For any valid ECDSA signature `(r, s)`, the signature `(r, n-s)` is also mathematically valid (where `n` is the curve order). Does `ecdsa.VerifyASN1` in Go reject high-S signatures? Does Node's `crypto.createVerify` reject them? If both accept high-S, a valid signature can be "re-signed" without the private key.
  - This matters if signatures are used as unique identifiers anywhere downstream (unlikely in WebAuthn, but worth documenting).
- **ASN.1 DER leniency:** Are non-canonical DER encodings of the same (r, s) values accepted? (e.g., extra leading zeros, BER instead of DER)
- **ML-DSA-65 signature malleability:** Check whether `circl` and `@noble/post-quantum` have any known malleability in ML-DSA verification. ML-DSA is designed to be non-malleable, but confirm both libraries enforce this.

**What to verify:**
- Document the malleability behavior of each library (even if "won't fix" — it should be known).
- If signatures are ever compared for equality (now or in future), malleability would be a bug.

---

## 4. ClientData and AuthenticatorData Parsing

**Goal:** Ensure the ceremony verification cannot be bypassed via malformed inputs.

**Files:**
- `packages/core-go/webauthn/webauthn.go` — `verifyClientData()`, `parseAuthenticatorData()`
- `packages/core-ts/src/clientdata.ts`, `packages/core-ts/src/authdata.ts`

**Attack vectors:**
- **JSON injection in clientDataJSON:** The `challenge` field is compared as a string. Can an attacker craft a clientDataJSON where the challenge appears to match due to JSON parsing quirks? (e.g., Unicode escapes, duplicate keys, trailing data after the closing brace)
- **Base64url padding variants:** Confirm that base64url decoding rejects standard base64 (with `+/=`) and doesn't silently accept padded input where unpadded is expected.
- **AuthenticatorData truncation:** What if `authData` is exactly 37 bytes (minimum) but the flags claim attested credential data is present (0x40 set)? Confirm this is caught.
- **AuthenticatorData extension data:** WebAuthn allows extensions after credential data. Confirm the parser doesn't read past the COSE key into extension bytes and misinterpret them.
- **RP ID hash timing:** `verifyRPIdHash()` in Go uses a byte-by-byte loop. Confirm this is constant-time (or that timing leakage of the RP ID hash is not a meaningful attack). TypeScript uses `constantTimeEqual()` — verify it's actually constant-time.
- **Origin comparison:** Is origin comparison case-sensitive? WebAuthn spec says origins should be compared as ASCII strings. Confirm no Unicode normalization is applied.

**What to verify:**
- Every malformed input produces a clean error, never a panic or uncaught exception.
- Challenge comparison is exact byte equality after base64url decoding, not susceptible to encoding tricks.

---

## 5. Test Vector Generator Integrity

**Goal:** Ensure the software authenticator in vecgen produces cryptographically correct payloads that actually exercise the verification code.

**Files:**
- `tools/vecgen/main.go` — all authenticator types and vector generation

**Attack vectors:**
- **Self-consistency:** The vecgen signs with its own keys and the verifier checks against those same keys. If vecgen has a bug (e.g., signing over the wrong data), the verifier could also have the same bug and both would "agree" on the wrong thing. Cross-check: take the raw values from a generated vector and manually verify the signature using a third-party tool (e.g., OpenSSL for ES256).
- **Tampering effectiveness:** The tampered-signature vectors flip bits at specific positions. Confirm these positions actually fall within the signature data (not the length prefix or padding). A tamper that hits padding bytes might not actually invalidate the signature.
- **CBOR determinism:** The Go CBOR encoder does not guarantee deterministic output for maps. The vecgen caches COSE key bytes to work around this. Verify that the cached bytes in authData match what's in `expected.publicKeyCose` for registration vectors.

**What to verify:**
- At least one "valid" vector should be independently verified using a tool outside this repo.
- All "invalid" vectors should be confirmed to fail for the stated reason, not an earlier check (e.g., a "signature_tampered" vector that actually fails on "rp_id_mismatch" means the tamper test isn't testing what it claims).

---

## 6. Dependency Supply Chain

**Goal:** Audit third-party dependencies for known vulnerabilities and appropriate trust level.

**Dependencies to audit:**

| Package | Used in | Purpose | Risk |
|---------|---------|---------|------|
| `cloudflare/circl` | core-go, vecgen | ML-DSA-65 | High — PQ crypto correctness |
| `fxamacker/cbor/v2` | core-go, vecgen | CBOR decode | Medium — parser bugs could cause misinterpretation |
| `@noble/post-quantum` | core-ts | ML-DSA-65 | High — PQ crypto correctness |
| `cbor-x` | core-ts | CBOR decode | Medium — same as above |

**What to check:**
- Run `go vuln check` on all three Go modules.
- Run `npm audit` on core-ts.
- Check that `circl` and `@noble/post-quantum` have been audited (both have — find and reference the audit reports).
- Pin exact dependency versions in go.sum and package-lock.json (already done by default, but verify no floating ranges in go.mod or package.json allow unexpected upgrades).
- Confirm `cbor-x` and `fxamacker/cbor` handle malicious CBOR (deeply nested structures, huge allocations) without DoS. Both are used to parse attacker-supplied attestation objects.

---

## 7. Error Oracle / Information Leakage

**Goal:** Confirm the library does not leak information that helps an attacker.

**Files:**
- All error types in `packages/core-go/webauthn/webauthn.go` and `packages/core-ts/src/errors.ts`
- HTTP handler responses in `packages/server-go/`

**Attack vectors:**
- **Error differentiation:** The library returns distinct errors for each failure mode (rp_id_mismatch, challenge_mismatch, signature_invalid, etc.). In a production deployment, these should NOT be returned verbatim to the client. Verify that `server-go` returns generic error responses to HTTP clients while logging specific errors server-side.
- **Timing oracles:** Does a signature verification failure take measurably less time than a success? For ES256, the comparison should be constant-time. For ML-DSA-65, check whether `circl` and `noble` perform constant-time verification.
- **Stack traces in HTTP responses:** Confirm `server-go` never returns Go panic stack traces or internal error messages in HTTP response bodies.

---

## 8. Server-Go HTTP Handler Security

**Goal:** Audit the HTTP layer for common web security issues.

**Files:**
- `packages/server-go/` — all handler files and tests

**Attack vectors:**
- **Challenge replay:** Can a challenge be used more than once? Verify `MemoryChallengeStore` deletes challenges after consumption (single-use).
- **Challenge expiry:** Do expired challenges get rejected? What's the TTL? Is it configurable?
- **Race conditions:** Can two concurrent `FinishRegistration` requests both consume the same challenge? Test with concurrent goroutines.
- **Request body size limits:** Is there a maximum request body size? A huge attestationObject or signature could cause memory exhaustion.
- **CORS and content-type:** Does the server enforce `Content-Type: application/json`? Does it set appropriate CORS headers, or leave that to the consumer?
- **User ID enumeration:** Do the `BeginAuthentication` / `FinishAuthentication` endpoints behave differently for existing vs. non-existing users? (timing, error messages)

---

## 9. Cross-Language Consistency

**Goal:** Confirm Go and TypeScript produce identical results for all edge cases, not just the happy path.

**Method:**
- For each vector in all three JSON files, verify both languages produce the exact same success/failure result with the exact same error code.
- Write a script that runs both test suites and diffs the results.
- Specifically check: does a signature that's valid in Go also validate in TypeScript, and vice versa? The composite signature format is defined by this library — if Go and TypeScript disagree on the framing, interop breaks.

**Edge cases to test:**
- Maximum-length credential IDs
- Zero sign count vs. maximum sign count (uint32 max)
- COSE keys with fields in different CBOR map ordering

---

## 10. Threat Model Documentation

**Goal:** Document what this library does and does not protect against.

The library should have a clear `SECURITY.md` that states:
- **In scope:** Cryptographic verification of WebAuthn ceremonies (the math is correct).
- **Out of scope / caller responsibility:**
  - Secure storage of `publicKeyCOSE` (if an attacker can modify stored keys, they can downgrade algorithms)
  - TLS enforcement (the library doesn't check that origin uses HTTPS, though WebAuthn requires it)
  - Rate limiting (the library doesn't throttle authentication attempts)
  - Credential binding (the library verifies signatures but doesn't enforce that a credential belongs to a specific user — that's the CredentialStore's job)
  - Token/session management after successful authentication

---

## Execution Order

Recommended priority (highest-impact first):

1. **Section 1** — Composite signature logic (new code, highest risk)
2. **Section 2** — COSE key parsing (determines which algorithm runs)
3. **Section 4** — ClientData/AuthenticatorData parsing (attacker-supplied input)
4. **Section 8** — HTTP handler security (network-facing)
5. **Section 5** — Vector generator integrity (ensures tests are meaningful)
6. **Section 3** — Signature malleability (lower risk for WebAuthn but worth documenting)
7. **Section 7** — Error oracles (defense in depth)
8. **Section 6** — Dependency audit (periodic)
9. **Section 9** — Cross-language consistency (correctness)
10. **Section 10** — Threat model documentation (ship blocker)
