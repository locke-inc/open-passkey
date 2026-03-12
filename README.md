# open-passkey

An open-source library for adding passkey authentication to any app. Built on [WebAuthn](https://www.w3.org/TR/webauthn-3/) with hybrid post-quantum signature verification (ML-DSA-65-ES256) that works today in Go and TypeScript.

> **Status:** Production-ready for ES256 passkeys with `none` attestation. Post-quantum algorithms verified but awaiting browser support.

## Hybrid Post-Quantum Support

open-passkey implements **ML-DSA-65-ES256** hybrid composite signatures ([draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/)), combining a NIST-standardized post-quantum algorithm with classical ECDSA in a single credential. Both signature components must verify independently. If either is broken, the other still protects you.

| Algorithm | COSE alg | Status | Go | TS |
|-----------|----------|--------|----|----|
| **ML-DSA-65-ES256** (composite) | `-52` | IETF Draft | Yes | Yes |
| **ML-DSA-65** (PQ only) | `-49` | NIST FIPS 204 | Yes | Yes |
| **ES256** (ECDSA P-256) | `-7` | Generally Available | Yes | Yes |

**How it works:** During registration, the server advertises preferred algorithms in `pubKeyCredParams`. During authentication, the core libraries read the COSE `alg` field from the stored credential and dispatch to the correct verifier automatically. ES256, ML-DSA-65, or the composite ML-DSA-65-ES256 path. No application code changes needed.

> **Browser support note:** As of early 2026, no major browser authenticator produces ML-DSA-65 or composite signatures natively. Credentials use ES256 until platform support arrives. Both cores verify all three algorithms today so that when authenticators catch up, your deployment is already protected.

## Architecture

open-passkey separates concerns into two layers. The **core protocol** is pure WebAuthn/FIDO2 verification logic with no framework dependencies. **Framework bindings** are thin adapters that wire the core into specific frameworks. Adding passkey support to a new framework only requires writing an adapter, not reimplementing cryptography.

```
open-passkey/
├── spec/vectors/        # Shared JSON test vectors
├── packages/
│   ├── core-go/         # Go core protocol
│   ├── server-go/       # Go HTTP bindings
│   ├── core-ts/         # TypeScript core protocol
│   └── angular/         # Angular components
└── tools/vecgen/        # Test vector generation
```

## Packages

### core-go

Go core protocol. Registration and authentication ceremony verification. ES256, ML-DSA-65, ML-DSA-65-ES256 composite.

Dependencies: Go stdlib `crypto`, [`fxamacker/cbor`](https://github.com/fxamacker/cbor), [`cloudflare/circl`](https://github.com/cloudflare/circl).

25 spec vectors passing.

```go
import "github.com/locke-inc/open-passkey/packages/core-go/webauthn"

// Registration
result, err := webauthn.VerifyRegistration(webauthn.RegistrationInput{
    RPID:              "example.com",
    ExpectedChallenge: challengeB64URL,
    ExpectedOrigin:    "https://example.com",
    ClientDataJSON:    credential.Response.ClientDataJSON,
    AttestationObject: credential.Response.AttestationObject,
})
// result.CredentialID, result.PublicKeyCOSE -- store for future auth

// Authentication: dispatches to ES256, ML-DSA-65, or ML-DSA-65-ES256
result, err := webauthn.VerifyAuthentication(webauthn.AuthenticationInput{
    RPID:                "example.com",
    ExpectedChallenge:   challengeB64URL,
    ExpectedOrigin:      "https://example.com",
    StoredPublicKeyCOSE: storedKeyBytes,
    StoredSignCount:     storedCount,
    ClientDataJSON:      credential.Response.ClientDataJSON,
    AuthenticatorData:   credential.Response.AuthenticatorData,
    Signature:           credential.Response.Signature,
})
```

**Algorithm constants:**

```go
webauthn.AlgES256                  // -7  (ECDSA P-256)
webauthn.AlgMLDSA65                // -49 (ML-DSA-65 / Dilithium3)
webauthn.AlgCompositeMLDSA65ES256  // -52 (hybrid composite)
```

### server-go

Go HTTP bindings. Challenge management, 4 ceremony handlers, pluggable store interfaces. Works with any Go router. Defaults to hybrid ML-DSA-65-ES256 preferred, with ML-DSA-65 and ES256 as fallbacks in `pubKeyCredParams`.

28 tests passing.

```go
import "github.com/locke-inc/open-passkey/packages/server-go"

p, _ := passkey.New(passkey.Config{
    RPID:            "example.com",
    RPDisplayName:   "My App",
    Origin:          "https://example.com",
    ChallengeStore:  passkey.NewMemoryChallengeStore(),
    CredentialStore: myDBCredentialStore,
})

mux := http.NewServeMux()
mux.HandleFunc("POST /passkey/register/begin",  p.BeginRegistration)
mux.HandleFunc("POST /passkey/register/finish", p.FinishRegistration)
mux.HandleFunc("POST /passkey/login/begin",     p.BeginAuthentication)
mux.HandleFunc("POST /passkey/login/finish",    p.FinishAuthentication)
```

**Pluggable interfaces:** `ChallengeStore` (single-use challenge storage; in-memory default provided) and `CredentialStore` (credential persistence; you implement for your DB — must implement `Store`, `Get`, `GetByUser`, `Update`, `Delete`).

### core-ts

TypeScript core. Full parity with Go utilizing the same 25 spec vectors. ES256, ML-DSA-65, and composite verification.

Dependencies: Node `crypto`, [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum), `cbor-x`.

```typescript
import {
  verifyRegistration,
  verifyAuthentication,
  COSE_ALG_ES256,                    // -7
  COSE_ALG_MLDSA65,                  // -49
  COSE_ALG_COMPOSITE_MLDSA65_ES256,  // -52
} from "@open-passkey/core";
```

The API mirrors the Go core. Same `verifyRegistration` / `verifyAuthentication` functions, same automatic algorithm dispatch based on the stored COSE key.

### angular

Headless Angular components and injectable service. Content projection for custom UI. Handles WebAuthn ceremony and server communication.

28 tests passing.

```typescript
// app.config.ts
import { providePasskey } from "@open-passkey/angular";

export const appConfig = {
  providers: [
    provideHttpClient(),
    providePasskey({ baseUrl: "/passkey" }),
  ],
};
```

```html
<!-- Registration -->
<passkey-register [userId]="userId" [username]="username"
                  (registered)="onRegistered($event)"
                  (error)="onError($event)" #reg>
  <button (click)="reg.register()" [disabled]="reg.loading()">
    Register Passkey
  </button>
</passkey-register>

<!-- Authentication -->
<passkey-login [userId]="userId"
               (authenticated)="onAuthenticated($event)"
               (error)="onError($event)" #login>
  <button (click)="login.login()" [disabled]="login.loading()">
    Sign in with Passkey
  </button>
</passkey-login>
```

**Service API:**

```typescript
import { PasskeyService } from "@open-passkey/angular";

@Component({ ... })
class MyComponent {
  private passkey = inject(PasskeyService);

  register() {
    this.passkey.register(userId, username).subscribe(result => { ... });
  }
  login() {
    this.passkey.authenticate(userId).subscribe(result => { ... });
  }
}
```

The client passes through whatever algorithm the server and authenticator negotiate. No client-side changes needed for PQ support.

## Cross-Language Testing

Every implementation runs against the same JSON test vectors in `spec/vectors/`. These contain real WebAuthn payloads generated by a software authenticator, covering both happy paths and failure modes. When a bug is found in any language, a new vector is added and all implementations gain the test case automatically.

**Registration** (9 vectors):
- ES256 + none attestation
- RP ID mismatch
- Challenge mismatch
- Origin mismatch
- Wrong ceremony type
- User Presence (UP) flag missing
- User Verified (UV) flag missing (passes — UV optional by default)
- Packed attestation format rejected
- Token binding present rejected

**Authentication** (10 vectors):
- ES256 signature
- RP ID mismatch
- Challenge mismatch
- Tampered signature
- Wrong ceremony type
- User Presence (UP) flag missing
- User Verified (UV) flag missing (passes — UV optional by default)
- Sign count both zero (passes per spec)
- Sign count rollback detected
- Token binding "supported" (passes — only "present" rejected)

**Hybrid PQ** (6 vectors):
- ML-DSA-65-ES256 composite
- RP ID mismatch
- Challenge mismatch
- ML-DSA component tampered
- ECDSA component tampered
- Wrong ceremony type

```bash
# Go core
cd packages/core-go && go test ./... -v

# Go server
cd packages/server-go && go test ./... -v

# TypeScript core
cd packages/core-ts && npm test

# Angular
cd packages/angular && npm test
```

## Development

### Prerequisites

- Go 1.21+
- Node.js 18+ (for TypeScript packages)

### Generate test vectors

The vector generator uses a software authenticator to produce real WebAuthn payloads:

```bash
cd tools/vecgen
go run main.go -out ../../spec/vectors
```

## Roadmap

- [x] Go core: registration + authentication verification
- [x] Go HTTP server bindings: 4 handlers, pluggable stores
- [x] TypeScript core: same 25 spec vectors, full parity
- [x] Angular bindings: headless components, injectable service
- [x] Hybrid PQ: ML-DSA-65-ES256 composite in Go + TypeScript
- [x] 25 shared test vectors across 3 ceremonies
- [x] Sign count rollback detection
- [x] PRF extension support
- [x] User presence / user verification flag enforcement
- [x] Attestation format validation (`none` only; rejects unsupported formats)
- [x] Token binding handling
- [ ] React component bindings
- [ ] Additional attestation formats (packed, TPM, Android)
- [ ] Backup flags (BE/BS) enforcement options

## Contributing

Strict TDD. To add a new test case:

1. Add a vector to `spec/vectors/` (or update `tools/vecgen/main.go` and regenerate)
2. Run tests in all languages. The new vector should fail.
3. Implement the fix in each language.
4. All vectors pass = done.

**New language implementation:** Create `packages/core-{lang}/`, write a test runner that loads `spec/vectors/*.json`, implement until all 25 vectors pass.

## License

MIT. Copyright 2025 Locke Identity Networks Inc.
