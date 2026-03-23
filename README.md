# open-passkey

An open-source library for adding passkey authentication to any app. Built on [WebAuthn](https://www.w3.org/TR/webauthn-3/) with hybrid post-quantum signature verification (ML-DSA-65-ES256) that works today in Go and TypeScript.

> **Status:** Production-ready for ES256 passkeys. Post-quantum algorithms verified but awaiting browser support.

## Hybrid Post-Quantum Support

open-passkey implements **ML-DSA-65-ES256** hybrid composite signatures ([draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/)), combining a NIST-standardized post-quantum algorithm with classical ECDSA in a single credential. Both signature components must verify independently. If either is broken, the other still protects you.

| Algorithm | COSE alg | Status | Go | TS |
|-----------|----------|--------|----|----|
| **ML-DSA-65-ES256** (composite) | `-52` | IETF Draft | Yes | Yes |
| **ML-DSA-65** (PQ only) | `-49` | NIST FIPS 204 | Yes | Yes |
| **ES256** (ECDSA P-256) | `-7` | Generally Available | Yes | Yes |

During registration, the server advertises preferred algorithms in `pubKeyCredParams`. During authentication, the core libraries read the COSE `alg` field from the stored credential and dispatch to the correct verifier automatically. No application code changes needed when PQ support arrives in browsers.

## Architecture

```
open-passkey/
├── spec/vectors/           # Shared JSON test vectors (31 vectors, 3 ceremonies)
├── packages/
│   ├── core-go/            # Go core protocol
│   ├── server-go/          # Go HTTP bindings
│   ├── core-ts/            # TypeScript core protocol
│   ├── authenticator-ts/   # TypeScript software authenticator
│   └── angular/            # Angular components + service
└── tools/vecgen/           # Test vector generation
```

The **core protocol** is pure WebAuthn/FIDO2 verification logic with no framework dependencies. **Framework bindings** are thin adapters. Adding passkey support to a new framework only requires writing an adapter, not reimplementing cryptography.

## Packages

### core-go

Go core protocol. Registration and authentication verification with ES256, ML-DSA-65, and ML-DSA-65-ES256 composite.

Dependencies: Go stdlib `crypto`, [`fxamacker/cbor`](https://github.com/fxamacker/cbor), [`cloudflare/circl`](https://github.com/cloudflare/circl).

```go
import "github.com/locke-inc/open-passkey/packages/core-go/webauthn"

result, err := webauthn.VerifyRegistration(webauthn.RegistrationInput{
    RPID:              "example.com",
    ExpectedChallenge: challengeB64URL,
    ExpectedOrigin:    "https://example.com",
    ClientDataJSON:    credential.Response.ClientDataJSON,
    AttestationObject: credential.Response.AttestationObject,
})
// result.CredentialID, result.PublicKeyCOSE, result.BackupEligible, result.AttestationFormat

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
// result.SignCount, result.BackupEligible, result.BackupState
```

### server-go

Go HTTP bindings. Challenge management, 4 ceremony handlers, pluggable store interfaces. Works with any Go router.

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

Pluggable `ChallengeStore` and `CredentialStore` interfaces. In-memory defaults included for development. Discoverable credentials supported with `userHandle` verification.

### core-ts

TypeScript core. Full parity with Go — same 31 spec vectors. ES256, ML-DSA-65, and composite verification.

Dependencies: Node `crypto`, [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum), `cbor-x`.

```typescript
import { verifyRegistration, verifyAuthentication } from "@open-passkey/core";
```

Same API shape as Go. Automatic algorithm dispatch based on the stored COSE key.

### authenticator-ts

Software WebAuthn authenticator for credential creation and assertion. Useful for testing, CI pipelines, and environments without hardware authenticators. Produces outputs that verify against core-ts and core-go.

Dependencies: `cborg` (CBOR), Web Crypto API.

```typescript
import { createCredential, getAssertion } from "@open-passkey/authenticator";

// Create a passkey (registration)
const result = await createCredential({
  rpId: "example.com",
  rpName: "My App",
  userId: new Uint8Array([1, 2, 3, 4]),
  userName: "alice",
  challenge: crypto.getRandomValues(new Uint8Array(32)),
  origin: "https://example.com",
  algorithms: [-7], // ES256
});
// result.response.attestationObject, result.response.clientDataJSON, result.credential

// Authenticate with a stored credential (assertion)
const assertion = await getAssertion({
  rpId: "example.com",
  challenge: crypto.getRandomValues(new Uint8Array(32)),
  origin: "https://example.com",
  credential: result.credential,
});
// assertion.response.authenticatorData, assertion.response.signature, assertion.response.userHandle
```

Supports ES256 (ECDSA P-256). Generates `none` attestation, sets UP/UV/BE/BS flags, increments sign count, and converts signatures to DER format per the WebAuthn spec.

### angular

Headless Angular components and injectable service. Content projection for custom UI.

```typescript
import { providePasskey } from "@open-passkey/angular";

// In app.config.ts
providers: [provideHttpClient(), providePasskey({ baseUrl: "/passkey" })]
```

```html
<passkey-register [userId]="userId" [username]="username"
                  (registered)="onRegistered($event)" #reg>
  <button (click)="reg.register()" [disabled]="reg.loading()">Register Passkey</button>
</passkey-register>

<passkey-login [userId]="userId"
               (authenticated)="onAuthenticated($event)" #login>
  <button (click)="login.login()" [disabled]="login.loading()">Sign In</button>
</passkey-login>
```

## Features

- **Attestation:** `none` and `packed` (self-attestation + full x5c certificate chain)
- **Backup flags:** BE/BS exposed in results, spec conformance enforced (§6.3.3)
- **PRF extension:** Salt generation, per-credential evaluation, output passthrough
- **userHandle:** Cross-checked against credential owner in discoverable flow
- **Sign count:** Rollback detection per §7.2
- **Token binding:** `"present"` rejected, `"supported"` allowed

## Testing

31 shared test vectors across 3 ceremony files, verified in both Go and TypeScript:

```bash
./scripts/test-all.sh
```

| Package | Tests | Description |
|---------|-------|-------------|
| core-go | 31 vectors | Spec vector verification |
| core-ts | 31 vectors | Same vectors, TypeScript |
| server-go | 31 tests | HTTP handlers, stores, userHandle |
| authenticator-ts | 7 tests | Round-trip creation/assertion, DER encoding |
| angular | 37 tests | Components, service, PRF, userHandle |

## Development

**Prerequisites:** Go 1.21+, Node.js 18+

```bash
# Generate test vectors
cd tools/vecgen && go run main.go -out ../../spec/vectors

# Run all tests
./scripts/test-all.sh
```

## Roadmap

- [x] ES256 + ML-DSA-65 + ML-DSA-65-ES256 composite verification (Go + TypeScript)
- [x] Go HTTP server bindings with pluggable stores
- [x] Angular headless components + service
- [x] Packed attestation (self + x5c)
- [x] Backup flags, userHandle verification, PRF extension
- [x] 31 shared cross-language test vectors
- [ ] React hooks and components
- [ ] Additional attestation formats (TPM, Android)

## Contributing

Strict TDD. To add a test case:

1. Update `tools/vecgen/main.go` and regenerate vectors
2. Run `./scripts/test-all.sh` — new vector should fail
3. Implement in each language until all pass

**New language:** Create `packages/core-{lang}/`, load `spec/vectors/*.json`, implement until all 31 vectors pass.

## License

MIT. Copyright 2025 Locke Identity Networks Inc.
