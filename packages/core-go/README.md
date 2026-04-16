# core-go

Core WebAuthn/FIDO2 protocol verification library for Go. No HTTP, no sessions, no framework dependencies -- pure verification logic.

Supports classical (ES256), post-quantum (ML-DSA-65), and hybrid (ML-DSA-65-ES256 composite) signature algorithms. Verifies both registration and authentication ceremonies against the WebAuthn spec.

## Install

```bash
go get github.com/open-passkey/core-go
```

## Quick Start

### Verify a registration

```go
import "github.com/open-passkey/core-go/webauthn"

result, err := webauthn.VerifyRegistration(webauthn.RegistrationInput{
    RPID:              "example.com",
    ExpectedChallenge: challengeB64URL,
    ExpectedOrigin:    "https://example.com",
    ClientDataJSON:    credentialResponse.ClientDataJSON,
    AttestationObject: credentialResponse.AttestationObject,
})
if err != nil {
    log.Fatal(err)
}
// result.CredentialID, result.PublicKeyCOSE -- store these
```

### Verify an authentication

```go
result, err := webauthn.VerifyAuthentication(webauthn.AuthenticationInput{
    RPID:                "example.com",
    ExpectedChallenge:   challengeB64URL,
    ExpectedOrigin:      "https://example.com",
    StoredPublicKeyCOSE: storedCred.PublicKeyCOSE,
    StoredSignCount:     storedCred.SignCount,
    ClientDataJSON:      assertionResponse.ClientDataJSON,
    AuthenticatorData:   assertionResponse.AuthenticatorData,
    Signature:           assertionResponse.Signature,
})
if err != nil {
    log.Fatal(err)
}
// Update storedCred.SignCount = result.SignCount
```

## API

| Function | Returns | Description |
|----------|---------|-------------|
| `VerifyRegistration(input)` | `(*RegistrationResult, error)` | Verify a `navigator.credentials.create()` response |
| `VerifyAuthentication(input)` | `(*AuthenticationResult, error)` | Verify a `navigator.credentials.get()` response |

### Types

| Type | Key Fields |
|------|------------|
| `RegistrationInput` | RPID, ExpectedChallenge, ExpectedOrigin, ClientDataJSON, AttestationObject, RequireUserVerification |
| `RegistrationResult` | CredentialID, PublicKeyCOSE, SignCount, BackupEligible, BackupState, AttestationFormat, AttestationX5C |
| `AuthenticationInput` | RPID, ExpectedChallenge, ExpectedOrigin, StoredPublicKeyCOSE, StoredSignCount, ClientDataJSON, AuthenticatorData, Signature, RequireUserVerification |
| `AuthenticationResult` | SignCount, Flags, BackupEligible, BackupState |

### Errors

| Error | Meaning |
|-------|---------|
| `ErrTypeMismatch` | clientDataJSON type is not `webauthn.create` / `webauthn.get` |
| `ErrChallengeMismatch` | Challenge does not match expected value |
| `ErrOriginMismatch` | Origin does not match expected value |
| `ErrRPIDMismatch` | RP ID hash does not match |
| `ErrSignatureInvalid` | Cryptographic signature verification failed |
| `ErrUnsupportedAlg` | COSE algorithm not supported |

### Algorithm Constants

| Constant | COSE alg | Algorithm |
|----------|----------|-----------|
| `AlgES256` | -7 | ECDSA P-256 (classical) |
| `AlgMLDSA65` | -49 | ML-DSA-65 / FIPS 204 (post-quantum) |
| `AlgCompositeMLDSA65ES256` | -52 | ML-DSA-65 + ES256 hybrid (draft-ietf-jose-pq-composite-sigs) |

### Attestation

Supported formats: `none`, `packed` (self-attestation and full x5c chain).

## Test

```bash
go test ./webauthn/ -v
```

Tests run against shared JSON vectors in `spec/vectors/`.

## Dependencies

- [cloudflare/circl](https://github.com/cloudflare/circl) -- ML-DSA-65 (Dilithium3) signature verification
- [fxamacker/cbor/v2](https://github.com/fxamacker/cbor) -- CBOR decoding for COSE keys and attestation objects

## Related Packages

| Package | Description |
|---------|-------------|
| [server-go](../server-go) | HTTP handlers for passkey registration and authentication |
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK for passkey ceremonies |

## License

MIT
