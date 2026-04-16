# OpenPasskey.Core

Core WebAuthn/FIDO2 protocol verification library for .NET. Handles attestation parsing, signature verification, and client data validation with post-quantum algorithm support.

## Install

```bash
dotnet add package OpenPasskey.Core
```

## Usage

### Registration

```csharp
using OpenPasskey.Core;

var input = new RegistrationInput
{
    AttestationObject = attestationObjectBase64url,
    ClientDataJson = clientDataJsonBase64url,
    ExpectedChallenge = challengeBase64url,
    ExpectedOrigin = "https://example.com",
    RpId = "example.com",
    RequireUserVerification = true
};

RegistrationResult result = WebAuthn.VerifyRegistration(input);
// result.CredentialId, result.PublicKeyCose, result.SignCount
```

### Authentication

```csharp
var input = new AuthenticationInput
{
    AuthenticatorData = authDataBase64url,
    ClientDataJson = clientDataJsonBase64url,
    Signature = signatureBase64url,
    ExpectedChallenge = challengeBase64url,
    ExpectedOrigin = "https://example.com",
    RpId = "example.com",
    StoredPublicKeyCose = storedPublicKeyBase64url,
    StoredSignCount = 0,
    RequireUserVerification = true
};

AuthenticationResult result = WebAuthn.VerifyAuthentication(input);
// result.SignCount, result.BackupEligible, result.BackupState
```

### Error Handling

All verification failures throw `WebAuthnException` with a machine-readable error code:

```csharp
try
{
    WebAuthn.VerifyRegistration(input);
}
catch (WebAuthnException ex)
{
    Console.WriteLine(ex.Code); // e.g. "signature_invalid", "rp_id_mismatch"
}
```

## Algorithms

| Algorithm | COSE alg | Notes |
|-----------|----------|-------|
| ES256 (ECDSA P-256) | -7 | Classical, all browsers |
| ML-DSA-65 | -49 | Post-quantum, FIPS 204 |
| ML-DSA-65-ES256 | -52 | Composite hybrid PQ |

## Attestation Formats

- `none` -- no attestation
- `packed` -- self-attestation and full x5c chain

## Dependencies

- PeterO.Cbor (CBOR decoding)
- BouncyCastle.Cryptography (ML-DSA-65, ECDSA)

## Test

```bash
dotnet test
```

Tests run against the shared test vectors in `spec/vectors/`.

## Related Packages

- [server-aspnet](../server-aspnet) -- ASP.NET Core integration using this library

## License

MIT
