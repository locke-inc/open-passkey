# core-java

Core WebAuthn/FIDO2 protocol verification library for Java. Handles attestation parsing, signature verification, and client data validation with post-quantum algorithm support.

## Install

```xml
<dependency>
    <groupId>com.openpasskey</groupId>
    <artifactId>core-java</artifactId>
    <version>0.1.3</version>
</dependency>
```

## Usage

### Registration

```java
import com.openpasskey.core.WebAuthn;
import com.openpasskey.core.RegistrationInput;
import com.openpasskey.core.RegistrationResult;

var input = new RegistrationInput();
input.setAttestationObject(attestationObjectBase64url);
input.setClientDataJson(clientDataJsonBase64url);
input.setExpectedChallenge(challengeBase64url);
input.setExpectedOrigin("https://example.com");
input.setRpId("example.com");
input.setRequireUserVerification(true);

RegistrationResult result = WebAuthn.verifyRegistration(input);
// result.getCredentialId(), result.getPublicKeyCose(), result.getSignCount()
```

### Authentication

```java
import com.openpasskey.core.AuthenticationInput;
import com.openpasskey.core.AuthenticationResult;

var input = new AuthenticationInput();
input.setAuthenticatorData(authDataBase64url);
input.setClientDataJson(clientDataJsonBase64url);
input.setSignature(signatureBase64url);
input.setExpectedChallenge(challengeBase64url);
input.setExpectedOrigin("https://example.com");
input.setRpId("example.com");
input.setStoredPublicKeyCose(storedPublicKeyBase64url);
input.setStoredSignCount(0);
input.setRequireUserVerification(true);

AuthenticationResult result = WebAuthn.verifyAuthentication(input);
// result.getSignCount(), result.isBackupEligible(), result.isBackupState()
```

### Error Handling

All verification failures throw `WebAuthnException` with a machine-readable error code:

```java
try {
    WebAuthn.verifyRegistration(input);
} catch (WebAuthnException e) {
    System.out.println(e.getCode()); // e.g. "signature_invalid", "rp_id_mismatch"
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

- BouncyCastle (cryptography, ML-DSA-65)
- Jackson CBOR (CBOR decoding)

## Test

```bash
mvn test
```

## Related Packages

- [server-spring](../server-spring) -- Spring Boot integration using this library

## License

MIT
