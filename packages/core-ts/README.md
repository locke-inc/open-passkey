# @open-passkey/core

Core WebAuthn/FIDO2 protocol verification library with post-quantum cryptography support.

This is the **Core Protocol** layer -- no HTTP handling, no framework bindings, no session management. It verifies registration and authentication ceremonies given raw WebAuthn structures. Use this if you're building your own server integration. For ready-made framework bindings, see [@open-passkey/express](https://www.npmjs.com/package/@open-passkey/express), [@open-passkey/nextjs](https://www.npmjs.com/package/@open-passkey/nextjs), etc.

## Install

```bash
npm install @open-passkey/core
```

## Supported Algorithms

| Algorithm | COSE alg | Notes |
|-----------|----------|-------|
| ES256 (ECDSA P-256) | -7 | Classical, all browsers |
| ML-DSA-65 (Dilithium3) | -49 | Post-quantum, FIPS 204 |
| ML-DSA-65-ES256 (composite) | -52 | Hybrid PQ, draft-ietf-jose-pq-composite-sigs |

## Usage

### Verify Registration

```typescript
import { verifyRegistration } from "@open-passkey/core";

const result = await verifyRegistration({
  rpId: "example.com",
  expectedChallenge: "abc123...",           // base64url
  expectedOrigin: "https://example.com",
  clientDataJSON: "eyJ0eXBlIjoi...",        // base64url
  attestationObject: "o2NmbXRk...",         // base64url
  requireUserVerification: true,            // optional, default false
});

// result: { credentialId, publicKeyCose, signCount, backupEligible, backupState, attestationFormat, ... }
```

### Verify Authentication

```typescript
import { verifyAuthentication } from "@open-passkey/core";

const result = await verifyAuthentication({
  rpId: "example.com",
  expectedChallenge: "xyz789...",           // base64url
  expectedOrigin: "https://example.com",
  storedPublicKeyCose: credentialPublicKey,  // Uint8Array (COSE key from registration)
  storedSignCount: 0,
  clientDataJSON: "eyJ0eXBlIjoi...",        // base64url
  authenticatorData: "SZYN5Y...",           // base64url
  signature: "MEUCIQD...",                  // base64url
  requireUserVerification: true,            // optional, default false
});

// result: { signCount, backupEligible, backupState }
```

### Error Handling

All verification errors extend `WebAuthnError` with specific error classes:

```typescript
import {
  WebAuthnError,
  ChallengeMismatchError,
  OriginMismatchError,
  RPIDMismatchError,
  SignatureInvalidError,
  UnsupportedAlgorithmError,
} from "@open-passkey/core";

try {
  await verifyRegistration(input);
} catch (err) {
  if (err instanceof SignatureInvalidError) {
    // handle invalid signature
  }
}
```

## API

### `verifyRegistration(input: RegistrationInput): Promise<RegistrationResult>`

Verifies a WebAuthn registration (attestation) ceremony. Supports `none` and `packed` (self-attestation + full x5c) attestation formats.

### `verifyAuthentication(input: AuthenticationInput): Promise<AuthenticationResult>`

Verifies a WebAuthn authentication (assertion) ceremony. Automatically dispatches to the correct signature verifier based on the COSE `alg` field in the stored key.

## Attestation Formats

- **none** -- no attestation statement
- **packed** -- self-attestation and full x5c certificate chain

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Framework-agnostic server handler logic |
| [@open-passkey/express](https://www.npmjs.com/package/@open-passkey/express) | Express.js middleware |
| [@open-passkey/nextjs](https://www.npmjs.com/package/@open-passkey/nextjs) | Next.js App Router handlers |
| [@open-passkey/fastify](https://www.npmjs.com/package/@open-passkey/fastify) | Fastify plugin |
| [@open-passkey/hono](https://www.npmjs.com/package/@open-passkey/hono) | Hono middleware |
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK |

## License

MIT
