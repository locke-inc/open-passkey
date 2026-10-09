# @open-passkey/authenticator

Software WebAuthn authenticator for testing and CI. Produces `attestationObject`, `clientDataJSON`, `authenticatorData`, and `signature` outputs -- the same structures a hardware authenticator would generate.

This is a **testing tool**, not a production library. Use it to write integration tests for your passkey server without needing a real browser or hardware authenticator.

## Install

```bash
npm install @open-passkey/authenticator --save-dev
```

## Usage

### Create a credential (registration)

```typescript
import { createCredential } from "@open-passkey/authenticator";

const result = await createCredential({
  rpId: "example.com",
  rpName: "My App",
  userId: new TextEncoder().encode("user-123"),
  userName: "alice@example.com",
  challenge: challengeBytes, // Uint8Array
  origin: "https://example.com",
  algorithms: [-7], // ES256
  ceremony: { userPresent: true, userVerified: false, backupEligible: true, backupState: true },
});

// result: {
//   credentialId, rawId, clientDataJSON, attestationObject,
//   publicKey, publicKeyCose, storedCredential
// }
```

### Get an assertion (authentication)

```typescript
import { getAssertion } from "@open-passkey/authenticator";

const result = await getAssertion({
  rpId: "example.com",
  challenge: challengeBytes,
  origin: "https://example.com",
  credential: storedCredential, // from createCredential
  ceremony: { userPresent: true, userVerified: false, backupEligible: true, backupState: true },
});

// result: {
//   credentialId, rawId, clientDataJSON,
//   authenticatorData, signature, userHandle
// }
```

Ceremony facts are required for every operation. They describe the simulated authenticator
ceremony; an RP request for `userVerification: "required"` does not establish verification.
Tests simulating verified authenticators must explicitly supply `userVerified: true`.
Missing presence, an unsatisfied verification requirement, impossible backup flags, and
assertions for a different credential RP ID are rejected. This is an API change for callers
that previously relied on hardcoded UP/UV flags.

## API

| Function | Description |
|----------|-------------|
| `createCredential(input)` | Simulates `navigator.credentials.create()` |
| `getAssertion(input)` | Simulates `navigator.credentials.get()` |

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/core](https://www.npmjs.com/package/@open-passkey/core) | Core protocol verification (verify what this generates) |
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Server handler logic |

## License

MIT
