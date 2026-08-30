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
  userId: "user-123",
  userName: "alice@example.com",
  challenge: challengeBytes, // Uint8Array
  origin: "https://example.com",
  algorithms: [-7], // ES256
  extensions: { credProps: true },
  ceremony: {
    userPresent: true,
    userVerified: true, // only after genuine verification
    backupEligible: true,
    backupState: true,
  },
});

// result: {
//   credentialId, rawId, clientDataJSON, attestationObject,
//   publicKey, publicKeyCose, storedCredential,
//   clientExtensionResults: { credProps: { rk: true } }
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
  ceremony: {
    userPresent: true,
    userVerified: false,
    backupEligible: true,
    backupState: true,
  },
});

// result: {
//   credentialId, rawId, clientDataJSON,
//   authenticatorData, signature, userHandle
// }
```

## API

| Function | Description |
|----------|-------------|
| `createCredential(input)` | Simulates `navigator.credentials.create()` |
| `getAssertion(input)` | Simulates `navigator.credentials.get()` |

Both functions require explicit `ceremony` facts. The authenticator never
infers user verification or backup flags from a WebAuthn preference. A
`userVerification: "required"` request fails unless `userVerified` is true.
Synced credential assertions always use `signCount: 0`. Cross-origin callers
must also provide `crossOrigin: true` and a distinct, trustworthy `topOrigin`.
RP IDs are checked against bundled ICANN and private Public Suffix List rules
without a ceremony-time network request. `credProps` is negotiated as a
client-only extension and therefore does not set the authenticator-data ED bit.

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/core](https://www.npmjs.com/package/@open-passkey/core) | Core protocol verification (verify what this generates) |
| [@open-passkey/server](https://www.npmjs.com/package/@open-passkey/server) | Server handler logic |

## License

MIT
