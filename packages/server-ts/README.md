# @open-passkey/server

Framework-agnostic WebAuthn server handler logic with post-quantum cryptography support.

This package contains the shared `Passkey` class, credential/challenge stores, session management, and all ceremony orchestration. Framework-specific packages (Express, Fastify, Next.js, etc.) are thin wrappers around this. Use this directly if you need full control or are integrating with an unsupported framework.

## Install

```bash
npm install @open-passkey/server
```

## Usage

```typescript
import {
  Passkey,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/server";

const passkey = new Passkey({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});

// Registration ceremony
const regOptions = await passkey.beginRegistration({ userId, username });
const regResult = await passkey.finishRegistration({ userId, credential });

// Authentication ceremony
const authOptions = await passkey.beginAuthentication({ userId });
const authResult = await passkey.finishAuthentication({ userId, credential });
```

### With sessions

```typescript
const passkey = new Passkey({
  rpId: "example.com",
  rpName: "My App",
  origin: "https://example.com",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
  session: {
    secret: "your-32+-character-hmac-secret-here",
    duration: 86400000, // 24h in ms
  },
});
```

Session tokens are HMAC-SHA256 signed, stateless cookies. The `finishAuthentication` result will include a `sessionToken` string when sessions are configured.

### Custom stores

Implement `ChallengeStore` and `CredentialStore` interfaces for production use (e.g., backed by a database):

```typescript
import type { ChallengeStore, CredentialStore } from "@open-passkey/server";
```

## Supported Algorithms

| Algorithm | COSE alg | Notes |
|-----------|----------|-------|
| ES256 (ECDSA P-256) | -7 | Classical, all browsers |
| ML-DSA-65 (Dilithium3) | -49 | Post-quantum, FIPS 204 |
| ML-DSA-65-ES256 (composite) | -52 | Hybrid PQ |

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/core](https://www.npmjs.com/package/@open-passkey/core) | Core protocol verification |
| [@open-passkey/express](https://www.npmjs.com/package/@open-passkey/express) | Express middleware |
| [@open-passkey/fastify](https://www.npmjs.com/package/@open-passkey/fastify) | Fastify plugin |
| [@open-passkey/hono](https://www.npmjs.com/package/@open-passkey/hono) | Hono middleware |
| [@open-passkey/nextjs](https://www.npmjs.com/package/@open-passkey/nextjs) | Next.js handlers |
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK |

## License

MIT
