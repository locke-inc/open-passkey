import { createPasskeyHandlers, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/nextjs";

const globalForPasskey = globalThis as unknown as {
  passkeyHandlers?: ReturnType<typeof createPasskeyHandlers>;
};

export const handlers = globalForPasskey.passkeyHandlers ??= createPasskeyHandlers({
  rpId: "localhost",
  rpDisplayName: "Open Passkey Next.js Example",
  origin: "http://localhost:3004",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
  session: {
    secret: "nextjs-example-secret-must-be-32-chars!",
  },
});
