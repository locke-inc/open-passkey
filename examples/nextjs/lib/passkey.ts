import { createPasskeyHandlers, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/nextjs";

export const handlers = createPasskeyHandlers({
  rpId: "localhost",
  rpDisplayName: "Open Passkey Next.js Example",
  origin: "http://localhost:3004",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});
