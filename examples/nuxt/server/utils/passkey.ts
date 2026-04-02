import { createPasskeyHandlers, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/nuxt";

export const handlers = createPasskeyHandlers({
  rpId: "localhost",
  rpDisplayName: "Open Passkey Nuxt Example",
  origin: "http://localhost:3005",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});
