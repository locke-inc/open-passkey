import { createPasskeyEndpoints, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/astro";

export const endpoints = createPasskeyEndpoints({
  rpId: "localhost",
  rpDisplayName: "Open Passkey Astro Example",
  origin: "http://localhost:3008",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});
