import { createPasskeyEndpoints, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/astro";

export const endpoints = createPasskeyEndpoints({
  rpId: "localhost",
  rpDisplayName: "Open Passkey Astro Example",
  origin: "http://localhost:3008",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
  session: { secret: "astro-example-secret-must-be-32-chars!", secure: false },
});
