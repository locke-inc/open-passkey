import { createPasskeyHandlers, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/sveltekit";

export const handlers = createPasskeyHandlers({
  rpId: "localhost",
  rpDisplayName: "Open Passkey SvelteKit Example",
  origin: "http://localhost:3006",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
  session: { secret: "sveltekit-example-secret-32-charss!", secure: false },
});
