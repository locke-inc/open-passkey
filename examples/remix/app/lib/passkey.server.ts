import { createPasskeyActions, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/remix";

export const actions = createPasskeyActions({
  rpId: "localhost",
  rpDisplayName: "Open Passkey Remix Example",
  origin: "http://localhost:3007",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
});
