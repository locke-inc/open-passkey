import { createPasskeyActions, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/remix";

export const actions = createPasskeyActions({
  rpId: "localhost",
  rpDisplayName: "Open Passkey Remix Example",
  origin: "http://localhost:3007",
  challengeStore: new MemoryChallengeStore(),
  credentialStore: new MemoryCredentialStore(),
  session: { secret: "remix-example-secret-must-be-32-chars!", secure: false },
});
