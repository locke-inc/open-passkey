import { describe, it, expect } from "vitest";
import { Passkey, PasskeyError } from "../passkey.js";
import { MemoryChallengeStore, MemoryCredentialStore } from "../stores.js";
import type { PasskeyConfig, StoredCredential } from "../types.js";

function makePasskey(overrides?: Partial<PasskeyConfig>) {
  const credentialStore = overrides?.credentialStore ?? new MemoryCredentialStore();
  return {
    passkey: new Passkey({
      rpId: "example.com",
      rpDisplayName: "Example",
      origin: "https://example.com",
      challengeStore: new MemoryChallengeStore(),
      credentialStore,
      ...overrides,
    }),
    credentialStore,
  };
}

function fakeCred(userId: string, id: number = 1): StoredCredential {
  return {
    credentialId: new Uint8Array([id]),
    publicKeyCose: new Uint8Array([0]),
    signCount: 0,
    userId,
    prfSupported: false,
  };
}

describe("beginRegistration — multi-credential & excludeCredentials", () => {
  it("returns 409 when user has credentials (default config)", async () => {
    const store = new MemoryCredentialStore();
    await store.store(fakeCred("user-1"));
    const { passkey } = makePasskey({ credentialStore: store });

    await expect(
      passkey.beginRegistration({ userId: "user-1", username: "alice" }),
    ).rejects.toThrow(
      expect.objectContaining({ statusCode: 409, message: "user already registered" }),
    );
  });

  it("succeeds with allowMultipleCredentials: true when user has credentials", async () => {
    const store = new MemoryCredentialStore();
    await store.store(fakeCred("user-1"));
    const { passkey } = makePasskey({
      credentialStore: store,
      allowMultipleCredentials: true,
    });

    const resp = await passkey.beginRegistration({ userId: "user-1", username: "alice" });
    expect(resp.challenge).toBeDefined();
  });

  it("includes excludeCredentials when user has existing credentials", async () => {
    const store = new MemoryCredentialStore();
    await store.store(fakeCred("user-1", 1));
    await store.store(fakeCred("user-1", 2));
    const { passkey } = makePasskey({
      credentialStore: store,
      allowMultipleCredentials: true,
    });

    const resp = await passkey.beginRegistration({ userId: "user-1", username: "alice" });
    expect(resp.excludeCredentials).toBeDefined();
    expect(resp.excludeCredentials).toHaveLength(2);
    expect(resp.excludeCredentials![0].type).toBe("public-key");
    expect(resp.excludeCredentials![1].type).toBe("public-key");
  });

  it("does NOT include excludeCredentials for new users", async () => {
    const { passkey } = makePasskey();
    const resp = await passkey.beginRegistration({ userId: "new-user", username: "bob" });
    expect(resp.excludeCredentials).toBeUndefined();
  });
});
