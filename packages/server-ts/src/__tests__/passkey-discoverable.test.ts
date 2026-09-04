import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@open-passkey/core", () => ({
  verifyAuthentication: vi.fn(),
  verifyRegistration: vi.fn(),
  COSE_ALG_ES256: -7,
  COSE_ALG_MLDSA65: -49,
  COSE_ALG_COMPOSITE_MLDSA65_ES256: -52,
}));

import { verifyAuthentication } from "@open-passkey/core";
import { Passkey } from "../passkey.js";
import { MemoryChallengeStore, MemoryCredentialStore } from "../stores.js";
import { base64urlEncode } from "../base64url.js";

const mockedVerify = vi.mocked(verifyAuthentication);

function fakeCredential(id = "AQ") {
  return {
    id,
    rawId: id,
    type: "public-key",
    response: {
      clientDataJSON: "Y2xpZW50RGF0YQ",
      authenticatorData: "YXV0aERhdGE",
      signature: "c2ln",
    },
  };
}

async function setup() {
  const challengeStore = new MemoryChallengeStore();
  const credentialStore = new MemoryCredentialStore();
  const passkey = new Passkey({
    rpId: "example.com",
    rpDisplayName: "Example",
    origin: "https://example.com",
    challengeStore,
    credentialStore,
  });
  await credentialStore.store({
    credentialId: new Uint8Array([1]),
    publicKeyCose: new Uint8Array([0]),
    signCount: 0,
    userId: "alice",
    prfSupported: false,
  });
  return { passkey, challengeStore };
}

beforeEach(() => {
  vi.resetAllMocks();
  mockedVerify.mockReturnValue({ signCount: 1 } as never);
});

describe("finishAuthentication — explicit challenge (discoverable flow)", () => {
  it("succeeds with explicit challenge and no userId", async () => {
    const { passkey, challengeStore } = await setup();
    await challengeStore.store("ch-abc", "ch-abc", 300_000);

    const resp = await passkey.finishAuthentication({
      challenge: "ch-abc",
      credential: fakeCredential(),
    });

    expect(resp.authenticated).toBe(true);
    expect(resp.userId).toBe("alice");
    expect(mockedVerify).toHaveBeenCalledOnce();
    expect(vi.mocked(mockedVerify).mock.calls[0][0]).toMatchObject({
      expectedChallenge: "ch-abc",
    });
  });

  it("400s for an unknown challenge key", async () => {
    const { passkey } = await setup();

    await expect(
      passkey.finishAuthentication({
        challenge: "no-such-challenge",
        credential: fakeCredential(),
      }),
    ).rejects.toThrow(
      expect.objectContaining({ statusCode: 400, message: "challenge not found or expired" }),
    );
    expect(mockedVerify).not.toHaveBeenCalled();
  });

  it("400s when neither userId nor challenge is provided", async () => {
    const { passkey } = await setup();

    await expect(
      passkey.finishAuthentication({ credential: fakeCredential() }),
    ).rejects.toThrow(
      expect.objectContaining({ statusCode: 400, message: "challenge not found or expired" }),
    );
    expect(mockedVerify).not.toHaveBeenCalled();
  });

  it("old-style challenge-as-userId still works (backward compat)", async () => {
    const { passkey, challengeStore } = await setup();
    await challengeStore.store("ch-abc", "ch-abc", 300_000);

    const resp = await passkey.finishAuthentication({
      userId: "ch-abc",
      credential: fakeCredential(),
    });

    expect(resp.authenticated).toBe(true);
    expect(resp.userId).toBe("alice");
  });

  it("userHandle mismatch still rejected as the owner gate", async () => {
    const { passkey, challengeStore } = await setup();
    await challengeStore.store("ch-abc", "ch-abc", 300_000);

    const cred = fakeCredential();
    cred.response = {
      ...cred.response,
      userHandle: base64urlEncode(new TextEncoder().encode("bob")),
    };

    await expect(
      passkey.finishAuthentication({ challenge: "ch-abc", credential: cred }),
    ).rejects.toThrow(
      expect.objectContaining({ statusCode: 400, message: "userHandle does not match credential owner" }),
    );
    expect(mockedVerify).not.toHaveBeenCalled();
  });
});
