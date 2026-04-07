import { describe, it, expect } from "vitest";
import { Passkey } from "../passkey.js";
import { MemoryChallengeStore, MemoryCredentialStore } from "../stores.js";
import { createSessionToken } from "../session.js";
import type { SessionConfig } from "../session.js";

const SECRET = "a]Vv3X!kP9#mW2$nQ7@rT5&jY0^uL8*dF";

function makePasskey(session?: SessionConfig) {
  return new Passkey({
    rpId: "example.com",
    rpDisplayName: "Example",
    origin: "https://example.com",
    challengeStore: new MemoryChallengeStore(),
    credentialStore: new MemoryCredentialStore(),
    session,
  });
}

describe("Passkey with session (unit, no HTTP)", () => {
  it("getSessionConfig returns config when session is configured", () => {
    const p = makePasskey({ secret: SECRET });
    expect(p.getSessionConfig()).toBeDefined();
    expect(p.getSessionConfig()!.secret).toBe(SECRET);
  });

  it("getSessionConfig returns undefined when session is not configured", () => {
    const p = makePasskey();
    expect(p.getSessionConfig()).toBeUndefined();
  });

  it("getSessionTokenData validates token and returns SessionTokenData", () => {
    const p = makePasskey({ secret: SECRET });
    const token = createSessionToken("user-1", { secret: SECRET });
    const data = p.getSessionTokenData(token);
    expect(data.userId).toBe("user-1");
    expect(data.expiresAt).toBeGreaterThan(Date.now());
  });

  it("getSessionTokenData throws for invalid token", () => {
    const p = makePasskey({ secret: SECRET });
    expect(() => p.getSessionTokenData("bad:token:sig")).toThrow();
  });

  it("throws when session is not configured and getSessionTokenData is called", () => {
    const p = makePasskey();
    expect(() => p.getSessionTokenData("any")).toThrow("session is not configured");
  });
});
