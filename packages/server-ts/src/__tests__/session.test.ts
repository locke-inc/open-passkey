import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import {
  createSessionToken,
  validateSessionToken,
  validateSessionConfig,
  buildSetCookieHeader,
  buildClearCookieHeader,
  parseCookieToken,
  type SessionConfig,
} from "../session.js";

const SECRET = "a]Vv3X!kP9#mW2$nQ7@rT5&jY0^uL8*dF"; // 34 chars

function makeConfig(overrides?: Partial<SessionConfig>): SessionConfig {
  return { secret: SECRET, ...overrides };
}

describe("Token Creation", () => {
  it("creates a token with format userId:expiresAt:signature", () => {
    const token = createSessionToken("user123", makeConfig());
    const parts = token.split(":");
    expect(parts.length).toBeGreaterThanOrEqual(3);
    // last part is signature, second-to-last is expiresAt (number)
    const lastColon = token.lastIndexOf(":");
    const secondLastColon = token.lastIndexOf(":", lastColon - 1);
    const expiresAtStr = token.slice(secondLastColon + 1, lastColon);
    expect(Number(expiresAtStr)).toBeGreaterThan(Date.now());
  });

  it("token expiresAt is in the future by the configured duration", () => {
    const duration = 60_000; // 1 min
    const before = Date.now();
    const token = createSessionToken("user123", makeConfig({ duration }));
    const after = Date.now();

    const lastColon = token.lastIndexOf(":");
    const secondLastColon = token.lastIndexOf(":", lastColon - 1);
    const expiresAt = Number(token.slice(secondLastColon + 1, lastColon));

    expect(expiresAt).toBeGreaterThanOrEqual(before + duration);
    expect(expiresAt).toBeLessThanOrEqual(after + duration);
  });

  it("uses default 24h duration when not specified", () => {
    const before = Date.now();
    const token = createSessionToken("user123", makeConfig());

    const lastColon = token.lastIndexOf(":");
    const secondLastColon = token.lastIndexOf(":", lastColon - 1);
    const expiresAt = Number(token.slice(secondLastColon + 1, lastColon));

    const diff = expiresAt - before;
    expect(diff).toBeGreaterThanOrEqual(86_400_000 - 100);
    expect(diff).toBeLessThanOrEqual(86_400_000 + 100);
  });

  it("handles userIds containing colons", () => {
    const token = createSessionToken("urn:user:123", makeConfig());
    const data = validateSessionToken(token, makeConfig());
    expect(data.userId).toBe("urn:user:123");
  });
});

describe("Token Validation", () => {
  it("validates a freshly created token and returns SessionTokenData", () => {
    const token = createSessionToken("user123", makeConfig());
    const data = validateSessionToken(token, makeConfig());
    expect(data.userId).toBe("user123");
    expect(data.expiresAt).toBeGreaterThan(Date.now());
  });

  it("rejects a token with tampered userId", () => {
    const token = createSessionToken("user123", makeConfig());
    const tampered = token.replace("user123", "evil");
    expect(() => validateSessionToken(tampered, makeConfig())).toThrow();
  });

  it("rejects a token with tampered expiresAt", () => {
    const token = createSessionToken("user123", makeConfig());
    const lastColon = token.lastIndexOf(":");
    const secondLastColon = token.lastIndexOf(":", lastColon - 1);
    const tampered =
      token.slice(0, secondLastColon + 1) + "9999999999999" + token.slice(lastColon);
    expect(() => validateSessionToken(tampered, makeConfig())).toThrow();
  });

  it("rejects a token with tampered signature", () => {
    const token = createSessionToken("user123", makeConfig());
    const tampered = token.slice(0, -1) + (token.endsWith("a") ? "b" : "a");
    expect(() => validateSessionToken(tampered, makeConfig())).toThrow();
  });

  it("rejects an expired token", async () => {
    const token = createSessionToken(
      "user123",
      makeConfig({ duration: 1, clockSkewGrace: 0 }),
    );
    await new Promise((r) => setTimeout(r, 10));
    expect(() =>
      validateSessionToken(token, makeConfig({ duration: 1, clockSkewGrace: 0 })),
    ).toThrow("session expired");
  });

  it("rejects a token signed with a different secret", () => {
    const token = createSessionToken("user123", makeConfig());
    const other = makeConfig({
      secret: "zZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZ",
    });
    expect(() => validateSessionToken(token, other)).toThrow();
  });

  it("rejects malformed tokens", () => {
    const config = makeConfig();
    expect(() => validateSessionToken("", config)).toThrow();
    expect(() => validateSessionToken("nocolons", config)).toThrow();
    expect(() => validateSessionToken("one:colon", config)).toThrow();
  });
});

describe("Clock Skew Grace", () => {
  it("accepts a token expired by 5 seconds (within default 10s grace)", async () => {
    const token = createSessionToken(
      "user123",
      makeConfig({ duration: 1 }),
    );
    await new Promise((r) => setTimeout(r, 10));
    // Token expired by ~10ms, default grace is 10s
    const data = validateSessionToken(token, makeConfig({ duration: 1 }));
    expect(data.userId).toBe("user123");
  });

  it("rejects a token expired by 15 seconds (beyond default 10s grace)", () => {
    // Create a token with expiresAt in the past by 15 seconds
    const config = makeConfig({ duration: 1, clockSkewGrace: 10_000 });
    const token = createSessionToken("user123", config);

    // Manually create a token that expired 15s ago
    const expiredAt = Date.now() - 15_000;
    const payload = `user123:${expiredAt}`;
    const sig = createHmac("sha256", SECRET).update(payload).digest("base64url");
    const expiredToken = `${payload}:${sig}`;

    expect(() => validateSessionToken(expiredToken, config)).toThrow("session expired");
  });

  it("respects custom clockSkewGrace config value", () => {
    const expiredAt = Date.now() - 5_000; // 5s ago
    const payload = `user123:${expiredAt}`;
    const sig = createHmac("sha256", SECRET).update(payload).digest("base64url");
    const token = `${payload}:${sig}`;

    // With 10s grace, should pass
    expect(() =>
      validateSessionToken(token, makeConfig({ clockSkewGrace: 10_000 })),
    ).not.toThrow();

    // With 1s grace, should fail
    expect(() =>
      validateSessionToken(token, makeConfig({ clockSkewGrace: 1_000 })),
    ).toThrow("session expired");
  });
});

describe("Cookie Header Building", () => {
  it("buildSetCookieHeader includes HttpOnly, Path, Max-Age, SameSite", () => {
    const header = buildSetCookieHeader("tok", makeConfig());
    expect(header).toContain("op_session=tok");
    expect(header).toContain("HttpOnly");
    expect(header).toContain("Path=/");
    expect(header).toContain("Max-Age=86400");
    expect(header).toContain("SameSite=Lax");
  });

  it("buildSetCookieHeader includes Secure when config.secure is true", () => {
    const header = buildSetCookieHeader("tok", makeConfig({ secure: true }));
    expect(header).toContain("Secure");
  });

  it("buildSetCookieHeader omits Secure when config.secure is false", () => {
    const header = buildSetCookieHeader("tok", makeConfig({ secure: false }));
    expect(header).not.toContain("Secure");
  });

  it("buildSetCookieHeader includes Domain when configured", () => {
    const header = buildSetCookieHeader("tok", makeConfig({ domain: "example.com" }));
    expect(header).toContain("Domain=example.com");
  });

  it("buildClearCookieHeader sets Max-Age=0", () => {
    const header = buildClearCookieHeader(makeConfig());
    expect(header).toContain("Max-Age=0");
    expect(header).toContain("op_session=");
    expect(header).toContain("HttpOnly");
  });
});

describe("Cookie Parsing", () => {
  it("parseCookieToken extracts token from Cookie header", () => {
    const token = parseCookieToken("op_session=abc123", makeConfig());
    expect(token).toBe("abc123");
  });

  it("parseCookieToken handles multiple cookies", () => {
    const token = parseCookieToken(
      "other=x; op_session=abc123; another=y",
      makeConfig(),
    );
    expect(token).toBe("abc123");
  });

  it("parseCookieToken returns null when cookie not found", () => {
    const token = parseCookieToken("other=x", makeConfig());
    expect(token).toBeNull();
  });

  it("parseCookieToken returns null for empty/undefined header", () => {
    expect(parseCookieToken(null, makeConfig())).toBeNull();
    expect(parseCookieToken(undefined, makeConfig())).toBeNull();
    expect(parseCookieToken("", makeConfig())).toBeNull();
  });
});

describe("Config Validation", () => {
  it("rejects secret shorter than 32 characters", () => {
    expect(() => validateSessionConfig({ secret: "short" })).toThrow();
  });

  it("accepts secret of exactly 32 characters", () => {
    expect(() =>
      validateSessionConfig({ secret: "a".repeat(32) }),
    ).not.toThrow();
  });
});
