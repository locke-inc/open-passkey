import { describe, it, expect, vi, beforeEach } from "vitest";

// We need to mock fetch since sdk-js runs in browser context
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Import after mocking
const { PasskeyClient } = await import("../index.js");

describe("PasskeyClient session methods", () => {
  let client: InstanceType<typeof PasskeyClient>;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new PasskeyClient({ baseUrl: "https://example.com/passkey" });
  });

  describe("getSession", () => {
    it("calls GET {baseUrl}/session with credentials: include", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ userId: "user-1", authenticated: true }),
      });

      await client.getSession();

      expect(mockFetch).toHaveBeenCalledWith(
        "https://example.com/passkey/session",
        {
          credentials: "include",
        },
      );
    });

    it("returns { userId, authenticated: true } on 200", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ userId: "user-1", authenticated: true }),
      });

      const result = await client.getSession();
      expect(result).toEqual({ userId: "user-1", authenticated: true });
    });

    it("returns null on 401", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 401,
        json: () => Promise.resolve({ error: "no session" }),
      });

      const result = await client.getSession();
      expect(result).toBeNull();
    });

    it("throws on network error", async () => {
      mockFetch.mockRejectedValue(new Error("network error"));

      await expect(client.getSession()).rejects.toThrow("network error");
    });
  });

  describe("logout", () => {
    it("calls POST {baseUrl}/logout with credentials: include", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      await client.logout();

      expect(mockFetch).toHaveBeenCalledWith(
        "https://example.com/passkey/logout",
        {
          method: "POST",
          credentials: "include",
        },
      );
    });

    it("resolves on 200", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });
      await expect(client.logout()).resolves.toBeUndefined();
    });

    it("resolves on 401 (already logged out)", async () => {
      mockFetch.mockResolvedValue({ ok: false, status: 401 });
      await expect(client.logout()).resolves.toBeUndefined();
    });

    it("clears prfKey so vault() throws after logout", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });
      await client.logout();
      expect(() => client.vault()).toThrow("Vault requires PRF support");
    });
  });
});
