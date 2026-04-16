import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock fetch
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Mock crypto.subtle
const mockImportKey = vi.fn();
const mockDeriveKey = vi.fn();
const mockEncrypt = vi.fn();
const mockDecrypt = vi.fn();
const mockSign = vi.fn();
const mockGetRandomValues = vi.fn();

const fakeEncKey = { type: "secret", algorithm: { name: "AES-GCM" } };
const fakeHmacKey = { type: "secret", algorithm: { name: "HMAC" } };

vi.stubGlobal("crypto", {
  subtle: {
    importKey: mockImportKey,
    deriveKey: mockDeriveKey,
    encrypt: mockEncrypt,
    decrypt: mockDecrypt,
    sign: mockSign,
  },
  getRandomValues: mockGetRandomValues,
});

// Import after mocking
const { PasskeyClient, Vault, base64urlEncode, base64urlDecode } = await import("../index.js");

// Predictable HMAC output for tests
const fakeHmacOutput = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer;
const expectedHashedKey = base64urlEncode(fakeHmacOutput);

describe("PasskeyClient.vault()", () => {
  let client: InstanceType<typeof PasskeyClient>;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new PasskeyClient({ baseUrl: "https://example.com/passkey" });
  });

  it("throws if authenticate() was not called", () => {
    expect(() => client.vault()).toThrow("Vault requires PRF support");
  });

  it("throws if PRF was not supported (no prfKey set)", () => {
    // Without calling authenticate() with PRF, prfKey remains null
    expect(() => client.vault()).toThrow("Vault requires PRF support");
  });
});

describe("Vault", () => {
  let vault: InstanceType<typeof Vault>;
  const fakePrfOutput = new ArrayBuffer(32);

  beforeEach(() => {
    vi.clearAllMocks();

    // Setup crypto mocks
    mockImportKey.mockResolvedValue(fakeEncKey);
    mockDeriveKey.mockImplementation((_algo: unknown, _km: unknown, keyType: unknown) => {
      // Return the right fake key based on what's being derived
      if ((keyType as { name: string }).name === "HMAC") return Promise.resolve(fakeHmacKey);
      return Promise.resolve(fakeEncKey);
    });
    mockSign.mockResolvedValue(fakeHmacOutput);
    mockGetRandomValues.mockImplementation((arr: Uint8Array) => {
      // Fill with predictable bytes for testing
      for (let i = 0; i < arr.length; i++) arr[i] = i;
      return arr;
    });

    vault = new Vault(fakePrfOutput, "https://example.com/passkey");
  });

  describe("key derivation", () => {
    it("imports PRF output as HKDF key material", async () => {
      mockEncrypt.mockResolvedValue(new ArrayBuffer(16));
      mockFetch.mockResolvedValue({ ok: true, status: 204 });

      await vault.setItem("k", "v");

      expect(mockImportKey).toHaveBeenCalledWith(
        "raw", fakePrfOutput, "HKDF", false, ["deriveKey"]
      );
    });

    it("derives AES-256-GCM encryption key via HKDF-SHA256", async () => {
      mockEncrypt.mockResolvedValue(new ArrayBuffer(16));
      mockFetch.mockResolvedValue({ ok: true, status: 204 });

      await vault.setItem("k", "v");

      expect(mockDeriveKey).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "HKDF",
          hash: "SHA-256",
          info: new TextEncoder().encode("aes-256-gcm"),
        }),
        fakeEncKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      );
    });

    it("derives HMAC-SHA256 key for key blinding via HKDF", async () => {
      mockEncrypt.mockResolvedValue(new ArrayBuffer(16));
      mockFetch.mockResolvedValue({ ok: true, status: 204 });

      await vault.setItem("k", "v");

      expect(mockDeriveKey).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "HKDF",
          hash: "SHA-256",
          info: new TextEncoder().encode("vault-key-hmac"),
        }),
        fakeEncKey,
        { name: "HMAC", hash: "SHA-256", length: 256 },
        false,
        ["sign"],
      );
    });
  });

  describe("setItem", () => {
    it("HMACs the key and calls PUT /vault/{hashedKey}", async () => {
      const ciphertextBuf = new Uint8Array([10, 20, 30, 40]).buffer;
      mockEncrypt.mockResolvedValue(ciphertextBuf);
      mockFetch.mockResolvedValue({ ok: true, status: 204 });

      await vault.setItem("my-key", "my-value");

      // Key should be HMAC'd, not plaintext
      expect(mockSign).toHaveBeenCalledWith(
        "HMAC",
        fakeHmacKey,
        new TextEncoder().encode("my-key"),
      );
      expect(mockFetch).toHaveBeenCalledWith(
        `https://example.com/passkey/vault/${expectedHashedKey}`,
        expect.objectContaining({
          method: "PUT",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
        }),
      );

      // Verify the body contains base64url-encoded iv || ciphertext
      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body).toHaveProperty("value");
      const decoded = new Uint8Array(base64urlDecode(body.value));
      expect(decoded.length).toBe(12 + 4); // 12 IV + 4 ciphertext
    });

    it("never sends plaintext key names to the server", async () => {
      mockEncrypt.mockResolvedValue(new ArrayBuffer(4));
      mockFetch.mockResolvedValue({ ok: true, status: 204 });

      await vault.setItem("secret-api-key", "val");

      const url = mockFetch.mock.calls[0][0] as string;
      expect(url).not.toContain("secret-api-key");
      expect(url).toContain(expectedHashedKey);
    });

    it("throws on non-ok response", async () => {
      mockEncrypt.mockResolvedValue(new ArrayBuffer(4));
      mockFetch.mockResolvedValue({
        ok: false,
        status: 409,
        json: () => Promise.resolve({ error: "vault item limit exceeded" }),
      });

      await expect(vault.setItem("k", "v")).rejects.toThrow("vault item limit exceeded");
    });
  });

  describe("getItem", () => {
    it("HMACs the key and calls GET /vault/{hashedKey}", async () => {
      // Build a fake packed blob: 12-byte IV + ciphertext
      const iv = new Uint8Array(12);
      const ct = new Uint8Array([99, 100, 101]);
      const packed = new Uint8Array(12 + ct.length);
      packed.set(iv, 0);
      packed.set(ct, 12);

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ value: base64urlEncode(packed.buffer) }),
      });

      const plainBuf = new TextEncoder().encode("decrypted-value").buffer;
      mockDecrypt.mockResolvedValue(plainBuf);

      const result = await vault.getItem("my-key");

      expect(mockSign).toHaveBeenCalledWith(
        "HMAC",
        fakeHmacKey,
        new TextEncoder().encode("my-key"),
      );
      expect(mockFetch).toHaveBeenCalledWith(
        `https://example.com/passkey/vault/${expectedHashedKey}`,
        { credentials: "include" },
      );
      expect(mockDecrypt).toHaveBeenCalled();
      expect(result).toBe("decrypted-value");
    });

    it("returns null on 404", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: "not found" }),
      });

      const result = await vault.getItem("nonexistent");
      expect(result).toBeNull();
    });

    it("throws on non-404 errors", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        json: () => Promise.resolve({ error: "server error" }),
      });

      await expect(vault.getItem("key")).rejects.toThrow("Failed to get vault item");
    });
  });

  describe("removeItem", () => {
    it("HMACs the key and calls DELETE /vault/{hashedKey}", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 204 });

      await vault.removeItem("my-key");

      expect(mockSign).toHaveBeenCalledWith(
        "HMAC",
        fakeHmacKey,
        new TextEncoder().encode("my-key"),
      );
      expect(mockFetch).toHaveBeenCalledWith(
        `https://example.com/passkey/vault/${expectedHashedKey}`,
        {
          method: "DELETE",
          credentials: "include",
        },
      );
    });
  });

  describe("deterministic key hashing", () => {
    it("same key always produces the same hashed key", async () => {
      mockEncrypt.mockResolvedValue(new ArrayBuffer(4));
      mockFetch.mockResolvedValue({ ok: true, status: 204 });

      await vault.setItem("same-key", "val1");
      await vault.setItem("same-key", "val2");

      const url1 = mockFetch.mock.calls[0][0] as string;
      const url2 = mockFetch.mock.calls[1][0] as string;
      expect(url1).toBe(url2);
    });
  });
});
