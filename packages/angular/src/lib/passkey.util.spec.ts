import { base64urlDecode, base64urlEncode } from "./passkey.util";

describe("base64url utilities", () => {
  it("should round-trip encode and decode", () => {
    const original = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const encoded = base64urlEncode(original.buffer);
    const decoded = new Uint8Array(base64urlDecode(encoded));
    expect(decoded).toEqual(original);
  });

  it("should produce URL-safe output with no padding", () => {
    // Bytes that produce +, /, and = in standard base64
    const bytes = new Uint8Array([251, 239, 190]); // standard base64: "++--"
    const encoded = base64urlEncode(bytes.buffer);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
  });

  it("should decode base64url with no padding", () => {
    // "SGVsbG8" is base64url for "Hello" (no padding)
    const decoded = new Uint8Array(base64urlDecode("SGVsbG8"));
    expect(Array.from(decoded)).toEqual([72, 101, 108, 108, 111]);
  });

  it("should handle empty input", () => {
    const encoded = base64urlEncode(new ArrayBuffer(0));
    expect(encoded).toBe("");
    const decoded = new Uint8Array(base64urlDecode(""));
    expect(decoded.length).toBe(0);
  });
});
