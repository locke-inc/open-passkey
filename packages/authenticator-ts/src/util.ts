const crypto = globalThis.crypto;

/** Extract the underlying ArrayBuffer from a Uint8Array, handling sliced views. */
export function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  // ArrayBuffer.prototype.slice always returns ArrayBuffer (not SharedArrayBuffer)
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(data)));
}

export function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let totalLen = 0;
  for (const arr of arrays) totalLen += arr.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function uint32BE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, n);
  return buf;
}

export function uint16BE(n: number): Uint8Array {
  const buf = new Uint8Array(2);
  new DataView(buf.buffer).setUint16(0, n);
  return buf;
}
