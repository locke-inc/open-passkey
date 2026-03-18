import { p1363ToDer } from "./der.js";
import { sha256, base64urlEncode, concatBytes, uint32BE, toArrayBuffer } from "./util.js";
import type { GetAssertionInput, GetAssertionResult, StoredCredential } from "./types.js";

export async function getAssertion(input: GetAssertionInput): Promise<GetAssertionResult> {
  const credential = input.credential;
  const newSignCount = credential.signCount + 1;

  // Build authenticatorData for assertion
  // flags: 0x05 = UP(0x01) | UV(0x04)
  // Backup flags: BE(0x08) | BS(0x10)
  const rpIdHash = await sha256(new TextEncoder().encode(input.rpId));
  const flagsByte = 0x01 | 0x04 | 0x08 | 0x10; // UP + UV + BE + BS
  const flags = new Uint8Array([flagsByte]);
  const signCountBytes = uint32BE(newSignCount);
  const authData = concatBytes(rpIdHash, flags, signCountBytes);

  // Build clientDataJSON
  const clientDataJSON = JSON.stringify({
    type: "webauthn.get",
    challenge: base64urlEncode(input.challenge),
    origin: input.origin,
    crossOrigin: false,
  });
  const clientDataJSONBytes = new TextEncoder().encode(clientDataJSON);

  // Sign: authData || SHA-256(clientDataJSON)
  const clientDataHash = await sha256(clientDataJSONBytes);
  const signatureBase = concatBytes(authData, clientDataHash);

  // Import private key and sign
  const privateKey = await globalThis.crypto.subtle.importKey(
    "pkcs8",
    toArrayBuffer(credential.privateKeyPkcs8),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );

  const p1363Sig = new Uint8Array(
    await globalThis.crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      toArrayBuffer(signatureBase),
    ),
  );

  // Convert P1363 to DER for WebAuthn
  const derSig = p1363ToDer(p1363Sig);

  const now = new Date().toISOString();
  const updatedCredential: StoredCredential = {
    ...credential,
    signCount: newSignCount,
    lastUsedAt: now,
  };

  return {
    response: {
      authenticatorData: base64urlEncode(authData),
      clientDataJSON: base64urlEncode(clientDataJSONBytes),
      signature: base64urlEncode(derSig),
      userHandle: base64urlEncode(credential.userId),
    },
    updatedCredential,
  };
}
