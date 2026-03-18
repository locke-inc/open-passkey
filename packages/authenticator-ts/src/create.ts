import * as cborg from "cborg";
import { encodeES256PublicKey, ALG_ES256 } from "./cose.js";
import { sha256, base64urlEncode, randomBytes, concatBytes, uint32BE, uint16BE } from "./util.js";
import type { CreateCredentialInput, CreateCredentialResult, StoredCredential } from "./types.js";

const AAGUID = new Uint8Array(16); // 16 zero bytes for software authenticator

export async function createCredential(input: CreateCredentialInput): Promise<CreateCredentialResult> {
  // Only ES256 (-7) is supported
  if (!input.algorithms.includes(ALG_ES256)) {
    throw new Error("No supported algorithm found. Only ES256 (-7) is supported.");
  }

  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );

  // Export keys in formats we need
  const privateKeyPkcs8 = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
  );
  const publicKeySpki = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("spki", keyPair.publicKey),
  );
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", keyPair.publicKey);

  // Extract raw x, y coordinates from JWK
  const x = base64urlDecodeRaw(jwk.x!);
  const y = base64urlDecodeRaw(jwk.y!);

  // COSE-encoded public key
  const publicKeyCose = encodeES256PublicKey(x, y);

  // Generate random credential ID (32 bytes)
  const credentialId = randomBytes(32);

  // Build authenticatorData for registration
  // flags: 0x5D = UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10) | AT(0x40)
  const rpIdHash = await sha256(new TextEncoder().encode(input.rpId));
  const flags = new Uint8Array([0x5d]);
  const signCount = uint32BE(0);

  // Attested credential data: AAGUID(16) || credIdLen(2) || credId || COSEkey
  const credIdLen = uint16BE(credentialId.length);
  const attestedCredData = concatBytes(AAGUID, credIdLen, credentialId, publicKeyCose);
  const authData = concatBytes(rpIdHash, flags, signCount, attestedCredData);

  // Build clientDataJSON
  const clientDataJSON = JSON.stringify({
    type: "webauthn.create",
    challenge: base64urlEncode(input.challenge),
    origin: input.origin,
    crossOrigin: false,
  });
  const clientDataJSONBytes = new TextEncoder().encode(clientDataJSON);

  // Build attestationObject (fmt: "none")
  const attestationObject = cborg.encode(new Map<string, unknown>([
    ["fmt", "none"],
    ["attStmt", new Map()],
    ["authData", authData],
  ]));

  const now = new Date().toISOString();
  const credential: StoredCredential = {
    credentialId,
    rpId: input.rpId,
    rpName: input.rpName,
    userId: input.userId,
    userName: input.userName,
    privateKeyPkcs8,
    publicKeyCose,
    publicKeySpki,
    signCount: 0,
    createdAt: now,
    lastUsedAt: now,
    backupEligible: true,
    backupState: true,
  };

  return {
    credential,
    response: {
      attestationObject: base64urlEncode(attestationObject),
      clientDataJSON: base64urlEncode(clientDataJSONBytes),
    },
    credentialId: base64urlEncode(credentialId),
    publicKeyCose,
  };
}

function base64urlDecodeRaw(input: string): Uint8Array {
  let padded = input.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4 !== 0) padded += "=";
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
