import { p1363ToDer } from "./der.js";
import { sha256, base64urlEncode, concatBytes, uint32BE, toArrayBuffer } from "./util.js";
import type { GetAssertionInput, GetAssertionResult, StoredCredential } from "./types.js";
import {
  authenticatorFlags,
  requireCeremonyFacts,
  requireRequestedUserVerification,
} from "./ceremony.js";
import { encodeCollectedClientData, validateCeremonyContext } from "./origin.js";

export async function getAssertion(input: GetAssertionInput): Promise<GetAssertionResult> {
  validateCeremonyContext(input.rpId, input.origin, input.topOrigin, input.crossOrigin);
  const credential = input.credential;
  if (credential.rpId !== input.rpId) {
    throw new Error("Credential RP ID does not match request");
  }
  const ceremony = requireCeremonyFacts(input.ceremony);
  requireRequestedUserVerification(input.userVerification, ceremony);

  // Build authenticatorData for assertion
  const rpIdHash = await sha256(new TextEncoder().encode(input.rpId));
  const flagsByte = authenticatorFlags(ceremony, false);
  const flags = new Uint8Array([flagsByte]);
  const signCountBytes = uint32BE(0);
  const authData = concatBytes(rpIdHash, flags, signCountBytes);

  // Build clientDataJSON
  const clientDataJSONBytes = encodeCollectedClientData(
    "webauthn.get",
    base64urlEncode(input.challenge),
    input.origin,
    input.topOrigin,
    input.crossOrigin,
  );

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
    signCount: 0,
    backupEligible: ceremony.backupEligible,
    backupState: ceremony.backupState,
    lastUsedAt: now,
  };

  return {
    response: {
      authenticatorData: base64urlEncode(authData),
      clientDataJSON: base64urlEncode(clientDataJSONBytes),
      signature: base64urlEncode(derSig),
      userHandle: credential.userId === null ? null : base64urlEncode(credential.userId),
    },
    updatedCredential,
  };
}
