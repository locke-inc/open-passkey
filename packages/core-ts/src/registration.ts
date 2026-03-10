import { decode } from "cbor-x";
import { base64urlDecode } from "./util.js";
import { verifyClientData } from "./clientdata.js";
import { parseAuthenticatorData, verifyRPIdHash } from "./authdata.js";
import type { RegistrationInput, RegistrationResult } from "./types.js";

export function verifyRegistration(
  input: RegistrationInput,
): RegistrationResult {
  verifyClientData(
    input.clientDataJSON,
    "webauthn.create",
    input.expectedChallenge,
    input.expectedOrigin,
  );

  // Decode CBOR attestation object
  const attObjBytes = base64urlDecode(input.attestationObject);
  const attObj = decode(attObjBytes);
  const authData: Uint8Array = attObj.authData;

  const parsed = parseAuthenticatorData(authData, true);

  verifyRPIdHash(parsed.rpIdHash, input.rpId);

  return {
    credentialId: parsed.credentialId!,
    publicKeyCose: parsed.credentialKey!,
    signCount: parsed.signCount,
    rpIdHash: parsed.rpIdHash,
  };
}
