import { decode } from "cbor-x";
import { base64urlDecode } from "./util.js";
import { verifyClientData } from "./clientdata.js";
import { parseAuthenticatorData, verifyRPIdHash } from "./authdata.js";
import {
  UserPresenceRequiredError,
  UserVerificationRequiredError,
  UnsupportedAttestationFormatError,
} from "./errors.js";
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
  if (attObj.fmt !== "none") {
    throw new UnsupportedAttestationFormatError(attObj.fmt);
  }
  const authData: Uint8Array = attObj.authData;

  const parsed = parseAuthenticatorData(authData, true);

  verifyRPIdHash(parsed.rpIdHash, input.rpId);

  if ((parsed.flags & 0x01) === 0) {
    throw new UserPresenceRequiredError();
  }
  if (input.requireUserVerification && (parsed.flags & 0x04) === 0) {
    throw new UserVerificationRequiredError();
  }

  return {
    credentialId: parsed.credentialId!,
    publicKeyCose: parsed.credentialKey!,
    signCount: parsed.signCount,
    rpIdHash: parsed.rpIdHash,
    flags: parsed.flags,
  };
}
