import { sha256, constantTimeEqual } from "./util.js";
import { RPIDMismatchError } from "./errors.js";

const MIN_AUTH_DATA_LEN = 37;

export interface ParsedAuthData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  credentialId?: Uint8Array;
  credentialKey?: Uint8Array;
}

export function parseAuthenticatorData(
  authData: Uint8Array,
  expectCredData: boolean,
): ParsedAuthData {
  if (authData.length < MIN_AUTH_DATA_LEN) {
    throw new Error("authenticator_data_too_short");
  }

  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const view = new DataView(
    authData.buffer,
    authData.byteOffset,
    authData.byteLength,
  );
  const signCount = view.getUint32(33);

  const result: ParsedAuthData = { rpIdHash, flags, signCount };

  if (expectCredData) {
    const hasAttestedCredData = (flags & 0x40) !== 0;
    if (!hasAttestedCredData) {
      throw new Error("no_attested_credential_data");
    }

    let offset = 37;
    // AAGUID: 16 bytes
    offset += 16;
    // Credential ID length: 2 bytes big-endian
    const credIdLen = view.getUint16(offset);
    offset += 2;
    result.credentialId = authData.slice(offset, offset + credIdLen);
    offset += credIdLen;
    result.credentialKey = authData.slice(offset);
  }

  return result;
}

export function verifyRPIdHash(
  authDataRPIdHash: Uint8Array,
  rpId: string,
): void {
  const expected = sha256(new TextEncoder().encode(rpId));
  if (!constantTimeEqual(authDataRPIdHash, expected)) {
    throw new RPIDMismatchError();
  }
}
