import { decode } from "cbor-x";
import { sha256, constantTimeEqual } from "./util.js";
import { RPIDMismatchError } from "./errors.js";

const MIN_AUTH_DATA_LEN = 37;

function firstCborItemLength(data: Uint8Array): number {
  const requireBytes = (offset: number, count: number): void => {
    if (offset + count > data.length) throw new Error("invalid_authenticator_data");
  };
  const readItem = (start: number): number => {
    requireBytes(start, 1);
    const initial = data[start];
    const majorType = initial >> 5;
    const additional = initial & 0x1f;
    let offset = start + 1;
    let argument: number;

    if (additional < 24) {
      argument = additional;
    } else if (additional === 24) {
      requireBytes(offset, 1);
      argument = data[offset++];
    } else if (additional === 25) {
      requireBytes(offset, 2);
      argument = new DataView(data.buffer, data.byteOffset + offset, 2).getUint16(0);
      offset += 2;
    } else if (additional === 26) {
      requireBytes(offset, 4);
      argument = new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(0);
      offset += 4;
    } else if (additional === 27) {
      requireBytes(offset, 8);
      const value = new DataView(data.buffer, data.byteOffset + offset, 8).getBigUint64(0);
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("invalid_authenticator_data");
      argument = Number(value);
      offset += 8;
    } else {
      // CTAP2 canonical CBOR forbids indefinite-length items and reserved values.
      throw new Error("invalid_authenticator_data");
    }

    if (majorType === 0 || majorType === 1 || majorType === 7) return offset;
    if (majorType === 2 || majorType === 3) {
      requireBytes(offset, argument);
      return offset + argument;
    }
    if (majorType === 4) {
      for (let index = 0; index < argument; index++) offset = readItem(offset);
      return offset;
    }
    if (majorType === 5) {
      for (let index = 0; index < argument * 2; index++) offset = readItem(offset);
      return offset;
    }
    if (majorType === 6) return readItem(offset);
    throw new Error("invalid_authenticator_data");
  };

  return readItem(0);
}

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

    // Need at least 37 + 16 (AAGUID) + 2 (credID length) = 55 bytes
    if (authData.length < 55) {
      throw new Error("authenticator_data_too_short");
    }

    let offset = 37;
    // AAGUID: 16 bytes
    offset += 16;
    // Credential ID length: 2 bytes big-endian
    const credIdLen = view.getUint16(offset);
    offset += 2;
    if (authData.length < offset + credIdLen) {
      throw new Error("authenticator_data_too_short");
    }
    result.credentialId = authData.slice(offset, offset + credIdLen);
    offset += credIdLen;
    const credentialAndExtensions = authData.slice(offset);
    const credentialKeyLength = firstCborItemLength(credentialAndExtensions);
    const extensionData = credentialAndExtensions.slice(credentialKeyLength);
    if ((flags & 0x80) !== 0) {
      if (extensionData.length === 0) {
        throw new Error("invalid_authenticator_data");
      }
      decode(extensionData);
    } else if (extensionData.length !== 0) {
      throw new Error("invalid_authenticator_data");
    }
    result.credentialKey = authData.slice(offset, offset + credentialKeyLength);
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
