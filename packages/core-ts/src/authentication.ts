import { createVerify } from "node:crypto";
import { decode } from "cbor-x";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { base64urlDecode, sha256 } from "./util.js";
import { verifyClientData } from "./clientdata.js";
import { parseAuthenticatorData, verifyRPIdHash } from "./authdata.js";
import { SignatureInvalidError, SignCountRollbackError, UnsupportedAlgorithmError, UserPresenceRequiredError, UserVerificationRequiredError, InvalidBackupStateError } from "./errors.js";
import {
  COSE_ALG_ES256,
  COSE_ALG_MLDSA65,
  COSE_ALG_COMPOSITE_MLDSA65_ES256,
  COSE_KTY_MLDSA,
  COSE_KTY_COMPOSITE,
} from "./cose.js";
import type { AuthenticationInput, AuthenticationResult } from "./types.js";

function identifyCOSEAlgorithm(coseBytes: Uint8Array): number {
  const raw = decode(coseBytes) as Record<string, unknown>;
  return raw["3"] as number;
}

function coseES256KeyToDer(coseBytes: Uint8Array): Buffer {
  const raw = decode(coseBytes) as Record<string, unknown>;

  const kty = raw["1"];
  const alg = raw["3"];
  const crv = raw["-1"];
  const x = raw["-2"] as Uint8Array;
  const y = raw["-3"] as Uint8Array;

  if (kty !== 2 || alg !== COSE_ALG_ES256 || crv !== 1) {
    throw new UnsupportedAlgorithmError();
  }

  // Encode as uncompressed EC point: 0x04 || x || y
  const uncompressed = Buffer.concat([Buffer.from([0x04]), x, y]);

  // Wrap in SubjectPublicKeyInfo ASN.1 DER for P-256
  const ecOid = Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]); // 1.2.840.10045.2.1
  const p256Oid = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]); // 1.2.840.10045.3.1.7
  const algoSeq = Buffer.concat([
    Buffer.from([0x30, ecOid.length + p256Oid.length]),
    ecOid,
    p256Oid,
  ]);
  const bitString = Buffer.concat([
    Buffer.from([0x03, uncompressed.length + 1, 0x00]),
    uncompressed,
  ]);
  const spki = Buffer.concat([
    Buffer.from([0x30, algoSeq.length + bitString.length]),
    algoSeq,
    bitString,
  ]);

  return spki;
}

function verifyES256Signature(
  coseKeyBytes: Uint8Array,
  authDataRaw: Uint8Array,
  clientDataHash: Uint8Array,
  sigBytes: Uint8Array,
): void {
  const spki = coseES256KeyToDer(coseKeyBytes);

  const verifier = createVerify("SHA256");
  verifier.update(Buffer.concat([authDataRaw, clientDataHash]));
  const valid = verifier.verify(
    { key: Buffer.concat([Buffer.from("-----BEGIN PUBLIC KEY-----\n"), Buffer.from(spki.toString("base64").replace(/(.{64})/g, "$1\n")), Buffer.from("\n-----END PUBLIC KEY-----")]), format: "pem" },
    Buffer.from(sigBytes),
  );

  if (!valid) {
    throw new SignatureInvalidError();
  }
}

/** Verify an ES256 signature given raw uncompressed EC point bytes (65 bytes). */
function verifyES256SignatureRaw(
  ecPointBytes: Uint8Array,
  authDataRaw: Uint8Array,
  clientDataHash: Uint8Array,
  sigBytes: Uint8Array,
): void {
  // Wrap the raw uncompressed point in SubjectPublicKeyInfo DER for P-256
  const ecOid = Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const p256Oid = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
  const algoSeq = Buffer.concat([
    Buffer.from([0x30, ecOid.length + p256Oid.length]),
    ecOid,
    p256Oid,
  ]);
  const bitString = Buffer.concat([
    Buffer.from([0x03, ecPointBytes.length + 1, 0x00]),
    ecPointBytes,
  ]);
  const spki = Buffer.concat([
    Buffer.from([0x30, algoSeq.length + bitString.length]),
    algoSeq,
    bitString,
  ]);

  const verifier = createVerify("SHA256");
  verifier.update(Buffer.concat([authDataRaw, clientDataHash]));
  const valid = verifier.verify(
    { key: Buffer.concat([Buffer.from("-----BEGIN PUBLIC KEY-----\n"), Buffer.from(spki.toString("base64").replace(/(.{64})/g, "$1\n")), Buffer.from("\n-----END PUBLIC KEY-----")]), format: "pem" },
    Buffer.from(sigBytes),
  );

  if (!valid) {
    throw new SignatureInvalidError();
  }
}

function verifyMLDSA65Signature(
  coseKeyBytes: Uint8Array,
  authDataRaw: Uint8Array,
  clientDataHash: Uint8Array,
  sigBytes: Uint8Array,
): void {
  const raw = decode(coseKeyBytes) as Record<string, unknown>;
  const kty = raw["1"];
  const alg = raw["3"];
  const pub = raw["-1"] as Uint8Array;

  if (kty !== COSE_KTY_MLDSA || alg !== COSE_ALG_MLDSA65) {
    throw new UnsupportedAlgorithmError();
  }

  const verifyData = new Uint8Array([...authDataRaw, ...clientDataHash]);
  const valid = ml_dsa65.verify(sigBytes, verifyData, pub);

  if (!valid) {
    throw new SignatureInvalidError();
  }
}

// ML-DSA-65 public key size (FIPS 204).
const MLDSA_PUB_KEY_SIZE = 1952;
// Uncompressed EC P-256 point: 0x04 || x(32) || y(32).
const ECDSA_UNCOMPRESSED_SIZE = 65;

function verifyCompositeSignature(
  coseKeyBytes: Uint8Array,
  authDataRaw: Uint8Array,
  clientDataHash: Uint8Array,
  sigBytes: Uint8Array,
): void {
  // Decode the composite COSE key
  const raw = decode(coseKeyBytes) as Record<string, unknown>;
  const kty = raw["1"];
  const alg = raw["3"];
  const compositeKey = raw["-1"] as Uint8Array;

  if (kty !== COSE_KTY_COMPOSITE || alg !== COSE_ALG_COMPOSITE_MLDSA65_ES256) {
    throw new UnsupportedAlgorithmError();
  }

  const expectedKeyLen = MLDSA_PUB_KEY_SIZE + ECDSA_UNCOMPRESSED_SIZE;
  if (compositeKey.length !== expectedKeyLen) {
    throw new UnsupportedAlgorithmError(
      `composite public key wrong length: got ${compositeKey.length}, want ${expectedKeyLen}`,
    );
  }

  // Split composite key: ML-DSA-65 (1952 bytes) || ECDSA uncompressed point (65 bytes)
  const mldsaPubKey = compositeKey.slice(0, MLDSA_PUB_KEY_SIZE);
  const ecdsaPubPoint = compositeKey.slice(MLDSA_PUB_KEY_SIZE);

  // Split composite signature: 4-byte big-endian ML-DSA sig length || ML-DSA sig || ES256 DER sig
  if (sigBytes.length < 4) {
    throw new SignatureInvalidError();
  }

  const view = new DataView(sigBytes.buffer, sigBytes.byteOffset, sigBytes.byteLength);
  const mldsaSigLen = view.getUint32(0);

  if (sigBytes.length < 4 + mldsaSigLen) {
    throw new SignatureInvalidError();
  }

  const mldsaSig = sigBytes.slice(4, 4 + mldsaSigLen);
  const ecdsaSig = sigBytes.slice(4 + mldsaSigLen);

  // Both components verify over the same data: authData || SHA256(clientDataJSON)
  // ML-DSA-65: signs the message directly (no additional hashing)
  const verifyData = new Uint8Array([...authDataRaw, ...clientDataHash]);
  const mldsaValid = ml_dsa65.verify(mldsaSig, verifyData, mldsaPubKey);
  if (!mldsaValid) {
    throw new SignatureInvalidError();
  }

  // ES256: verify using the raw EC point extracted from the composite key
  verifyES256SignatureRaw(ecdsaPubPoint, authDataRaw, clientDataHash, ecdsaSig);
}

export function verifyAuthentication(
  input: AuthenticationInput,
): AuthenticationResult {
  const clientDataJSONRaw = verifyClientData(
    input.clientDataJSON,
    "webauthn.get",
    input.expectedChallenge,
    input.expectedOrigin,
  );

  const authDataRaw = base64urlDecode(input.authenticatorData);
  const parsed = parseAuthenticatorData(authDataRaw, false);

  verifyRPIdHash(parsed.rpIdHash, input.rpId);

  if ((parsed.flags & 0x01) === 0) {
    throw new UserPresenceRequiredError();
  }
  if (input.requireUserVerification && (parsed.flags & 0x04) === 0) {
    throw new UserVerificationRequiredError();
  }

  // BS must be 0 if BE is 0 (§6.3.3)
  if ((parsed.flags & 0x08) === 0 && (parsed.flags & 0x10) !== 0) {
    throw new InvalidBackupStateError();
  }

  const clientDataHash = sha256(clientDataJSONRaw);
  const sigBytes = base64urlDecode(input.signature);
  const alg = identifyCOSEAlgorithm(input.storedPublicKeyCose);

  switch (alg) {
    case COSE_ALG_ES256:
      verifyES256Signature(input.storedPublicKeyCose, authDataRaw, clientDataHash, sigBytes);
      break;
    case COSE_ALG_MLDSA65:
      verifyMLDSA65Signature(input.storedPublicKeyCose, authDataRaw, clientDataHash, sigBytes);
      break;
    case COSE_ALG_COMPOSITE_MLDSA65_ES256:
      verifyCompositeSignature(input.storedPublicKeyCose, authDataRaw, clientDataHash, sigBytes);
      break;
    default:
      throw new UnsupportedAlgorithmError();
  }

  // Sign count rollback detection per WebAuthn spec §7.2 step 21.
  // If both stored and reported counts are non-zero, the new count must be greater.
  if (input.storedSignCount > 0 && parsed.signCount <= input.storedSignCount) {
    throw new SignCountRollbackError();
  }

  return {
    signCount: parsed.signCount,
    flags: parsed.flags,
    backupEligible: (parsed.flags & 0x08) !== 0,
    backupState: (parsed.flags & 0x10) !== 0,
  };
}
