import { createVerify } from "node:crypto";
import { decode } from "cbor-x";
import { base64urlDecode, sha256 } from "./util.js";
import { verifyClientData } from "./clientdata.js";
import { parseAuthenticatorData, verifyRPIdHash } from "./authdata.js";
import { SignatureInvalidError, UnsupportedAlgorithmError } from "./errors.js";
import { COSE_ALG_ES256, COSE_ALG_MLDSA65 } from "./cose.js";
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

function verifyMLDSA65Signature(
  _coseKeyBytes: Uint8Array,
  _authDataRaw: Uint8Array,
  _clientDataHash: Uint8Array,
  _sigBytes: Uint8Array,
): void {
  // ML-DSA-65 verification requires a post-quantum crypto library.
  // Node.js does not yet have native ML-DSA support.
  // Server-side ML-DSA-65 verification should use the Go implementation (core-go).
  // This TypeScript path will be implemented when a stable PQ library is available for Node.js.
  throw new UnsupportedAlgorithmError(
    "ML-DSA-65 verification is not yet available in the TypeScript implementation. Use the Go server (core-go) for post-quantum passkey verification.",
  );
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
    default:
      throw new UnsupportedAlgorithmError();
  }

  return {
    signCount: parsed.signCount,
  };
}
