import { createVerify } from "node:crypto";
import { decode } from "cbor-x";
import { base64urlDecode, sha256 } from "./util.js";
import { verifyClientData } from "./clientdata.js";
import { parseAuthenticatorData, verifyRPIdHash } from "./authdata.js";
import { SignatureInvalidError } from "./errors.js";
import type { AuthenticationInput, AuthenticationResult } from "./types.js";

function coseKeyToDer(coseBytes: Uint8Array): Buffer {
  // cbor-x decodes CBOR maps with integer keys as plain objects with string keys
  const raw = decode(coseBytes) as Record<string, unknown>;

  const kty = raw["1"];
  const alg = raw["3"];
  const crv = raw["-1"];
  const x = raw["-2"] as Uint8Array;
  const y = raw["-3"] as Uint8Array;

  if (kty !== 2 || alg !== -7 || crv !== 1) {
    throw new Error("unsupported_cose_algorithm");
  }

  // Encode as uncompressed EC point: 0x04 || x || y
  const uncompressed = Buffer.concat([Buffer.from([0x04]), x, y]);

  // Wrap in SubjectPublicKeyInfo ASN.1 DER for P-256
  // SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING { uncompressed point } }
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

  // Decode COSE key to DER SPKI format for Node crypto
  const spki = coseKeyToDer(input.storedPublicKeyCose);
  const sigBytes = base64urlDecode(input.signature);

  // Verify ECDSA signature using Node's crypto
  // The signature from WebAuthn is DER-encoded ASN.1, which Node's verify expects
  const verifier = createVerify("SHA256");
  verifier.update(Buffer.concat([authDataRaw, clientDataHash]));
  const valid = verifier.verify(
    { key: Buffer.concat([Buffer.from("-----BEGIN PUBLIC KEY-----\n"), Buffer.from(spki.toString("base64").replace(/(.{64})/g, "$1\n")), Buffer.from("\n-----END PUBLIC KEY-----")]), format: "pem" },
    Buffer.from(sigBytes),
  );

  if (!valid) {
    throw new SignatureInvalidError();
  }

  return {
    signCount: parsed.signCount,
  };
}
