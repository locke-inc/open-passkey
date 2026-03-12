import { createVerify } from "node:crypto";
import { decode } from "cbor-x";
import { sha256 } from "./util.js";
import { COSE_ALG_ES256 } from "./cose.js";
import { SignatureInvalidError, UnsupportedAlgorithmError } from "./errors.js";

/**
 * Verify packed self-attestation: the signature is over authData || SHA256(clientDataJSON),
 * verified using the credential public key from authData.
 */
export function verifyES256SelfAttestation(
  coseKeyBytes: Uint8Array,
  authDataRaw: Uint8Array,
  clientDataJSONRaw: Uint8Array,
  sigBytes: Uint8Array,
): void {
  const raw = decode(coseKeyBytes) as Record<string, unknown>;
  const kty = raw["1"];
  const alg = raw["3"];

  if (kty !== 2 || alg !== COSE_ALG_ES256) {
    throw new UnsupportedAlgorithmError();
  }

  const x = raw["-2"] as Uint8Array;
  const y = raw["-3"] as Uint8Array;

  // Encode as uncompressed EC point: 0x04 || x || y
  const uncompressed = Buffer.concat([Buffer.from([0x04]), x, y]);

  // Wrap in SubjectPublicKeyInfo ASN.1 DER for P-256
  const ecOid = Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const p256Oid = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
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

  const clientDataHash = sha256(clientDataJSONRaw);
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
