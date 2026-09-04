import { createHash, createVerify, X509Certificate } from "node:crypto";
import { decode } from "cbor-x";
import { COSE_ALG_ES256, COSE_KTY_EC2 } from "./cose.js";
import {
  InvalidAttestationStatementError,
  SignatureInvalidError,
  UnsupportedAlgorithmError,
} from "./errors.js";
import { constantTimeEqual } from "./util.js";

// TPM 2.0 constants (TPM Library Part 2, Structures).
const TPM_GENERATED_VALUE = 0xff544347; // magic for TPMS_ATTEST
const TPM_ST_ATTEST_CERTIFY = 0x8017; // type for certify attestation
const TPM_ALG_ECC = 0x0023; // TPMT_PUBLIC type for ECC keys

// TPM nameAlg identifiers mapped to Node hash names.
const NAME_ALG_HASHES: Record<number, string> = {
  0x0004: "sha1",
  0x000b: "sha256",
  0x000c: "sha384",
  0x000d: "sha512",
};

export interface TpmAttestationStatement {
  ver?: unknown;
  alg?: number;
  sig?: Uint8Array;
  x5c?: Uint8Array[];
  certInfo?: Uint8Array;
  pubArea?: Uint8Array;
}

interface ParsedPubArea {
  nameAlg: number;
  x: Uint8Array;
  y: Uint8Array;
}

function u16be(buf: Uint8Array, offset: number): number {
  return (buf[offset] << 8) | buf[offset + 1];
}

// Read a TPM2B sized buffer (u16 length prefix + bytes) at offset.
function readTpm2b(
  buf: Uint8Array,
  offset: number,
  context: string,
): { bytes: Uint8Array; next: number } {
  if (offset + 2 > buf.length) {
    throw new InvalidAttestationStatementError(`malformed tpm ${context}`);
  }
  const len = u16be(buf, offset);
  if (offset + 2 + len > buf.length) {
    throw new InvalidAttestationStatementError(`malformed tpm ${context}`);
  }
  return { bytes: buf.slice(offset + 2, offset + 2 + len), next: offset + 2 + len };
}

// Parse a TPM2B_PUBLIC (pubArea) holding an ECC key. Layout:
// type(2) || nameAlg(2) || objectAttributes(4) || authPolicy(TPM2B) ||
// parameters (symmetric(2) || scheme(2) || curveID(2) || kdf(2)) ||
// unique (x TPM2B || y TPM2B).
export function parseTpmPubArea(pubArea: Uint8Array): ParsedPubArea {
  if (pubArea.length < 2 + 2 + 4 + 2 + 8 + 2 + 2) {
    throw new InvalidAttestationStatementError("malformed tpm pubArea");
  }
  let offset = 0;
  const type = u16be(pubArea, offset);
  offset += 2;
  if (type !== TPM_ALG_ECC) {
    throw new InvalidAttestationStatementError(
      `unsupported tpm pubArea type 0x${type.toString(16)}`,
    );
  }
  const nameAlg = u16be(pubArea, offset);
  offset += 2;
  if (!(nameAlg in NAME_ALG_HASHES)) {
    throw new InvalidAttestationStatementError(
      `unsupported tpm nameAlg 0x${nameAlg.toString(16)}`,
    );
  }
  offset += 4; // objectAttributes
  const authPolicy = readTpm2b(pubArea, offset, "pubArea authPolicy");
  offset = authPolicy.next;
  if (offset + 8 > pubArea.length) {
    throw new InvalidAttestationStatementError("malformed tpm pubArea parameters");
  }
  offset += 8; // symmetric, scheme, curveID, kdf
  const x = readTpm2b(pubArea, offset, "pubArea x");
  const y = readTpm2b(pubArea, x.next, "pubArea y");
  return { nameAlg, x: x.bytes, y: y.bytes };
}

// TPM name of pubArea: nameAlg(2 BE) || Hash_nameAlg(pubArea).
export function computeTpmName(pubArea: Uint8Array, nameAlg: number): Uint8Array {
  const hashName = NAME_ALG_HASHES[nameAlg];
  if (!hashName) {
    throw new InvalidAttestationStatementError(
      `unsupported tpm nameAlg 0x${nameAlg.toString(16)}`,
    );
  }
  const digest = createHash(hashName).update(pubArea).digest();
  const name = new Uint8Array(2 + digest.length);
  name[0] = (nameAlg >> 8) & 0xff;
  name[1] = nameAlg & 0xff;
  name.set(digest, 2);
  return name;
}

interface ParsedCertInfo {
  magic: number;
  type: number;
  extraData: Uint8Array;
  name: Uint8Array;
}

// Parse a TPMS_ATTEST (certInfo): magic(4) || type(2) ||
// qualifiedSigner(TPM2B) || extraData(TPM2B) || clockInfo(17) ||
// firmwareVersion(8) || attested (certify: name TPM2B || qualifiedName TPM2B).
export function parseTpmCertInfo(certInfo: Uint8Array): ParsedCertInfo {
  if (certInfo.length < 4 + 2 + 2 + 2 + 17 + 8 + 2 + 2) {
    throw new InvalidAttestationStatementError("malformed tpm certInfo");
  }
  let offset = 0;
  const magic =
    (certInfo[offset] << 24) |
    (certInfo[offset + 1] << 16) |
    (certInfo[offset + 2] << 8) |
    certInfo[offset + 3];
  offset += 4;
  const type = u16be(certInfo, offset);
  offset += 2;
  const signer = readTpm2b(certInfo, offset, "certInfo qualifiedSigner");
  offset = signer.next;
  const extra = readTpm2b(certInfo, offset, "certInfo extraData");
  offset = extra.next;
  if (offset + 17 + 8 + 2 > certInfo.length) {
    throw new InvalidAttestationStatementError("malformed tpm certInfo");
  }
  offset += 17; // clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1)
  offset += 8; // firmwareVersion
  const name = readTpm2b(certInfo, offset, "certInfo name");
  offset = name.next;
  if (offset + 2 > certInfo.length) {
    throw new InvalidAttestationStatementError(
      "malformed tpm certInfo qualifiedName",
    );
  }
  return { magic: magic >>> 0, type, extraData: extra.bytes, name: name.bytes };
}

/**
 * Verify a TPM attestation statement (WebAuthn §8.3).
 *
 * Same-documented policy as packed: the AIK certificate (x5c[0]) is used as
 * the trust anchor for the signature only — no chain-to-root validation.
 * Per spec, sig covers certInfo (which binds attToBeSigned via extraData).
 */
export function verifyTpmAttestation(
  stmt: TpmAttestationStatement,
  authData: Uint8Array,
  clientDataHash: Uint8Array,
  credentialKeyCose: Uint8Array,
): void {
  if (stmt.ver !== "2.0") {
    throw new InvalidAttestationStatementError('tpm ver must be "2.0"');
  }
  if (!stmt.sig || !stmt.x5c || stmt.x5c.length === 0 || !stmt.certInfo || !stmt.pubArea) {
    throw new InvalidAttestationStatementError(
      "tpm statement missing sig, x5c, certInfo, or pubArea",
    );
  }

  const { nameAlg, x, y } = parseTpmPubArea(stmt.pubArea);
  const expectedName = computeTpmName(stmt.pubArea, nameAlg);
  const certInfo = parseTpmCertInfo(stmt.certInfo);

  if (certInfo.magic !== TPM_GENERATED_VALUE) {
    throw new InvalidAttestationStatementError("tpm certInfo bad magic");
  }
  if (certInfo.type !== TPM_ST_ATTEST_CERTIFY) {
    throw new InvalidAttestationStatementError("tpm certInfo bad type");
  }
  if (!constantTimeEqual(certInfo.name, expectedName)) {
    throw new InvalidAttestationStatementError("tpm certInfo name mismatch");
  }

  // Per TPM Library (TPMS_ATTEST) + WebAuthn §8.3, extraData is a TPM2B
  // (max 64 bytes) holding the digest of attToBeSigned under the nameAlg hash,
  // not attToBeSigned itself.
  const attToBeSigned = Buffer.concat([authData, clientDataHash]);
  const expectedExtra = createHash(NAME_ALG_HASHES[nameAlg])
    .update(attToBeSigned)
    .digest();
  if (!constantTimeEqual(certInfo.extraData, new Uint8Array(expectedExtra))) {
    throw new InvalidAttestationStatementError("tpm certInfo extraData mismatch");
  }

  // The ECC point in pubArea must equal the credential key from authData.
  const cose = decode(credentialKeyCose) as Record<string, unknown>;
  if (cose["1"] !== COSE_KTY_EC2) {
    throw new UnsupportedAlgorithmError();
  }
  const cx = cose["-2"] as Uint8Array;
  const cy = cose["-3"] as Uint8Array;
  if (!cx || !cy || !constantTimeEqual(cx, x) || !constantTimeEqual(cy, y)) {
    throw new InvalidAttestationStatementError(
      "tpm pubArea point differs from credential key",
    );
  }

  if (stmt.alg !== COSE_ALG_ES256) {
    throw new UnsupportedAlgorithmError(`attestation alg ${stmt.alg}`);
  }
  const cert = new X509Certificate(stmt.x5c[0]);
  const verifier = createVerify("SHA256");
  verifier.update(stmt.certInfo);
  const valid = verifier.verify(cert.publicKey, Buffer.from(stmt.sig));
  if (!valid) {
    throw new SignatureInvalidError();
  }
}
