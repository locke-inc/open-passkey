import { createVerify, X509Certificate } from "node:crypto";
import { COSE_ALG_ES256 } from "./cose.js";
import {
  InvalidAttestationStatementError,
  SignatureInvalidError,
  UnsupportedAlgorithmError,
} from "./errors.js";
import { constantTimeEqual } from "./util.js";

// DER contents (not TLV) of OID 1.3.6.1.4.1.11129.2.1.17
// (android KeyDescription extension).
const ANDROID_OID_CONTENTS = new Uint8Array([
  0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11,
]);

// Keymaster security levels: 0 = SoftwareOnly, 1 = TEE, 2 = StrongBox.
const SECURITY_LEVEL_SOFTWARE = 0;
const SECURITY_LEVEL_TEE = 1;
const SECURITY_LEVEL_STRONGBOX = 2;

export interface AndroidKeyAttestationStatement {
  alg?: number;
  sig?: Uint8Array;
  x5c?: Uint8Array[];
}

interface Tlv {
  tag: number;
  value: Uint8Array;
  next: number;
}

function readTlv(buf: Uint8Array, offset: number): Tlv {
  if (offset + 2 > buf.length) {
    throw new InvalidAttestationStatementError("malformed certificate DER");
  }
  const tag = buf[offset];
  let len = buf[offset + 1];
  let headerLen = 2;
  if (len & 0x80) {
    const count = len & 0x7f;
    if (count === 0 || count > 4 || offset + 2 + count > buf.length) {
      throw new InvalidAttestationStatementError("malformed certificate DER");
    }
    len = 0;
    for (let i = 0; i < count; i++) {
      len = len * 256 + buf[offset + 2 + i];
    }
    headerLen += count;
  }
  if (offset + headerLen + len > buf.length) {
    throw new InvalidAttestationStatementError("malformed certificate DER");
  }
  return {
    tag,
    value: buf.slice(offset + headerLen, offset + headerLen + len),
    next: offset + headerLen + len,
  };
}

function children(buf: Uint8Array): Tlv[] {
  const out: Tlv[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const tlv = readTlv(buf, offset);
    out.push(tlv);
    offset = tlv.next;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Minimal DER walk: Certificate -> TBSCertificate -> [3] extensions ->
// Extension with the KeyDescription OID -> KeyDescription fields.
// KeyDescription ::= SEQUENCE { attestationVersion INTEGER,
//   attestationSecurityLevel ENUMERATED, keymasterVersion INTEGER,
//   keymasterSecurityLevel ENUMERATED, attestationChallenge OCTET STRING,
//   uniqueId OCTET STRING, softwareEnforced AuthorizationList,
//   teeEnforced AuthorizationList }
export interface AndroidKeyDescription {
  securityLevel: number;
  attestationChallenge: Uint8Array;
}

export function parseAndroidKeyDescription(
  certDer: Uint8Array,
): AndroidKeyDescription {
  const cert = readTlv(certDer, 0);
  if (cert.tag !== 0x30) {
    throw new InvalidAttestationStatementError("malformed certificate DER");
  }
  const certKids = children(cert.value);
  if (certKids.length < 1 || certKids[0].tag !== 0x30) {
    throw new InvalidAttestationStatementError("malformed certificate DER");
  }
  const tbsKids = children(certKids[0].value);
  const extensionsWrapper = tbsKids.find((t) => t.tag === 0xa3);
  if (!extensionsWrapper) {
    throw new InvalidAttestationStatementError(
      "android-key leaf certificate has no extensions",
    );
  }
  const wrapperKids = children(extensionsWrapper.value);
  if (wrapperKids.length < 1 || wrapperKids[0].tag !== 0x30) {
    throw new InvalidAttestationStatementError("malformed certificate extensions");
  }
  for (const ext of children(wrapperKids[0].value)) {
    if (ext.tag !== 0x30) continue;
    const parts = children(ext.value);
    if (parts.length < 2 || parts[0].tag !== 0x06) continue;
    if (!bytesEqual(parts[0].value, ANDROID_OID_CONTENTS)) continue;
    const valuePart = parts.find((p) => p.tag === 0x04);
    if (!valuePart) {
      throw new InvalidAttestationStatementError(
        "malformed android-key extension value",
      );
    }
    const kd = readTlv(valuePart.value, 0);
    if (kd.tag !== 0x30) {
      throw new InvalidAttestationStatementError(
        "malformed android KeyDescription",
      );
    }
    const fields = children(kd.value);
    if (fields.length < 2 || fields[1].tag !== 0x0a || fields[1].value.length !== 1) {
      throw new InvalidAttestationStatementError(
        "malformed android KeyDescription",
      );
    }
    if (fields.length < 5 || fields[4].tag !== 0x04) {
      throw new InvalidAttestationStatementError(
        "malformed android KeyDescription",
      );
    }
    return {
      securityLevel: fields[1].value[0],
      attestationChallenge: fields[4].value,
    };
  }
  throw new InvalidAttestationStatementError(
    "android-key extension 1.3.6.1.4.1.11129.2.1.17 missing",
  );
}

export function androidAttestationSecurityLevel(certDer: Uint8Array): number {
  return parseAndroidKeyDescription(certDer).securityLevel;
}

export function androidAttestationChallenge(certDer: Uint8Array): Uint8Array {
  return parseAndroidKeyDescription(certDer).attestationChallenge;
}

/**
 * Verify an android-key attestation statement (WebAuthn §8.4).
 *
 * Same-documented policy as packed: the leaf certificate (x5c[0]) is used as
 * the trust anchor for the signature only — no chain-to-root validation.
 * Policy: accept TEE and StrongBox security levels, reject SoftwareOnly.
 */
export function verifyAndroidKeyAttestation(
  stmt: AndroidKeyAttestationStatement,
  authData: Uint8Array,
  clientDataHash: Uint8Array,
): void {
  if (!stmt.sig || !stmt.x5c || stmt.x5c.length === 0) {
    throw new InvalidAttestationStatementError(
      "android-key statement missing sig or x5c",
    );
  }

  const { securityLevel: level, attestationChallenge } =
    parseAndroidKeyDescription(stmt.x5c[0]);
  if (level === SECURITY_LEVEL_SOFTWARE) {
    throw new InvalidAttestationStatementError(
      "android-key software-only attestation rejected",
    );
  }
  if (level !== SECURITY_LEVEL_TEE && level !== SECURITY_LEVEL_STRONGBOX) {
    throw new InvalidAttestationStatementError(
      `android-key unrecognized security level ${level}`,
    );
  }

  // WebAuthn §8.4: attestationChallenge must equal the clientDataHash.
  if (!constantTimeEqual(attestationChallenge, clientDataHash)) {
    throw new InvalidAttestationStatementError(
      "android-key attestationChallenge mismatch",
    );
  }

  if (stmt.alg !== COSE_ALG_ES256) {
    throw new UnsupportedAlgorithmError(`attestation alg ${stmt.alg}`);
  }
  const cert = new X509Certificate(stmt.x5c[0]);
  const verifier = createVerify("SHA256");
  verifier.update(Buffer.concat([authData, clientDataHash]));
  const valid = verifier.verify(cert.publicKey, Buffer.from(stmt.sig));
  if (!valid) {
    throw new SignatureInvalidError();
  }
}
