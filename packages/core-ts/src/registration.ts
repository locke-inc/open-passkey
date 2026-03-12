import { createVerify, X509Certificate } from "node:crypto";
import { decode } from "cbor-x";
import { base64urlDecode, sha256 } from "./util.js";
import { verifyClientData } from "./clientdata.js";
import { parseAuthenticatorData, verifyRPIdHash } from "./authdata.js";
import {
  COSE_ALG_ES256,
} from "./cose.js";
import {
  UserPresenceRequiredError,
  UserVerificationRequiredError,
  UnsupportedAttestationFormatError,
  InvalidBackupStateError,
  InvalidAttestationStatementError,
  SignatureInvalidError,
  UnsupportedAlgorithmError,
} from "./errors.js";
import type { RegistrationInput, RegistrationResult } from "./types.js";

// Import verifyAuthentication's signature helpers for self-attestation reuse
import { verifyES256SelfAttestation } from "./packed.js";

export function verifyRegistration(
  input: RegistrationInput,
): RegistrationResult {
  const clientDataJSONRaw = verifyClientData(
    input.clientDataJSON,
    "webauthn.create",
    input.expectedChallenge,
    input.expectedOrigin,
  );

  // Decode CBOR attestation object
  const attObjBytes = base64urlDecode(input.attestationObject);
  const attObj = decode(attObjBytes);

  const fmt: string = attObj.fmt;
  const authData: Uint8Array = attObj.authData;
  let attStmt: { alg?: number; sig?: Uint8Array; x5c?: Uint8Array[] } | undefined;

  switch (fmt) {
    case "none":
      break;
    case "packed": {
      const raw = attObj.attStmt;
      if (!raw || raw.alg === undefined || !raw.sig) {
        throw new InvalidAttestationStatementError("missing alg or sig");
      }
      attStmt = { alg: raw.alg, sig: raw.sig, x5c: raw.x5c };
      break;
    }
    default:
      throw new UnsupportedAttestationFormatError(fmt);
  }

  const parsed = parseAuthenticatorData(authData, true);

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

  // Verify packed attestation
  if (fmt === "packed" && attStmt) {
    const clientDataHash = sha256(clientDataJSONRaw);
    if (attStmt.x5c && attStmt.x5c.length > 0) {
      // Full attestation: verify with x5c[0]
      verifyPackedFullAttestation(attStmt, authData, clientDataHash);
    } else {
      // Self-attestation: verify with credential public key
      verifyES256SelfAttestation(parsed.credentialKey!, authData, clientDataJSONRaw, attStmt.sig!);
    }
  }

  const result: RegistrationResult = {
    credentialId: parsed.credentialId!,
    publicKeyCose: parsed.credentialKey!,
    signCount: parsed.signCount,
    rpIdHash: parsed.rpIdHash,
    flags: parsed.flags,
    backupEligible: (parsed.flags & 0x08) !== 0,
    backupState: (parsed.flags & 0x10) !== 0,
    attestationFormat: fmt,
  };

  if (attStmt?.x5c && attStmt.x5c.length > 0) {
    result.attestationX5C = attStmt.x5c;
  }

  return result;
}

function verifyPackedFullAttestation(
  stmt: { alg?: number; sig?: Uint8Array; x5c?: Uint8Array[] },
  authData: Uint8Array,
  clientDataHash: Uint8Array,
): void {
  if (!stmt.x5c || stmt.x5c.length === 0) {
    throw new InvalidAttestationStatementError("x5c is empty");
  }

  const certDer = stmt.x5c[0];
  const cert = new X509Certificate(certDer);

  const verifyData = new Uint8Array([...authData, ...clientDataHash]);

  switch (stmt.alg) {
    case COSE_ALG_ES256: {
      const verifier = createVerify("SHA256");
      verifier.update(verifyData);
      const valid = verifier.verify(
        { key: cert.publicKey, format: "pem" } as any,
        Buffer.from(stmt.sig!),
      );
      if (!valid) {
        throw new SignatureInvalidError();
      }
      break;
    }
    default:
      throw new UnsupportedAlgorithmError(`attestation alg ${stmt.alg}`);
  }
}
