/**
 * Core WebAuthn/FIDO2 protocol verification library.
 *
 * This is the "Core Protocol" layer — no HTTP handling, no framework bindings,
 * no session management. It verifies registration and authentication ceremonies
 * given raw WebAuthn structures.
 *
 * Supported algorithms:
 * - ES256 (ECDSA P-256, COSE alg -7) — classical, widely supported
 * - ML-DSA-65 (FIPS 204 / Dilithium3, COSE alg -49) — post-quantum
 * - ML-DSA-65-ES256 (composite, COSE alg -52) — hybrid PQ, draft-ietf-jose-pq-composite-sigs
 */

export { verifyRegistration } from "./registration.js";
export { verifyAuthentication } from "./authentication.js";
export type {
  RegistrationInput,
  RegistrationResult,
  AuthenticationInput,
  AuthenticationResult,
} from "./types.js";
export {
  WebAuthnError,
  TypeMismatchError,
  ChallengeMismatchError,
  OriginMismatchError,
  RPIDMismatchError,
  SignatureInvalidError,
  UnsupportedAlgorithmError,
  SignCountRollbackError,
  UserPresenceRequiredError,
  UserVerificationRequiredError,
  UnsupportedAttestationFormatError,
  TokenBindingUnsupportedError,
} from "./errors.js";
export {
  COSE_ALG_ES256,
  COSE_ALG_MLDSA65,
  COSE_ALG_COMPOSITE_MLDSA65_ES256,
  COSE_KTY_EC2,
  COSE_KTY_MLDSA,
  COSE_KTY_COMPOSITE,
} from "./cose.js";
