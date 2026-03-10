/**
 * Core WebAuthn/FIDO2 protocol verification library.
 *
 * This is the "Core Protocol" layer — no HTTP handling, no framework bindings,
 * no session management. It verifies registration and authentication ceremonies
 * given raw WebAuthn structures.
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
} from "./errors.js";
