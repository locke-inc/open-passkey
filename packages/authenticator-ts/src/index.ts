export { createCredential } from "./create.js";
export { getAssertion } from "./assert.js";
export type {
  StoredCredential,
  CreateCredentialInput,
  CreateCredentialResult,
  GetAssertionInput,
  GetAssertionResult,
  CeremonyFacts,
  ClientExtensionResults,
  CreateExtensionInputs,
} from "./types.js";
export { ALG_ES256 } from "./cose.js";
export { p1363ToDer } from "./der.js";
