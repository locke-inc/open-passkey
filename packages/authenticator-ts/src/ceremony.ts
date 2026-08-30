import type {
  CeremonyFacts,
  ClientExtensionResults,
  CreateExtensionInputs,
} from "./types.js";

export interface NegotiatedExtensions {
  clientExtensionResults: ClientExtensionResults;
}

export function negotiateCreateExtensions(
  inputs: CreateExtensionInputs | undefined,
): NegotiatedExtensions {
  if (!inputs?.credProps) {
    return { clientExtensionResults: {} };
  }

  const clientExtensionResults = { credProps: { rk: true } };
  return { clientExtensionResults };
}

export function requireCeremonyFacts(facts: CeremonyFacts | undefined): CeremonyFacts {
  if (
    !facts ||
    typeof facts.userPresent !== "boolean" ||
    typeof facts.userVerified !== "boolean" ||
    typeof facts.backupEligible !== "boolean" ||
    typeof facts.backupState !== "boolean"
  ) {
    throw new Error("Explicit ceremony facts are required");
  }
  if (facts.backupState && !facts.backupEligible) {
    throw new Error("backupState requires backupEligible");
  }
  return facts;
}

export function requireRequestedUserVerification(
  requirement: "required" | "preferred" | "discouraged" | undefined,
  facts: CeremonyFacts,
): void {
  if (requirement === "required" && !facts.userVerified) {
    throw new Error("User verification is required");
  }
}

export function authenticatorFlags(
  facts: CeremonyFacts,
  attestedCredentialData: boolean,
): number {
  return (
    (facts.userPresent ? 0x01 : 0) |
    (facts.userVerified ? 0x04 : 0) |
    (facts.backupEligible ? 0x08 : 0) |
    (facts.backupState ? 0x10 : 0) |
    (attestedCredentialData ? 0x40 : 0)
  );
}
