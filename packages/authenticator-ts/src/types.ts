export interface CeremonyFacts {
  userPresent: boolean;
  userVerified: boolean;
  backupEligible: boolean;
  backupState: boolean;
}

export interface CreateExtensionInputs {
  credProps?: boolean;
}

export interface ClientExtensionResults {
  credProps?: { rk: boolean };
}

export interface StoredCredential {
  credentialId: Uint8Array;
  rpId: string;
  rpName: string;
  userId: Uint8Array | null;
  userName: string;
  privateKeyPkcs8: Uint8Array;
  publicKeyCose: Uint8Array;
  publicKeySpki: Uint8Array;
  signCount: number;
  createdAt: string;
  lastUsedAt: string;
  backupEligible: boolean;
  backupState: boolean;
}

export interface CreateCredentialInput {
  rpId: string;
  rpName: string;
  userId: Uint8Array;
  userName: string;
  challenge: Uint8Array;
  origin: string;
  topOrigin?: string;
  crossOrigin?: boolean;
  algorithms: number[];
  requireResidentKey?: boolean;
  userVerification?: "required" | "preferred" | "discouraged";
  excludeCredentials?: Uint8Array[];
  extensions?: CreateExtensionInputs;
  ceremony: CeremonyFacts;
}

export interface CreateCredentialResult {
  credential: StoredCredential;
  response: {
    attestationObject: string; // base64url
    clientDataJSON: string; // base64url
  };
  credentialId: string; // base64url
  publicKeyCose: Uint8Array;
  clientExtensionResults: ClientExtensionResults;
}

export interface GetAssertionInput {
  rpId: string;
  challenge: Uint8Array;
  origin: string;
  topOrigin?: string;
  crossOrigin?: boolean;
  credential: StoredCredential;
  userVerification?: "required" | "preferred" | "discouraged";
  ceremony: CeremonyFacts;
}

export interface GetAssertionResult {
  response: {
    authenticatorData: string; // base64url
    clientDataJSON: string; // base64url
    signature: string; // base64url
    userHandle: string | null; // base64url
  };
  updatedCredential: StoredCredential;
}
