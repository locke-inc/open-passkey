export interface StoredCredential {
  credentialId: Uint8Array;
  rpId: string;
  rpName: string;
  userId: Uint8Array;
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
  algorithms: number[];
  requireResidentKey?: boolean;
  userVerification?: "required" | "preferred" | "discouraged";
  excludeCredentials?: Uint8Array[];
}

export interface CreateCredentialResult {
  credential: StoredCredential;
  response: {
    attestationObject: string; // base64url
    clientDataJSON: string; // base64url
  };
  credentialId: string; // base64url
  publicKeyCose: Uint8Array;
}

export interface GetAssertionInput {
  rpId: string;
  challenge: Uint8Array;
  origin: string;
  credential: StoredCredential;
  userVerification?: "required" | "preferred" | "discouraged";
}

export interface GetAssertionResult {
  response: {
    authenticatorData: string; // base64url
    clientDataJSON: string; // base64url
    signature: string; // base64url
    userHandle: string; // base64url
  };
  updatedCredential: StoredCredential;
}
