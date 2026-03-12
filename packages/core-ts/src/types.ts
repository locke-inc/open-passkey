export interface RegistrationInput {
  rpId: string;
  expectedChallenge: string; // base64url-encoded
  expectedOrigin: string;
  clientDataJSON: string; // base64url-encoded
  attestationObject: string; // base64url-encoded
  requireUserVerification?: boolean;
}

export interface RegistrationResult {
  credentialId: Uint8Array;
  publicKeyCose: Uint8Array;
  signCount: number;
  rpIdHash: Uint8Array;
  flags: number;
  backupEligible: boolean;
  backupState: boolean;
  attestationFormat: string;
  attestationX5C?: Uint8Array[];
}

export interface AuthenticationInput {
  rpId: string;
  expectedChallenge: string; // base64url-encoded
  expectedOrigin: string;
  storedPublicKeyCose: Uint8Array;
  storedSignCount: number;
  clientDataJSON: string; // base64url-encoded
  authenticatorData: string; // base64url-encoded
  signature: string; // base64url-encoded
  requireUserVerification?: boolean;
}

export interface AuthenticationResult {
  signCount: number;
  flags: number;
  backupEligible: boolean;
  backupState: boolean;
}
