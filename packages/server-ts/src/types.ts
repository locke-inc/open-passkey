// --- Store interfaces ---

export interface ChallengeStore {
  store(key: string, challenge: string, timeout: number): Promise<void>;
  consume(key: string): Promise<string | null>;
}

export interface CredentialStore {
  store(cred: StoredCredential): Promise<void>;
  get(credentialId: Uint8Array): Promise<StoredCredential | null>;
  getByUser(userId: string): Promise<StoredCredential[]>;
  update(cred: StoredCredential): Promise<void>;
  delete(credentialId: Uint8Array): Promise<void>;
}

export interface StoredCredential {
  credentialId: Uint8Array;
  publicKeyCose: Uint8Array;
  signCount: number;
  userId: string;
  prfSalt?: Uint8Array;
  prfSupported: boolean;
}

// --- Config ---

import type { SessionConfig } from "./session.js";

export interface PasskeyConfig {
  rpId: string;
  rpDisplayName: string;
  origin: string;
  challengeStore: ChallengeStore;
  credentialStore: CredentialStore;
  challengeLength?: number; // bytes, default 32
  challengeTimeout?: number; // milliseconds, default 300000 (5 min)
  allowMultipleCredentials?: boolean; // default false
  session?: SessionConfig;

  /**
   * Optional static 32-byte PRF salt used for all credentials.
   * When set, this salt is used instead of generating random per-credential salts.
   * Enables PRF output during discoverable credential (usernameless) authentication,
   * because the server can include the salt in prf.eval.first without knowing which
   * credential will be selected.
   *
   * Security: prfOutput = HMAC-SHA256(credentialSecret, salt). Since each credential's
   * secret has full 256-bit entropy, a static salt still produces unique output per credential.
   *
   * When undefined (default), random 32-byte salts are generated per credential and
   * stored on StoredCredential.prfSalt (requires userId for authentication PRF).
   */
  prfSalt?: Uint8Array;
}

// --- Request types ---

export interface BeginRegistrationRequest {
  userId: string;
  username: string;
}

export interface FinishRegistrationRequest {
  userId: string;
  prfSupported?: boolean;
  credential: {
    id: string;
    rawId: string;
    type: string;
    response: {
      clientDataJSON: string;
      attestationObject: string;
    };
  };
}

export interface BeginAuthenticationRequest {
  userId?: string;
}

export interface FinishAuthenticationRequest {
  userId: string;
  credential: {
    id: string;
    rawId: string;
    type: string;
    response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
      userHandle?: string;
    };
  };
}

// --- Response types ---

export interface BeginRegistrationResponse {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ type: string; alg: number }>;
  authenticatorSelection: { residentKey: string; userVerification: string };
  timeout: number;
  attestation: string;
  excludeCredentials?: Array<{ type: string; id: string }>;
  extensions?: Record<string, unknown>;
}

export interface FinishRegistrationResponse {
  credentialId: string;
  registered: true;
  prfSupported: boolean;
  sessionToken?: string;
}

export interface BeginAuthenticationResponse {
  challenge: string;
  rpId: string;
  timeout: number;
  userVerification: string;
  allowCredentials?: Array<{ type: string; id: string }>;
  extensions?: Record<string, unknown>;
}

export interface FinishAuthenticationResponse {
  userId: string;
  credentialId: string;
  authenticated: true;
  prfSupported?: boolean;
  sessionToken?: string;
}
