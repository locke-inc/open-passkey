/** Configuration for the passkey service. */
export interface PasskeyConfig {
  /** Base URL for the passkey server endpoints (e.g., "/passkey" or "https://api.example.com/passkey"). */
  baseUrl: string;
}

/** PRF salt pair for the PRF extension. */
export interface PRFSaltPair {
  first: string;   // base64url-encoded salt
  second?: string;  // optional second salt
}

/** PRF extension input shape. */
export interface PRFExtension {
  eval?: PRFSaltPair;
  evalByCredential?: Record<string, PRFSaltPair>;
}

/** Result emitted after successful passkey registration. */
export interface PasskeyRegistrationResult {
  credentialId: string;
  registered: boolean;
  prfSupported: boolean;
  prfOutput?: ArrayBuffer;
}

/** Result emitted after successful passkey authentication. */
export interface PasskeyAuthenticationResult {
  userId: string;
  authenticated: boolean;
  prfSupported?: boolean;
  prfOutput?: ArrayBuffer;
}

// --- Server API request/response shapes (matching server-go) ---

export interface BeginRegistrationRequest {
  userId: string;
  username: string;
}

export interface BeginRegistrationResponse {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ type: string; alg: number }>;
  authenticatorSelection: {
    residentKey: string;
    userVerification: string;
  };
  timeout: number;
  attestation: string;
  extensions?: {
    prf?: PRFExtension;
  };
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

export interface BeginAuthenticationResponse {
  challenge: string;
  rpId: string;
  timeout: number;
  userVerification: string;
  allowCredentials?: Array<{ type: string; id: string }>;
  extensions?: {
    prf?: PRFExtension;
  };
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
