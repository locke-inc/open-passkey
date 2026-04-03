/** Configuration for the passkey service. */
export interface PasskeyConfig {
  /** Base URL for the passkey server endpoints (e.g., "/passkey" or "https://api.example.com/passkey"). */
  baseUrl: string;
}

// Re-export SDK result types for convenience
export type {
  RegistrationResult as PasskeyRegistrationResult,
  AuthenticationResult as PasskeyAuthenticationResult,
} from "@open-passkey/sdk";
