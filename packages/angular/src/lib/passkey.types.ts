// Re-export PasskeyClientConfig as PasskeyConfig for Angular idiomatic naming
export type { PasskeyClientConfig as PasskeyConfig } from "@open-passkey/sdk";

// Re-export SDK result types for convenience
export type {
  RegistrationResult as PasskeyRegistrationResult,
  AuthenticationResult as PasskeyAuthenticationResult,
} from "@open-passkey/sdk";
