use std::fmt;

/// Error type for WebAuthn verification failures.
#[derive(Debug, Clone)]
pub enum WebAuthnError {
    TypeMismatch,
    ChallengeMismatch,
    OriginMismatch,
    RpIdMismatch,
    SignatureInvalid,
    UnsupportedCoseAlgorithm,
    SignCountRollback,
    UserPresenceRequired,
    UserVerificationRequired,
    UnsupportedAttestationFormat,
    TokenBindingUnsupported,
    InvalidBackupState,
    InvalidAttestationStatement,
    /// Generic input parsing error (not a spec error code).
    InvalidInput(String),
}

impl WebAuthnError {
    /// Return the machine-readable error code string.
    pub fn code(&self) -> &str {
        match self {
            WebAuthnError::TypeMismatch => "type_mismatch",
            WebAuthnError::ChallengeMismatch => "challenge_mismatch",
            WebAuthnError::OriginMismatch => "origin_mismatch",
            WebAuthnError::RpIdMismatch => "rp_id_mismatch",
            WebAuthnError::SignatureInvalid => "signature_invalid",
            WebAuthnError::UnsupportedCoseAlgorithm => "unsupported_cose_algorithm",
            WebAuthnError::SignCountRollback => "sign_count_rollback",
            WebAuthnError::UserPresenceRequired => "user_presence_required",
            WebAuthnError::UserVerificationRequired => "user_verification_required",
            WebAuthnError::UnsupportedAttestationFormat => "unsupported_attestation_format",
            WebAuthnError::TokenBindingUnsupported => "token_binding_unsupported",
            WebAuthnError::InvalidBackupState => "invalid_backup_state",
            WebAuthnError::InvalidAttestationStatement => "invalid_attestation_statement",
            WebAuthnError::InvalidInput(_) => "invalid_input",
        }
    }
}

impl fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebAuthnError::InvalidInput(msg) => write!(f, "invalid input: {}", msg),
            other => write!(f, "{}", other.code()),
        }
    }
}

impl std::error::Error for WebAuthnError {}

/// Input for registration verification.
pub struct RegistrationInput {
    pub attestation_object: String,
    pub client_data_json: String,
    pub expected_challenge: String,
    pub expected_origin: String,
    pub rp_id: String,
    pub require_user_verification: bool,
}

/// Successful registration result.
#[derive(Debug)]
pub struct RegistrationResult {
    pub credential_id: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub sign_count: u32,
    pub rp_id_hash: Vec<u8>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// Input for authentication verification.
pub struct AuthenticationInput {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub expected_challenge: String,
    pub expected_origin: String,
    pub rp_id: String,
    pub stored_public_key_cose: String,
    pub stored_sign_count: u32,
    pub require_user_verification: bool,
}

/// Successful authentication result.
#[derive(Debug)]
pub struct AuthenticationResult {
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
}
