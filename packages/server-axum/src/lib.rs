//! Axum handlers for open-passkey WebAuthn/FIDO2 authentication.
//!
//! # Usage
//!
//! ```rust,no_run
//! use open_passkey_axum::{passkey_router, PasskeyConfig, MemoryChallengeStore, MemoryCredentialStore};
//! use std::sync::Arc;
//!
//! let config = PasskeyConfig {
//!     rp_id: "example.com".into(),
//!     rp_display_name: "Example".into(),
//!     origin: "https://example.com".into(),
//!     challenge_length: 32,
//!     challenge_timeout_seconds: 300,
//!     session: None,
//! };
//!
//! let challenge_store = Arc::new(MemoryChallengeStore::new());
//! let credential_store = Arc::new(MemoryCredentialStore::new());
//! let app = passkey_router(config, challenge_store, credential_store);
//! ```

pub mod handlers;
pub mod session;
pub mod stores;
pub mod types;

use axum::{routing::{get, post}, Router};
use std::sync::Arc;

use session::SessionConfig;

pub use stores::{
    ChallengeStore, CredentialStore, MemoryChallengeStore, MemoryCredentialStore, PasskeyError,
    StoredCredential,
};

/// Configuration for the passkey router.
pub struct PasskeyConfig {
    pub rp_id: String,
    pub rp_display_name: String,
    pub origin: String,
    pub challenge_length: usize,
    pub challenge_timeout_seconds: u64,
    pub session: Option<SessionConfig>,
}

impl PasskeyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.rp_id.is_empty() {
            return Err("rp_id is required".into());
        }
        if self.origin.is_empty() {
            return Err("origin is required".into());
        }
        if self.rp_id.contains("://") || self.rp_id.contains('/') {
            return Err(format!("rp_id must be a bare domain (got '{}')", self.rp_id));
        }
        if !self.origin.starts_with("https://") && !self.origin.starts_with("http://") {
            return Err(format!(
                "origin must start with https:// or http:// (got '{}')",
                self.origin
            ));
        }
        Ok(())
    }
}

/// Shared state passed to all handlers via Axum's State extractor.
pub struct PasskeyState {
    pub config: PasskeyConfig,
    pub challenge_store: Arc<dyn ChallengeStore>,
    pub credential_store: Arc<dyn CredentialStore>,
    pub session: Option<SessionConfig>,
}

impl PasskeyState {
    pub fn new(
        config: PasskeyConfig,
        challenge_store: Arc<dyn ChallengeStore>,
        credential_store: Arc<dyn CredentialStore>,
    ) -> Self {
        Self {
            config,
            challenge_store,
            credential_store,
            session: None,
        }
    }
}

/// Create an Axum Router with the 4 WebAuthn passkey endpoints.
/// If `config.session` is set, also registers GET /session and POST /logout.
pub fn passkey_router(
    config: PasskeyConfig,
    challenge_store: Arc<dyn ChallengeStore>,
    credential_store: Arc<dyn CredentialStore>,
) -> Router {
    config.validate().expect("invalid passkey config");

    if let Some(ref session_config) = config.session {
        session::validate_config(session_config).expect("invalid session config");
    }

    let session_config = config.session.clone();
    let mut state = PasskeyState::new(config, challenge_store, credential_store);
    state.session = session_config;
    let state = Arc::new(state);

    let mut router = Router::new()
        .route("/register/begin", post(handlers::begin_registration))
        .route("/register/finish", post(handlers::finish_registration))
        .route("/login/begin", post(handlers::begin_authentication))
        .route("/login/finish", post(handlers::finish_authentication));

    if state.session.is_some() {
        router = router
            .route("/session", get(handlers::get_session))
            .route("/logout", post(handlers::logout));
    }

    router.with_state(state)
}
