pub mod authdata;
pub mod base64url;
pub mod clientdata;
pub mod composite;
pub mod cose;
pub mod es256;
pub mod mldsa65;
pub mod packed;
pub mod types;
pub mod webauthn;

pub use types::{
    AuthenticationInput, AuthenticationResult, RegistrationInput, RegistrationResult, WebAuthnError,
};
pub use webauthn::{verify_authentication, verify_registration};
