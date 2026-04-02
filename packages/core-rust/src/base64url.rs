use base64ct::{Base64UrlUnpadded, Encoding};

use crate::types::WebAuthnError;

/// Decode a base64url-encoded string (no padding) into bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, WebAuthnError> {
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|_| WebAuthnError::InvalidInput("invalid base64url encoding".into()))
}

/// Encode bytes as base64url (no padding).
pub fn encode(input: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(input)
}
