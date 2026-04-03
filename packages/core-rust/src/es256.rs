use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;
use sha2::{Digest, Sha256};

use crate::types::WebAuthnError;

/// Verify an ES256 (ECDSA P-256 with SHA-256) signature.
///
/// `x` and `y` are the 32-byte affine coordinates of the public key.
/// `auth_data` is the raw authenticator data bytes.
/// `client_data_json_raw` is the raw clientDataJSON bytes.
/// `signature_der` is the DER-encoded ECDSA signature.
pub fn verify_es256(
    x: &[u8],
    y: &[u8],
    auth_data: &[u8],
    client_data_json_raw: &[u8],
    signature_der: &[u8],
) -> Result<(), WebAuthnError> {
    // Build the uncompressed point: 0x04 || x || y
    let point = EncodedPoint::from_affine_coordinates(
        p256::FieldBytes::from_slice(x),
        p256::FieldBytes::from_slice(y),
        false,
    );

    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|_| WebAuthnError::SignatureInvalid)?;

    // Verification data = authData || SHA256(clientDataJSON)
    let client_data_hash = Sha256::digest(client_data_json_raw);
    let mut verification_data = Vec::with_capacity(auth_data.len() + 32);
    verification_data.extend_from_slice(auth_data);
    verification_data.extend_from_slice(&client_data_hash);

    let sig = Signature::from_der(signature_der)
        .map_err(|_| WebAuthnError::SignatureInvalid)?;

    verifying_key
        .verify(&verification_data, &sig)
        .map_err(|_| WebAuthnError::SignatureInvalid)
}

/// Verify ES256 from an uncompressed public key point (65 bytes: 0x04 || x || y).
pub fn verify_es256_uncompressed(
    uncompressed_key: &[u8],
    auth_data: &[u8],
    client_data_json_raw: &[u8],
    signature_der: &[u8],
) -> Result<(), WebAuthnError> {
    if uncompressed_key.len() != 65 || uncompressed_key[0] != 0x04 {
        return Err(WebAuthnError::SignatureInvalid);
    }
    verify_es256(
        &uncompressed_key[1..33],
        &uncompressed_key[33..65],
        auth_data,
        client_data_json_raw,
        signature_der,
    )
}
