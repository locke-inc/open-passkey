use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
};
use sha2::{Digest, Sha256};

use crate::types::WebAuthnError;

/// Expected ML-DSA-65 public key size in bytes.
pub const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;

/// Expected ML-DSA-65 signature size in bytes.
pub const MLDSA65_SIGNATURE_SIZE: usize = 3309;

/// Verify an ML-DSA-65 detached signature.
///
/// ML-DSA signs the message directly (no additional hashing).
/// Verification data = authData || SHA256(clientDataJSON).
pub fn verify_mldsa65(
    public_key_bytes: &[u8],
    auth_data: &[u8],
    client_data_json_raw: &[u8],
    signature_bytes: &[u8],
) -> Result<(), WebAuthnError> {
    if public_key_bytes.len() != MLDSA65_PUBLIC_KEY_SIZE {
        return Err(WebAuthnError::SignatureInvalid);
    }

    let pk = dilithium3::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| WebAuthnError::SignatureInvalid)?;

    let sig = dilithium3::DetachedSignature::from_bytes(signature_bytes)
        .map_err(|_| WebAuthnError::SignatureInvalid)?;

    // Verification data = authData || SHA256(clientDataJSON)
    let client_data_hash = Sha256::digest(client_data_json_raw);
    let mut verification_data = Vec::with_capacity(auth_data.len() + 32);
    verification_data.extend_from_slice(auth_data);
    verification_data.extend_from_slice(&client_data_hash);

    dilithium3::verify_detached_signature(&sig, &verification_data, &pk)
        .map_err(|_| WebAuthnError::SignatureInvalid)
}
