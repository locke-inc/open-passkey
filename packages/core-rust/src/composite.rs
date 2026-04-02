use crate::es256;
use crate::mldsa65;
use crate::types::WebAuthnError;

/// Composite ML-DSA-65-ES256 public key size: 1952 (ML-DSA-65) + 65 (ECDSA uncompressed) = 2017 bytes.
pub const COMPOSITE_PUBLIC_KEY_SIZE: usize = 2017;

/// Verify a composite ML-DSA-65-ES256 signature.
///
/// Signature format: 4-byte big-endian ML-DSA sig length || ML-DSA-65 sig || ES256 DER sig.
/// Both components sign over the same data: authData || SHA256(clientDataJSON).
/// Both must verify independently for the composite to be valid.
pub fn verify_composite(
    public_key_bytes: &[u8],
    auth_data: &[u8],
    client_data_json_raw: &[u8],
    signature_bytes: &[u8],
) -> Result<(), WebAuthnError> {
    if public_key_bytes.len() != COMPOSITE_PUBLIC_KEY_SIZE {
        return Err(WebAuthnError::SignatureInvalid);
    }

    // Split public key: first 1952 = ML-DSA-65, last 65 = ECDSA uncompressed point
    let mldsa_pk = &public_key_bytes[..mldsa65::MLDSA65_PUBLIC_KEY_SIZE];
    let ecdsa_pk = &public_key_bytes[mldsa65::MLDSA65_PUBLIC_KEY_SIZE..];

    // Split signature: 4-byte length prefix, then ML-DSA sig, then ES256 DER sig
    if signature_bytes.len() < 4 {
        return Err(WebAuthnError::SignatureInvalid);
    }
    let mldsa_sig_len = u32::from_be_bytes([
        signature_bytes[0],
        signature_bytes[1],
        signature_bytes[2],
        signature_bytes[3],
    ]) as usize;

    let mldsa_sig_end = 4 + mldsa_sig_len;
    if signature_bytes.len() < mldsa_sig_end {
        return Err(WebAuthnError::SignatureInvalid);
    }

    let mldsa_sig = &signature_bytes[4..mldsa_sig_end];
    let ecdsa_sig = &signature_bytes[mldsa_sig_end..];

    // Both must verify
    mldsa65::verify_mldsa65(mldsa_pk, auth_data, client_data_json_raw, mldsa_sig)?;
    es256::verify_es256_uncompressed(ecdsa_pk, auth_data, client_data_json_raw, ecdsa_sig)?;

    Ok(())
}
