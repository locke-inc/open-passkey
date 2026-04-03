use ciborium::Value;
use sha2::{Digest, Sha256};

use crate::types::WebAuthnError;

/// Verify packed attestation statement.
///
/// - Empty attStmt (no alg, no sig): error (invalid_attestation_statement)
/// - Self attestation (alg + sig, no x5c): verify sig with credential public key
/// - Full attestation (alg + sig + x5c): verify sig with x5c[0] certificate
pub fn verify_packed_attestation(
    att_stmt: &[(Value, Value)],
    auth_data_bytes: &[u8],
    client_data_json_raw: &[u8],
    cred_public_key_cose: &[u8],
) -> Result<(), WebAuthnError> {
    let alg = get_cbor_int(att_stmt, "alg");
    let sig = get_cbor_bytes(att_stmt, "sig");
    let x5c = get_cbor_array(att_stmt, "x5c");

    // Must have alg and sig
    let _alg_val = alg.ok_or(WebAuthnError::InvalidAttestationStatement)?;
    let sig_bytes = sig.ok_or(WebAuthnError::InvalidAttestationStatement)?;

    // Verification data = authData || SHA256(clientDataJSON)
    let client_data_hash = Sha256::digest(client_data_json_raw);
    let mut verification_data = Vec::with_capacity(auth_data_bytes.len() + 32);
    verification_data.extend_from_slice(auth_data_bytes);
    verification_data.extend_from_slice(&client_data_hash);

    if let Some(x5c_certs) = x5c {
        // Full attestation: verify with x5c[0]
        if x5c_certs.is_empty() {
            return Err(WebAuthnError::InvalidAttestationStatement);
        }
        let cert_bytes = match &x5c_certs[0] {
            Value::Bytes(b) => b,
            _ => return Err(WebAuthnError::InvalidAttestationStatement),
        };
        verify_with_x509_cert(cert_bytes, &verification_data, &sig_bytes)
    } else {
        // Self attestation: verify with credential public key
        verify_self_attestation(cred_public_key_cose, &verification_data, &sig_bytes)
    }
}

/// Verify self-attestation using the credential's COSE public key.
fn verify_self_attestation(
    cose_key_bytes: &[u8],
    verification_data: &[u8],
    signature_der: &[u8],
) -> Result<(), WebAuthnError> {
    // Parse COSE key to extract x, y for ES256
    let cose_key: Value = ciborium::from_reader(cose_key_bytes)
        .map_err(|_| WebAuthnError::InvalidInput("invalid COSE key CBOR".into()))?;

    let map = match &cose_key {
        Value::Map(m) => m,
        _ => return Err(WebAuthnError::InvalidInput("COSE key not a map".into())),
    };

    let x = get_cose_bytes(map, -2)
        .ok_or_else(|| WebAuthnError::InvalidInput("missing x in COSE key".into()))?;
    let y = get_cose_bytes(map, -3)
        .ok_or_else(|| WebAuthnError::InvalidInput("missing y in COSE key".into()))?;

    // For self-attestation, we verify directly against verification_data
    // We need to use the raw verify (not the one that computes authData||hash internally)
    let point = p256::EncodedPoint::from_affine_coordinates(
        p256::FieldBytes::from_slice(&x),
        p256::FieldBytes::from_slice(&y),
        false,
    );
    let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
        .map_err(|_| WebAuthnError::SignatureInvalid)?;

    let sig = p256::ecdsa::Signature::from_der(signature_der)
        .map_err(|_| WebAuthnError::SignatureInvalid)?;

    use p256::ecdsa::signature::Verifier;
    verifying_key
        .verify(verification_data, &sig)
        .map_err(|_| WebAuthnError::SignatureInvalid)
}

/// Verify full attestation using x5c[0] certificate.
fn verify_with_x509_cert(
    cert_der: &[u8],
    verification_data: &[u8],
    signature_der: &[u8],
) -> Result<(), WebAuthnError> {
    use der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der)
        .map_err(|_| WebAuthnError::InvalidAttestationStatement)?;

    // Extract the public key from the certificate
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pub_key_bytes = spki.subject_public_key.raw_bytes();

    // For EC keys, the public key in SPKI is the uncompressed point
    if pub_key_bytes.len() != 65 || pub_key_bytes[0] != 0x04 {
        return Err(WebAuthnError::InvalidAttestationStatement);
    }

    let x = &pub_key_bytes[1..33];
    let y = &pub_key_bytes[33..65];

    let point = p256::EncodedPoint::from_affine_coordinates(
        p256::FieldBytes::from_slice(x),
        p256::FieldBytes::from_slice(y),
        false,
    );
    let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
        .map_err(|_| WebAuthnError::InvalidAttestationStatement)?;

    let sig = p256::ecdsa::Signature::from_der(signature_der)
        .map_err(|_| WebAuthnError::SignatureInvalid)?;

    use p256::ecdsa::signature::Verifier;
    verifying_key
        .verify(verification_data, &sig)
        .map_err(|_| WebAuthnError::SignatureInvalid)
}

/// Helper to get an integer value from a CBOR map with string key.
fn get_cbor_int(map: &[(Value, Value)], key: &str) -> Option<i128> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .and_then(|(_, v)| match v {
            Value::Integer(i) => Some(i128::from(*i)),
            _ => None,
        })
}

/// Helper to get bytes from a CBOR map with string key.
fn get_cbor_bytes(map: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .and_then(|(_, v)| match v {
            Value::Bytes(b) => Some(b.clone()),
            _ => None,
        })
}

/// Helper to get an array from a CBOR map with string key.
fn get_cbor_array(map: &[(Value, Value)], key: &str) -> Option<Vec<Value>> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .and_then(|(_, v)| match v {
            Value::Array(a) => Some(a.clone()),
            _ => None,
        })
}

/// Helper to get bytes from a COSE key map with integer key.
fn get_cose_bytes(map: &[(Value, Value)], key: i128) -> Option<Vec<u8>> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key))
        .and_then(|(_, v)| match v {
            Value::Bytes(b) => Some(b.clone()),
            _ => None,
        })
}
