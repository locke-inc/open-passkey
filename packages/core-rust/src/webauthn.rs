use ciborium::Value;

use crate::authdata;
use crate::base64url;
use crate::clientdata;
use crate::composite;
use crate::cose;
use crate::es256;
use crate::mldsa65;
use crate::packed;
use crate::types::{
    AuthenticationInput, AuthenticationResult, RegistrationInput, RegistrationResult, WebAuthnError,
};

/// Helper to get a value from a COSE key CBOR map by integer key.
fn get_cose_int_value(map: &[(Value, Value)], key: i128) -> Option<i128> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key))
        .and_then(|(_, v)| match v {
            Value::Integer(i) => Some(i128::from(*i)),
            _ => None,
        })
}

fn get_cose_bytes(map: &[(Value, Value)], key: i128) -> Option<Vec<u8>> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key))
        .and_then(|(_, v)| match v {
            Value::Bytes(b) => Some(b.clone()),
            _ => None,
        })
}

/// Verify a WebAuthn registration ceremony.
pub fn verify_registration(input: RegistrationInput) -> Result<RegistrationResult, WebAuthnError> {
    // 1. Verify client data
    let client_data = clientdata::verify_client_data(
        &input.client_data_json,
        "webauthn.create",
        &input.expected_challenge,
        &input.expected_origin,
    )?;

    // 2. Decode attestation object (CBOR)
    let att_obj_bytes = base64url::decode(&input.attestation_object)?;
    let att_obj: Value = ciborium::from_reader(att_obj_bytes.as_slice())
        .map_err(|e| WebAuthnError::InvalidInput(format!("invalid attestation object CBOR: {}", e)))?;

    let att_map = match &att_obj {
        Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidInput(
                "attestation object not a map".into(),
            ))
        }
    };

    // Extract fmt
    let fmt = att_map
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == "fmt"))
        .and_then(|(_, v)| match v {
            Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .unwrap_or("none");

    // Extract attStmt
    let att_stmt = att_map
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == "attStmt"))
        .and_then(|(_, v)| match v {
            Value::Map(m) => Some(m.as_slice()),
            _ => None,
        });

    // Extract authData
    let auth_data_bytes = att_map
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == "authData"))
        .and_then(|(_, v)| match v {
            Value::Bytes(b) => Some(b.clone()),
            _ => None,
        })
        .ok_or_else(|| WebAuthnError::InvalidInput("missing authData in attestation object".into()))?;

    // 3. Parse authenticator data
    let auth_data = authdata::parse_auth_data(&auth_data_bytes)?;

    // 4. Verify RP ID hash
    authdata::verify_rp_id_hash(&auth_data.rp_id_hash, &input.rp_id)?;

    // 5. Verify flags
    authdata::verify_flags(&auth_data, input.require_user_verification)?;

    // 6. Extract credential data
    let credential_id = auth_data
        .credential_id
        .as_ref()
        .ok_or_else(|| WebAuthnError::InvalidInput("no credential id in auth data".into()))?
        .clone();

    let cred_public_key_bytes = auth_data
        .credential_public_key
        .as_ref()
        .ok_or_else(|| WebAuthnError::InvalidInput("no public key in auth data".into()))?
        .clone();

    // 7. Verify attestation
    match fmt {
        "none" => {
            // No verification needed
        }
        "packed" => {
            let stmt = att_stmt.ok_or(WebAuthnError::InvalidAttestationStatement)?;
            packed::verify_packed_attestation(
                stmt,
                &auth_data_bytes,
                &client_data.raw_bytes,
                &cred_public_key_bytes,
            )?;
        }
        _ => {
            return Err(WebAuthnError::UnsupportedAttestationFormat);
        }
    }

    Ok(RegistrationResult {
        credential_id,
        public_key_cose: cred_public_key_bytes,
        sign_count: auth_data.sign_count,
        rp_id_hash: auth_data.rp_id_hash,
        backup_eligible: auth_data.backup_eligible(),
        backup_state: auth_data.backup_state(),
    })
}

/// Verify a WebAuthn authentication ceremony.
pub fn verify_authentication(
    input: AuthenticationInput,
) -> Result<AuthenticationResult, WebAuthnError> {
    // 1. Verify client data
    let client_data = clientdata::verify_client_data(
        &input.client_data_json,
        "webauthn.get",
        &input.expected_challenge,
        &input.expected_origin,
    )?;

    // 2. Decode authenticator data
    let auth_data_bytes = base64url::decode(&input.authenticator_data)?;
    let auth_data = authdata::parse_auth_data(&auth_data_bytes)?;

    // 3. Verify RP ID hash
    authdata::verify_rp_id_hash(&auth_data.rp_id_hash, &input.rp_id)?;

    // 4. Verify flags
    authdata::verify_flags(&auth_data, input.require_user_verification)?;

    // 5. Check sign count rollback
    if input.stored_sign_count > 0 && auth_data.sign_count <= input.stored_sign_count {
        return Err(WebAuthnError::SignCountRollback);
    }

    // 6. Decode stored public key and verify signature
    let stored_key_bytes = base64url::decode(&input.stored_public_key_cose)?;
    let signature_bytes = base64url::decode(&input.signature)?;

    let cose_key: Value = ciborium::from_reader(stored_key_bytes.as_slice())
        .map_err(|e| WebAuthnError::InvalidInput(format!("invalid COSE key CBOR: {}", e)))?;

    let map = match &cose_key {
        Value::Map(m) => m.as_slice(),
        _ => return Err(WebAuthnError::InvalidInput("COSE key not a map".into())),
    };

    let alg = get_cose_int_value(map, cose::COSE_KEY_ALG)
        .ok_or(WebAuthnError::UnsupportedCoseAlgorithm)?;

    match alg {
        cose::COSE_ALG_ES256 => {
            let x = get_cose_bytes(map, cose::COSE_KEY_X)
                .ok_or_else(|| WebAuthnError::InvalidInput("missing x in COSE key".into()))?;
            let y = get_cose_bytes(map, cose::COSE_KEY_Y)
                .ok_or_else(|| WebAuthnError::InvalidInput("missing y in COSE key".into()))?;

            es256::verify_es256(
                &x,
                &y,
                &auth_data_bytes,
                &client_data.raw_bytes,
                &signature_bytes,
            )?;
        }
        cose::COSE_ALG_MLDSA65 => {
            let pub_key = get_cose_bytes(map, cose::COSE_KEY_PUB)
                .ok_or_else(|| {
                    WebAuthnError::InvalidInput("missing pub in COSE key".into())
                })?;

            mldsa65::verify_mldsa65(
                &pub_key,
                &auth_data_bytes,
                &client_data.raw_bytes,
                &signature_bytes,
            )?;
        }
        cose::COSE_ALG_COMPOSITE_MLDSA65_ES256 => {
            let pub_key = get_cose_bytes(map, cose::COSE_KEY_PUB)
                .ok_or_else(|| {
                    WebAuthnError::InvalidInput("missing pub in COSE key".into())
                })?;

            composite::verify_composite(
                &pub_key,
                &auth_data_bytes,
                &client_data.raw_bytes,
                &signature_bytes,
            )?;
        }
        _ => {
            return Err(WebAuthnError::UnsupportedCoseAlgorithm);
        }
    }

    Ok(AuthenticationResult {
        sign_count: auth_data.sign_count,
        backup_eligible: auth_data.backup_eligible(),
        backup_state: auth_data.backup_state(),
    })
}
