use crate::base64url;
use crate::types::WebAuthnError;

/// Parsed client data from clientDataJSON.
pub struct ClientData {
    pub typ: String,
    pub challenge: String,
    pub origin: String,
    pub raw_bytes: Vec<u8>,
}

/// Verify client data JSON against expected values.
pub fn verify_client_data(
    client_data_json_b64: &str,
    expected_type: &str,
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<ClientData, WebAuthnError> {
    let raw_bytes = base64url::decode(client_data_json_b64)?;
    let json: serde_json::Value = serde_json::from_slice(&raw_bytes)
        .map_err(|e| WebAuthnError::InvalidInput(format!("invalid clientDataJSON: {}", e)))?;

    let typ = json["type"]
        .as_str()
        .ok_or_else(|| WebAuthnError::InvalidInput("missing type in clientDataJSON".into()))?
        .to_string();

    if typ != expected_type {
        return Err(WebAuthnError::TypeMismatch);
    }

    let challenge = json["challenge"]
        .as_str()
        .ok_or_else(|| {
            WebAuthnError::InvalidInput("missing challenge in clientDataJSON".into())
        })?
        .to_string();

    if challenge != expected_challenge {
        return Err(WebAuthnError::ChallengeMismatch);
    }

    let origin = json["origin"]
        .as_str()
        .ok_or_else(|| WebAuthnError::InvalidInput("missing origin in clientDataJSON".into()))?
        .to_string();

    if origin != expected_origin {
        return Err(WebAuthnError::OriginMismatch);
    }

    // Check tokenBinding
    if let Some(tb) = json.get("tokenBinding") {
        if let Some(status) = tb.get("status").and_then(|s| s.as_str()) {
            if status == "present" {
                return Err(WebAuthnError::TokenBindingUnsupported);
            }
        }
    }

    Ok(ClientData {
        typ,
        challenge,
        origin,
        raw_bytes,
    })
}
