use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

use open_passkey_core::{
    AuthenticationInput, RegistrationInput, verify_authentication, verify_registration,
};

use crate::stores::{PasskeyError, StoredCredential};
use crate::types::*;
use crate::PasskeyState;

fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, PasskeyError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| PasskeyError::BadRequest("invalid base64url encoding".into()))
}

fn generate_challenge(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    b64url_encode(&buf)
}

fn error_response(status: StatusCode, msg: &str) -> impl IntoResponse {
    (status, Json(json!({"error": msg})))
}

pub async fn begin_registration(
    State(state): State<Arc<PasskeyState>>,
    Json(req): Json<BeginRegistrationRequest>,
) -> impl IntoResponse {
    if req.user_id.is_empty() || req.username.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "userId and username are required").into_response();
    }

    let challenge = generate_challenge(state.config.challenge_length);
    let mut prf_salt = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut prf_salt);

    let challenge_data = json!({
        "challenge": challenge,
        "prfSalt": b64url_encode(&prf_salt),
    })
    .to_string();

    let timeout = Duration::from_secs(state.config.challenge_timeout_seconds);
    if let Err(_) = state.challenge_store.store(&req.user_id, &challenge_data, timeout) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to store challenge").into_response();
    }

    Json(json!({
        "challenge": challenge,
        "rp": { "id": state.config.rp_id, "name": state.config.rp_display_name },
        "user": {
            "id": b64url_encode(req.user_id.as_bytes()),
            "name": req.username,
            "displayName": req.username,
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -52 },
            { "type": "public-key", "alg": -49 },
            { "type": "public-key", "alg": -7 },
        ],
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "preferred",
        },
        "timeout": state.config.challenge_timeout_seconds * 1000,
        "attestation": "none",
        "extensions": {
            "prf": { "eval": { "first": b64url_encode(&prf_salt) } },
        },
    }))
    .into_response()
}

pub async fn finish_registration(
    State(state): State<Arc<PasskeyState>>,
    Json(req): Json<FinishRegistrationRequest>,
) -> impl IntoResponse {
    let challenge_data_str = match state.challenge_store.consume(&req.user_id) {
        Ok(c) => c,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "challenge not found or expired").into_response(),
    };

    let challenge_data: Value = serde_json::from_str(&challenge_data_str).unwrap();
    let stored_challenge = challenge_data["challenge"].as_str().unwrap();
    let stored_prf_salt = challenge_data["prfSalt"].as_str().unwrap();

    let result = match verify_registration(RegistrationInput {
        rp_id: &state.config.rp_id,
        expected_challenge: stored_challenge,
        expected_origin: &state.config.origin,
        client_data_json: &req.credential.response.client_data_json,
        attestation_object: &req.credential.response.attestation_object,
    }) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("registration verification failed: {}", e);
            return error_response(StatusCode::BAD_REQUEST, "registration verification failed").into_response();
        }
    };

    let prf_enabled = req.prf_supported.unwrap_or(false);
    let mut cred = StoredCredential {
        credential_id: result.credential_id.clone(),
        public_key_cose: result.public_key_cose.clone(),
        sign_count: result.sign_count,
        user_id: req.user_id.clone(),
        prf_salt: None,
        prf_supported: false,
    };
    if prf_enabled {
        if let Ok(salt) = b64url_decode(stored_prf_salt) {
            cred.prf_salt = Some(salt);
            cred.prf_supported = true;
        }
    }

    if let Err(_) = state.credential_store.store(cred) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to store credential").into_response();
    }

    Json(json!({
        "credentialId": b64url_encode(&result.credential_id),
        "registered": true,
        "prfSupported": prf_enabled,
    }))
    .into_response()
}

pub async fn begin_authentication(
    State(state): State<Arc<PasskeyState>>,
    body: Option<Json<BeginAuthenticationRequest>>,
) -> impl IntoResponse {
    let user_id = body.and_then(|b| b.0.user_id);

    let challenge = generate_challenge(state.config.challenge_length);
    let challenge_key = user_id.as_deref().filter(|s| !s.is_empty()).unwrap_or(&challenge);
    let timeout = Duration::from_secs(state.config.challenge_timeout_seconds);

    if let Err(_) = state.challenge_store.store(challenge_key, &challenge, timeout) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to store challenge").into_response();
    }

    let mut options = json!({
        "challenge": challenge,
        "rpId": state.config.rp_id,
        "timeout": state.config.challenge_timeout_seconds * 1000,
        "userVerification": "preferred",
    });

    if let Some(ref uid) = user_id {
        if !uid.is_empty() {
            let mut allow_credentials: Vec<Value> = Vec::new();
            let mut eval_by_credential = serde_json::Map::new();
            let mut has_prf = false;

            if let Ok(creds) = state.credential_store.get_by_user(uid) {
                for c in &creds {
                    let cred_id_encoded = b64url_encode(&c.credential_id);
                    allow_credentials.push(json!({"type": "public-key", "id": cred_id_encoded}));
                    if c.prf_supported {
                        if let Some(ref salt) = c.prf_salt {
                            eval_by_credential.insert(
                                cred_id_encoded,
                                json!({"first": b64url_encode(salt)}),
                            );
                            has_prf = true;
                        }
                    }
                }
            }
            options["allowCredentials"] = json!(allow_credentials);
            if has_prf {
                options["extensions"] = json!({"prf": {"evalByCredential": eval_by_credential}});
            }
        }
    }

    Json(options).into_response()
}

pub async fn finish_authentication(
    State(state): State<Arc<PasskeyState>>,
    Json(req): Json<FinishAuthenticationRequest>,
) -> impl IntoResponse {
    let challenge = match state.challenge_store.consume(&req.user_id) {
        Ok(c) => c,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "challenge not found or expired").into_response(),
    };

    let cred_id_bytes = match b64url_decode(&req.credential.id) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid credential ID encoding").into_response(),
    };

    let stored = match state.credential_store.get(&cred_id_bytes) {
        Ok(c) => c,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "credential not found").into_response(),
    };

    if let Some(ref user_handle) = req.credential.response.user_handle {
        if !user_handle.is_empty() {
            if let Ok(decoded) = b64url_decode(user_handle) {
                let decoded_str = String::from_utf8_lossy(&decoded);
                if decoded_str != stored.user_id {
                    return error_response(StatusCode::BAD_REQUEST, "userHandle does not match credential owner")
                        .into_response();
                }
            }
        }
    }

    let result = match verify_authentication(AuthenticationInput {
        rp_id: &state.config.rp_id,
        expected_challenge: &challenge,
        expected_origin: &state.config.origin,
        stored_public_key_cose: &stored.public_key_cose,
        stored_sign_count: stored.sign_count,
        client_data_json: &req.credential.response.client_data_json,
        authenticator_data: &req.credential.response.authenticator_data,
        signature: &req.credential.response.signature,
    }) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("authentication verification failed: {}", e);
            return error_response(StatusCode::BAD_REQUEST, "authentication verification failed").into_response();
        }
    };

    let mut updated = stored.clone();
    updated.sign_count = result.sign_count;
    if let Err(_) = state.credential_store.update(updated) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to update credential").into_response();
    }

    let mut resp = json!({
        "userId": stored.user_id,
        "authenticated": true,
    });
    if stored.prf_supported {
        resp["prfSupported"] = json!(true);
    }

    Json(resp).into_response()
}
