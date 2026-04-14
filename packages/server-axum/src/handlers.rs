use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
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

use crate::session;
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
        return error_response(StatusCode::BAD_REQUEST, "userId is required").into_response();
    }

    let existing = state.credential_store.get_by_user(&req.user_id).unwrap_or_default();

    if !state.config.allow_multiple_credentials && !existing.is_empty() {
        return error_response(StatusCode::CONFLICT, "user already registered").into_response();
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

    let mut options = json!({
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
    });

    if !existing.is_empty() {
        let exclude_list: Vec<Value> = existing
            .iter()
            .map(|c| {
                json!({
                    "type": "public-key",
                    "id": b64url_encode(&c.credential_id),
                })
            })
            .collect();
        options["excludeCredentials"] = json!(exclude_list);
    }

    Json(options).into_response()
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
        rp_id: state.config.rp_id.clone(),
        expected_challenge: stored_challenge.to_string(),
        expected_origin: state.config.origin.clone(),
        client_data_json: req.credential.response.client_data_json.clone(),
        attestation_object: req.credential.response.attestation_object.clone(),
        require_user_verification: false,
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

    let resp = json!({
        "credentialId": b64url_encode(&result.credential_id),
        "registered": true,
        "prfSupported": prf_enabled,
    });

    if let Some(ref session_config) = state.session {
        let token = session::create_token(&req.user_id, session_config);
        let cookie_header = session::build_set_cookie_header(&token, session_config);
        let mut headers = HeaderMap::new();
        headers.insert(header::SET_COOKIE, cookie_header.parse().unwrap());
        (headers, Json(resp)).into_response()
    } else {
        Json(resp).into_response()
    }
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
        rp_id: state.config.rp_id.clone(),
        expected_challenge: challenge,
        expected_origin: state.config.origin.clone(),
        stored_public_key_cose: b64url_encode(&stored.public_key_cose),
        stored_sign_count: stored.sign_count,
        client_data_json: req.credential.response.client_data_json.clone(),
        authenticator_data: req.credential.response.authenticator_data.clone(),
        signature: req.credential.response.signature.clone(),
        require_user_verification: false,
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

    if let Some(ref session_config) = state.session {
        let token = session::create_token(&stored.user_id, session_config);
        let cookie_header = session::build_set_cookie_header(&token, session_config);
        let mut headers = HeaderMap::new();
        headers.insert(header::SET_COOKIE, cookie_header.parse().unwrap());
        (headers, Json(resp)).into_response()
    } else {
        Json(resp).into_response()
    }
}

pub async fn get_session(
    State(state): State<Arc<PasskeyState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let session_config = match &state.session {
        Some(c) => c,
        None => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "sessions not configured").into_response(),
    };

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());

    let token = match session::parse_cookie_token(cookie_header, session_config) {
        Some(t) => t,
        None => return error_response(StatusCode::UNAUTHORIZED, "no session token").into_response(),
    };

    match session::validate_token(&token, session_config) {
        Ok(data) => Json(json!({
            "userId": data.user_id,
            "authenticated": true,
        })).into_response(),
        Err(_) => error_response(StatusCode::UNAUTHORIZED, "invalid or expired session").into_response(),
    }
}

pub async fn logout(
    State(state): State<Arc<PasskeyState>>,
) -> impl IntoResponse {
    let session_config = match &state.session {
        Some(c) => c,
        None => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "sessions not configured").into_response(),
    };

    let cookie_header = session::build_clear_cookie_header(session_config);
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, cookie_header.parse().unwrap());
    (headers, Json(json!({"success": true}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChallengeStore, CredentialStore, MemoryChallengeStore, MemoryCredentialStore, PasskeyConfig, PasskeyState};

    fn test_config(allow_multiple: bool) -> PasskeyConfig {
        PasskeyConfig {
            rp_id: "example.com".into(),
            rp_display_name: "Example".into(),
            origin: "https://example.com".into(),
            challenge_length: 32,
            challenge_timeout_seconds: 300,
            allow_multiple_credentials: allow_multiple,
            session: None,
        }
    }

    fn fake_cred(user_id: &str, cred_id: u8) -> StoredCredential {
        StoredCredential {
            credential_id: vec![cred_id],
            public_key_cose: vec![0],
            sign_count: 0,
            user_id: user_id.to_string(),
            prf_salt: None,
            prf_supported: false,
        }
    }

    fn make_state(
        config: PasskeyConfig,
        cred_store: Arc<MemoryCredentialStore>,
    ) -> Arc<PasskeyState> {
        let challenge_store = Arc::new(MemoryChallengeStore::new());
        Arc::new(PasskeyState {
            config,
            challenge_store: challenge_store as Arc<dyn crate::ChallengeStore>,
            credential_store: cred_store as Arc<dyn crate::CredentialStore>,
            session: None,
        })
    }

    #[tokio::test]
    async fn begin_registration_rejects_409_when_user_has_credentials() {
        let cred_store = Arc::new(MemoryCredentialStore::new());
        cred_store.store(fake_cred("user-1", 1)).unwrap();
        let state = make_state(test_config(false), cred_store);

        let req = BeginRegistrationRequest {
            user_id: "user-1".into(),
            username: "alice".into(),
        };
        let resp = begin_registration(State(state), Json(req)).await.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn begin_registration_succeeds_with_allow_multiple() {
        let cred_store = Arc::new(MemoryCredentialStore::new());
        cred_store.store(fake_cred("user-1", 1)).unwrap();
        let state = make_state(test_config(true), cred_store);

        let req = BeginRegistrationRequest {
            user_id: "user-1".into(),
            username: "alice".into(),
        };
        let resp = begin_registration(State(state), Json(req)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn begin_registration_includes_exclude_credentials() {
        let cred_store = Arc::new(MemoryCredentialStore::new());
        cred_store.store(fake_cred("user-1", 1)).unwrap();
        cred_store.store(fake_cred("user-1", 2)).unwrap();
        let state = make_state(test_config(true), cred_store);

        let req = BeginRegistrationRequest {
            user_id: "user-1".into(),
            username: "alice".into(),
        };
        let resp = begin_registration(State(state), Json(req)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let exclude = json["excludeCredentials"].as_array().unwrap();
        assert_eq!(exclude.len(), 2);
        assert_eq!(exclude[0]["type"], "public-key");
        assert_eq!(exclude[1]["type"], "public-key");
    }

    #[tokio::test]
    async fn begin_registration_no_exclude_credentials_for_new_user() {
        let cred_store = Arc::new(MemoryCredentialStore::new());
        let state = make_state(test_config(false), cred_store);

        let req = BeginRegistrationRequest {
            user_id: "new-user".into(),
            username: "bob".into(),
        };
        let resp = begin_registration(State(state), Json(req)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("excludeCredentials").is_none());
    }
}
