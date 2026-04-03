use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct BeginRegistrationRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct CredentialResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

#[derive(Debug, Deserialize)]
pub struct FinishRegistrationCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: CredentialResponse,
}

#[derive(Debug, Deserialize)]
pub struct FinishRegistrationRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub credential: FinishRegistrationCredential,
    #[serde(rename = "prfSupported")]
    pub prf_supported: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct BeginAuthenticationRequest {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FinishAuthenticationCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: AuthenticationResponse,
}

#[derive(Debug, Deserialize)]
pub struct FinishAuthenticationRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub credential: FinishAuthenticationCredential,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
