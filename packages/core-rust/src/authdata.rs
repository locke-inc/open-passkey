use sha2::{Digest, Sha256};

use crate::types::WebAuthnError;

/// Flags in authenticator data.
pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_BE: u8 = 0x08;
pub const FLAG_BS: u8 = 0x10;
pub const FLAG_AT: u8 = 0x40;

/// Parsed authenticator data.
pub struct AuthenticatorData {
    pub rp_id_hash: Vec<u8>,
    pub flags: u8,
    pub sign_count: u32,
    pub aaguid: Option<Vec<u8>>,
    pub credential_id: Option<Vec<u8>>,
    pub credential_public_key: Option<Vec<u8>>,
    pub raw: Vec<u8>,
}

impl AuthenticatorData {
    pub fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }

    pub fn user_verified(&self) -> bool {
        self.flags & FLAG_UV != 0
    }

    pub fn backup_eligible(&self) -> bool {
        self.flags & FLAG_BE != 0
    }

    pub fn backup_state(&self) -> bool {
        self.flags & FLAG_BS != 0
    }

    pub fn has_attested_credential(&self) -> bool {
        self.flags & FLAG_AT != 0
    }
}

/// Parse raw authenticator data bytes.
pub fn parse_auth_data(data: &[u8]) -> Result<AuthenticatorData, WebAuthnError> {
    if data.len() < 37 {
        return Err(WebAuthnError::InvalidInput(
            "authenticator data too short".into(),
        ));
    }

    let rp_id_hash = data[0..32].to_vec();
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    let mut aaguid = None;
    let mut credential_id = None;
    let mut credential_public_key = None;

    if flags & FLAG_AT != 0 {
        if data.len() < 55 {
            return Err(WebAuthnError::InvalidInput(
                "authenticator data too short for attested credential".into(),
            ));
        }
        aaguid = Some(data[37..53].to_vec());
        let cred_id_len = u16::from_be_bytes([data[53], data[54]]) as usize;
        let cred_id_end = 55 + cred_id_len;
        if data.len() < cred_id_end {
            return Err(WebAuthnError::InvalidInput(
                "authenticator data too short for credential id".into(),
            ));
        }
        credential_id = Some(data[55..cred_id_end].to_vec());
        credential_public_key = Some(data[cred_id_end..].to_vec());
    }

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        aaguid,
        credential_id,
        credential_public_key,
        raw: data.to_vec(),
    })
}

/// Verify the rpIdHash matches SHA-256(rpId).
pub fn verify_rp_id_hash(rp_id_hash: &[u8], rp_id: &str) -> Result<(), WebAuthnError> {
    let expected = Sha256::digest(rp_id.as_bytes());
    if rp_id_hash != expected.as_slice() {
        return Err(WebAuthnError::RpIdMismatch);
    }
    Ok(())
}

/// Verify flags: UP always required, UV optional.
pub fn verify_flags(
    auth_data: &AuthenticatorData,
    require_uv: bool,
) -> Result<(), WebAuthnError> {
    if !auth_data.user_present() {
        return Err(WebAuthnError::UserPresenceRequired);
    }
    if require_uv && !auth_data.user_verified() {
        return Err(WebAuthnError::UserVerificationRequired);
    }
    // BS=1 with BE=0 is invalid
    if auth_data.backup_state() && !auth_data.backup_eligible() {
        return Err(WebAuthnError::InvalidBackupState);
    }
    Ok(())
}
