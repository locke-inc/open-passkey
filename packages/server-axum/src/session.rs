//! Stateless HMAC-SHA256 session tokens with cookie helpers.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const MIN_SECRET_LENGTH: usize = 32;
const DEFAULT_DURATION_MS: u64 = 86_400_000; // 24h
const DEFAULT_CLOCK_SKEW_GRACE_MS: u64 = 10_000; // 10s
const DEFAULT_COOKIE_NAME: &str = "op_session";

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub secret: String,
    pub duration_ms: u64,
    pub clock_skew_grace_ms: u64,
    pub cookie_name: String,
    pub cookie_path: String,
    pub secure: bool,
    pub same_site: String,
    pub domain: Option<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            duration_ms: DEFAULT_DURATION_MS,
            clock_skew_grace_ms: DEFAULT_CLOCK_SKEW_GRACE_MS,
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            cookie_path: "/".to_string(),
            secure: true,
            same_site: "Lax".to_string(),
            domain: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionTokenData {
    pub user_id: String,
    pub expires_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("invalid session token")]
    InvalidToken,
    #[error("session expired")]
    Expired,
    #[error("{0}")]
    ConfigError(String),
}

pub fn validate_config(config: &SessionConfig) -> Result<(), SessionError> {
    if config.secret.len() < MIN_SECRET_LENGTH {
        return Err(SessionError::ConfigError(format!(
            "session secret must be at least {} characters",
            MIN_SECRET_LENGTH
        )));
    }
    Ok(())
}

fn sign(payload: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    let result = mac.finalize();
    URL_SAFE_NO_PAD.encode(result.into_bytes())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

pub fn create_token(user_id: &str, config: &SessionConfig) -> String {
    let expires_at = now_ms() + config.duration_ms;
    let payload = format!("{}:{}", user_id, expires_at);
    let signature = sign(&payload, &config.secret);
    format!("{}:{}", payload, signature)
}

pub fn validate_token(token: &str, config: &SessionConfig) -> Result<SessionTokenData, SessionError> {
    let last_colon = token.rfind(':').ok_or(SessionError::InvalidToken)?;
    let before_last = &token[..last_colon];
    let second_last_colon = before_last.rfind(':').ok_or(SessionError::InvalidToken)?;

    let user_id = &token[..second_last_colon];
    let expires_at_str = &token[second_last_colon + 1..last_colon];
    let provided_sig = &token[last_colon + 1..];

    if user_id.is_empty() || expires_at_str.is_empty() || provided_sig.is_empty() {
        return Err(SessionError::InvalidToken);
    }

    let expires_at: u64 = expires_at_str.parse().map_err(|_| SessionError::InvalidToken)?;

    // Constant-time comparison via HMAC verify
    let payload = format!("{}:{}", user_id, expires_at_str);
    let mut mac = HmacSha256::new_from_slice(config.secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());

    let provided_bytes = URL_SAFE_NO_PAD.decode(provided_sig).map_err(|_| SessionError::InvalidToken)?;
    mac.verify_slice(&provided_bytes).map_err(|_| SessionError::InvalidToken)?;

    // Expiry with clock skew grace
    if now_ms() > expires_at + config.clock_skew_grace_ms {
        return Err(SessionError::Expired);
    }

    Ok(SessionTokenData {
        user_id: user_id.to_string(),
        expires_at,
    })
}

pub fn build_set_cookie_header(token: &str, config: &SessionConfig) -> String {
    let max_age = config.duration_ms / 1000;
    let mut parts = vec![
        format!("{}={}", config.cookie_name, token),
        "HttpOnly".to_string(),
        format!("Path={}", config.cookie_path),
        format!("Max-Age={}", max_age),
        format!("SameSite={}", config.same_site),
    ];
    if config.secure {
        parts.push("Secure".to_string());
    }
    if let Some(ref domain) = config.domain {
        parts.push(format!("Domain={}", domain));
    }
    parts.join("; ")
}

pub fn build_clear_cookie_header(config: &SessionConfig) -> String {
    let mut parts = vec![
        format!("{}=", config.cookie_name),
        "HttpOnly".to_string(),
        format!("Path={}", config.cookie_path),
        "Max-Age=0".to_string(),
        format!("SameSite={}", config.same_site),
    ];
    if config.secure {
        parts.push("Secure".to_string());
    }
    if let Some(ref domain) = config.domain {
        parts.push(format!("Domain={}", domain));
    }
    parts.join("; ")
}

pub fn parse_cookie_token(cookie_header: Option<&str>, config: &SessionConfig) -> Option<String> {
    let header = cookie_header?;
    let prefix = format!("{}=", config.cookie_name);
    for cookie in header.split(';') {
        let trimmed = cookie.trim();
        if trimmed.starts_with(&prefix) {
            let value = &trimmed[prefix.len()..];
            if value.is_empty() {
                return None;
            }
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    fn test_config() -> SessionConfig {
        SessionConfig {
            secret: "a]Vv3X!kP9#mW2$nQ7@rT5&jY0^uL8*dF".to_string(),
            duration_ms: 86_400_000,
            ..Default::default()
        }
    }

    #[test]
    fn create_token_valid_format() {
        let config = test_config();
        let token = create_token("user123", &config);
        let parts: Vec<&str> = token.rsplitn(2, ':').collect();
        assert_eq!(parts.len(), 2);
        // Should have format userId:expiresAt:signature
        let colons: Vec<_> = token.match_indices(':').collect();
        assert!(colons.len() >= 2);
    }

    #[test]
    fn validate_fresh_token() {
        let config = test_config();
        let token = create_token("user123", &config);
        let data = validate_token(&token, &config).unwrap();
        assert_eq!(data.user_id, "user123");
        assert!(data.expires_at > now_ms());
    }

    #[test]
    fn reject_tampered_user_id() {
        let config = test_config();
        let token = create_token("user123", &config);
        let tampered = token.replacen("user123", "evil", 1);
        assert!(validate_token(&tampered, &config).is_err());
    }

    #[test]
    fn reject_tampered_signature() {
        let config = test_config();
        let token = create_token("user123", &config);
        let mut chars: Vec<char> = token.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();
        assert!(validate_token(&tampered, &config).is_err());
    }

    #[test]
    fn reject_expired_token() {
        let config = SessionConfig {
            secret: "a]Vv3X!kP9#mW2$nQ7@rT5&jY0^uL8*dF".to_string(),
            duration_ms: 1,
            clock_skew_grace_ms: 0,
            ..Default::default()
        };
        let token = create_token("user123", &config);
        thread::sleep(Duration::from_millis(10));
        assert!(validate_token(&token, &config).is_err());
    }

    #[test]
    fn reject_wrong_secret() {
        let config = test_config();
        let token = create_token("user123", &config);
        let other = SessionConfig {
            secret: "zZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZ".to_string(),
            ..test_config()
        };
        assert!(validate_token(&token, &other).is_err());
    }

    #[test]
    fn reject_malformed_token() {
        let config = test_config();
        assert!(validate_token("", &config).is_err());
        assert!(validate_token("nocolons", &config).is_err());
        assert!(validate_token("one:colon", &config).is_err());
    }

    #[test]
    fn user_id_with_colons() {
        let config = test_config();
        let token = create_token("urn:user:123", &config);
        let data = validate_token(&token, &config).unwrap();
        assert_eq!(data.user_id, "urn:user:123");
    }

    #[test]
    fn clock_skew_grace_accepts_within() {
        let config = SessionConfig {
            secret: "a]Vv3X!kP9#mW2$nQ7@rT5&jY0^uL8*dF".to_string(),
            duration_ms: 1,
            clock_skew_grace_ms: 10_000,
            ..Default::default()
        };
        let token = create_token("user123", &config);
        thread::sleep(Duration::from_millis(10));
        // Token expired by ~10ms but grace is 10s — should still be valid
        assert!(validate_token(&token, &config).is_ok());
    }

    #[test]
    fn clock_skew_grace_rejects_beyond() {
        let config = SessionConfig {
            secret: "a]Vv3X!kP9#mW2$nQ7@rT5&jY0^uL8*dF".to_string(),
            duration_ms: 1,
            clock_skew_grace_ms: 0,
            ..Default::default()
        };
        let token = create_token("user123", &config);
        thread::sleep(Duration::from_millis(10));
        assert!(validate_token(&token, &config).is_err());
    }

    #[test]
    fn build_set_cookie_header_defaults() {
        let config = test_config();
        let header = build_set_cookie_header("tok", &config);
        assert!(header.contains("op_session=tok"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Path=/"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Secure"));
        assert!(header.contains("Max-Age=86400"));
    }

    #[test]
    fn build_clear_cookie_header_test() {
        let config = test_config();
        let header = build_clear_cookie_header(&config);
        assert!(header.contains("op_session="));
        assert!(header.contains("Max-Age=0"));
    }

    #[test]
    fn reject_short_secret() {
        let config = SessionConfig {
            secret: "short".to_string(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }
}
