use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// --- Errors ---

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("challenge not found or expired")]
    ChallengeNotFound,
    #[error("credential not found")]
    CredentialNotFound,
    #[error("{0}")]
    BadRequest(String),
}

// --- Stored credential ---

#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub sign_count: u32,
    pub user_id: String,
    pub prf_salt: Option<Vec<u8>>,
    pub prf_supported: bool,
}

// --- Challenge store trait ---

pub trait ChallengeStore: Send + Sync {
    fn store(&self, key: &str, challenge: &str, timeout: Duration) -> Result<(), PasskeyError>;
    fn consume(&self, key: &str) -> Result<String, PasskeyError>;
}

// --- Credential store trait ---

pub trait CredentialStore: Send + Sync {
    fn store(&self, cred: StoredCredential) -> Result<(), PasskeyError>;
    fn get(&self, credential_id: &[u8]) -> Result<StoredCredential, PasskeyError>;
    fn get_by_user(&self, user_id: &str) -> Result<Vec<StoredCredential>, PasskeyError>;
    fn update(&self, cred: StoredCredential) -> Result<(), PasskeyError>;
    fn delete(&self, credential_id: &[u8]) -> Result<(), PasskeyError>;
}

// --- In-memory challenge store ---

struct ChallengeEntry {
    challenge: String,
    expires_at: Instant,
}

const CLEANUP_INTERVAL: u32 = 100;

pub struct MemoryChallengeStore {
    entries: Mutex<HashMap<String, ChallengeEntry>>,
    write_count: Mutex<u32>,
}

impl MemoryChallengeStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            write_count: Mutex::new(0),
        }
    }
}

impl Default for MemoryChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeStore for MemoryChallengeStore {
    fn store(&self, key: &str, challenge: &str, timeout: Duration) -> Result<(), PasskeyError> {
        let mut entries = self.entries.lock().unwrap();
        entries.insert(
            key.to_string(),
            ChallengeEntry {
                challenge: challenge.to_string(),
                expires_at: Instant::now() + timeout,
            },
        );
        let mut count = self.write_count.lock().unwrap();
        *count += 1;
        if *count >= CLEANUP_INTERVAL {
            *count = 0;
            let now = Instant::now();
            entries.retain(|_, v| v.expires_at > now);
        }
        Ok(())
    }

    fn consume(&self, key: &str) -> Result<String, PasskeyError> {
        let mut entries = self.entries.lock().unwrap();
        match entries.remove(key) {
            Some(entry) if entry.expires_at > Instant::now() => Ok(entry.challenge),
            _ => Err(PasskeyError::ChallengeNotFound),
        }
    }
}

// --- In-memory credential store ---

pub struct MemoryCredentialStore {
    creds: Mutex<Vec<StoredCredential>>,
}

impl MemoryCredentialStore {
    pub fn new() -> Self {
        Self {
            creds: Mutex::new(Vec::new()),
        }
    }
}

impl Default for MemoryCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn store(&self, cred: StoredCredential) -> Result<(), PasskeyError> {
        self.creds.lock().unwrap().push(cred);
        Ok(())
    }

    fn get(&self, credential_id: &[u8]) -> Result<StoredCredential, PasskeyError> {
        let creds = self.creds.lock().unwrap();
        creds
            .iter()
            .find(|c| c.credential_id == credential_id)
            .cloned()
            .ok_or(PasskeyError::CredentialNotFound)
    }

    fn get_by_user(&self, user_id: &str) -> Result<Vec<StoredCredential>, PasskeyError> {
        let creds = self.creds.lock().unwrap();
        Ok(creds.iter().filter(|c| c.user_id == user_id).cloned().collect())
    }

    fn update(&self, cred: StoredCredential) -> Result<(), PasskeyError> {
        let mut creds = self.creds.lock().unwrap();
        for c in creds.iter_mut() {
            if c.credential_id == cred.credential_id {
                *c = cred;
                return Ok(());
            }
        }
        Err(PasskeyError::CredentialNotFound)
    }

    fn delete(&self, credential_id: &[u8]) -> Result<(), PasskeyError> {
        let mut creds = self.creds.lock().unwrap();
        let len_before = creds.len();
        creds.retain(|c| c.credential_id != credential_id);
        if creds.len() == len_before {
            Err(PasskeyError::CredentialNotFound)
        } else {
            Ok(())
        }
    }
}
