package passkey

import (
	"sync"
	"time"
)

// --- Challenge store interface ---

// ChallengeStore manages single-use, time-limited WebAuthn challenges.
// Implementations must be safe for concurrent use.
type ChallengeStore interface {
	// Store saves a challenge associated with a key (typically userId).
	// The challenge must expire after the given timeout.
	Store(key, challenge string, timeout time.Duration) error

	// Consume retrieves and deletes a challenge for the given key.
	// Returns ErrChallengeNotFound if the challenge doesn't exist or has expired.
	Consume(key string) (string, error)
}

// --- Credential store interface ---

// StoredCredential represents a WebAuthn credential persisted by the relying party.
type StoredCredential struct {
	CredentialID  []byte
	PublicKeyCOSE []byte
	SignCount     uint32
	UserID        string
}

// CredentialStore manages WebAuthn credential persistence.
// Implementations must be safe for concurrent use.
type CredentialStore interface {
	// Store saves a new credential after successful registration.
	Store(cred StoredCredential) error

	// Get retrieves a credential by its credential ID.
	// Returns ErrCredentialNotFound if not found.
	Get(credentialID []byte) (StoredCredential, error)

	// GetByUser returns all credentials for a given user ID.
	GetByUser(userID string) ([]StoredCredential, error)

	// Update updates an existing credential (e.g., sign count after authentication).
	Update(cred StoredCredential) error
}

// --- In-memory challenge store ---

type challengeEntry struct {
	challenge string
	expiresAt time.Time
}

// MemoryChallengeStore is a thread-safe, in-memory ChallengeStore.
// Suitable for development, testing, and single-instance deployments.
type MemoryChallengeStore struct {
	mu      sync.Mutex
	entries map[string]challengeEntry
}

func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{
		entries: make(map[string]challengeEntry),
	}
}

func (s *MemoryChallengeStore) Store(key, challenge string, timeout time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = challengeEntry{
		challenge: challenge,
		expiresAt: time.Now().Add(timeout),
	}
	return nil
}

func (s *MemoryChallengeStore) Consume(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok {
		return "", ErrChallengeNotFound
	}
	delete(s.entries, key)
	if time.Now().After(entry.expiresAt) {
		return "", ErrChallengeNotFound
	}
	return entry.challenge, nil
}

// --- In-memory credential store ---

// MemoryCredentialStore is a thread-safe, in-memory CredentialStore.
// Suitable for development and testing only.
type MemoryCredentialStore struct {
	mu    sync.Mutex
	creds []StoredCredential
}

func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{}
}

func (s *MemoryCredentialStore) Store(cred StoredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds = append(s.creds, cred)
	return nil
}

func (s *MemoryCredentialStore) Get(credentialID []byte) (StoredCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.creds {
		if bytesEqual(c.CredentialID, credentialID) {
			return c, nil
		}
	}
	return StoredCredential{}, ErrCredentialNotFound
}

func (s *MemoryCredentialStore) GetByUser(userID string) ([]StoredCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []StoredCredential
	for _, c := range s.creds {
		if c.UserID == userID {
			result = append(result, c)
		}
	}
	return result, nil
}

func (s *MemoryCredentialStore) Update(cred StoredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.creds {
		if bytesEqual(c.CredentialID, cred.CredentialID) {
			s.creds[i] = cred
			return nil
		}
	}
	return ErrCredentialNotFound
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
