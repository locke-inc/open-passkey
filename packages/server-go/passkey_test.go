package passkey_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/locke-inc/open-passkey/packages/server-go"
)

func newTestPasskey(t *testing.T) *passkey.Passkey {
	t.Helper()
	p, err := passkey.New(passkey.Config{
		RPID:            "example.com",
		RPDisplayName:   "Example",
		Origin:          "https://example.com",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err != nil {
		t.Fatalf("failed to create Passkey: %v", err)
	}
	return p
}

func postJSON(handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	return result
}

// --- Config validation tests ---

func TestNew_MissingRPID(t *testing.T) {
	_, err := passkey.New(passkey.Config{
		Origin:          "https://example.com",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err == nil {
		t.Fatal("expected error for missing RPID")
	}
}

func TestNew_MissingOrigin(t *testing.T) {
	_, err := passkey.New(passkey.Config{
		RPID:            "example.com",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err == nil {
		t.Fatal("expected error for missing Origin")
	}
}

func TestNew_MissingChallengeStore(t *testing.T) {
	_, err := passkey.New(passkey.Config{
		RPID:            "example.com",
		Origin:          "https://example.com",
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err == nil {
		t.Fatal("expected error for missing ChallengeStore")
	}
}

func TestNew_MissingCredentialStore(t *testing.T) {
	_, err := passkey.New(passkey.Config{
		RPID:           "example.com",
		Origin:         "https://example.com",
		ChallengeStore: passkey.NewMemoryChallengeStore(),
	})
	if err == nil {
		t.Fatal("expected error for missing CredentialStore")
	}
}

// --- BeginRegistration tests ---

func TestBeginRegistration_Success(t *testing.T) {
	p := newTestPasskey(t)
	w := postJSON(p.BeginRegistration, map[string]string{
		"userId":   "user-123",
		"username": "alice",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["challenge"] == nil || resp["challenge"] == "" {
		t.Error("response missing challenge")
	}
	rp, ok := resp["rp"].(map[string]any)
	if !ok {
		t.Fatal("response missing rp object")
	}
	if rp["id"] != "example.com" {
		t.Errorf("rp.id: got %v, want example.com", rp["id"])
	}
	if rp["name"] != "Example" {
		t.Errorf("rp.name: got %v, want Example", rp["name"])
	}
	if resp["attestation"] != "none" {
		t.Errorf("attestation: got %v, want none", resp["attestation"])
	}
	// Verify PRF extension is included
	extensions, ok := resp["extensions"].(map[string]any)
	if !ok {
		t.Fatal("response missing extensions object")
	}
	prf, ok := extensions["prf"].(map[string]any)
	if !ok {
		t.Fatal("extensions missing prf object")
	}
	eval, ok := prf["eval"].(map[string]any)
	if !ok {
		t.Fatal("prf missing eval object")
	}
	if eval["first"] == nil || eval["first"] == "" {
		t.Error("prf.eval.first is missing or empty")
	}
}

func TestBeginRegistration_MissingFields(t *testing.T) {
	p := newTestPasskey(t)

	// Missing username
	w := postJSON(p.BeginRegistration, map[string]string{"userId": "user-123"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing username, got %d", w.Code)
	}

	// Missing userId
	w = postJSON(p.BeginRegistration, map[string]string{"username": "alice"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing userId, got %d", w.Code)
	}
}

// --- BeginAuthentication tests ---

func TestBeginAuthentication_Success(t *testing.T) {
	p := newTestPasskey(t)
	w := postJSON(p.BeginAuthentication, map[string]string{
		"userId": "user-123",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["challenge"] == nil || resp["challenge"] == "" {
		t.Error("response missing challenge")
	}
	if resp["rpId"] != "example.com" {
		t.Errorf("rpId: got %v, want example.com", resp["rpId"])
	}
}

func TestBeginAuthentication_DiscoverableFlow(t *testing.T) {
	p := newTestPasskey(t)
	// Empty body — discoverable credentials flow
	w := postJSON(p.BeginAuthentication, map[string]string{})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for discoverable flow, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["challenge"] == nil || resp["challenge"] == "" {
		t.Error("response missing challenge")
	}
	// Should not have allowCredentials for discoverable flow
	if resp["allowCredentials"] != nil {
		t.Error("discoverable flow should not include allowCredentials")
	}
}

// --- FinishRegistration tests ---

func TestFinishRegistration_MissingChallenge(t *testing.T) {
	p := newTestPasskey(t)
	// Try to finish without calling begin first
	w := postJSON(p.FinishRegistration, map[string]any{
		"userId": "user-123",
		"credential": map[string]any{
			"id":    "fake-cred-id",
			"rawId": "fake-cred-id",
			"type":  "public-key",
			"response": map[string]any{
				"clientDataJSON":    "fake",
				"attestationObject": "fake",
			},
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing challenge, got %d", w.Code)
	}
}

// --- FinishAuthentication tests ---

func TestFinishAuthentication_MissingChallenge(t *testing.T) {
	p := newTestPasskey(t)
	w := postJSON(p.FinishAuthentication, map[string]any{
		"userId": "user-123",
		"credential": map[string]any{
			"id":    "fake-cred-id",
			"rawId": "fake-cred-id",
			"type":  "public-key",
			"response": map[string]any{
				"clientDataJSON":    "fake",
				"authenticatorData": "fake",
				"signature":         "fake",
			},
		},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing challenge, got %d", w.Code)
	}
}

// --- MemoryChallengeStore tests ---

func TestMemoryChallengeStore_StoreAndConsume(t *testing.T) {
	store := passkey.NewMemoryChallengeStore()
	if err := store.Store("user1", "challenge-abc", 5*60*1e9); err != nil { // 5 min
		t.Fatalf("Store failed: %v", err)
	}

	challenge, err := store.Consume("user1")
	if err != nil {
		t.Fatalf("Consume failed: %v", err)
	}
	if challenge != "challenge-abc" {
		t.Errorf("got %q, want %q", challenge, "challenge-abc")
	}

	// Second consume should fail (single-use)
	_, err = store.Consume("user1")
	if err == nil {
		t.Error("expected error on second Consume")
	}
}

func TestMemoryChallengeStore_NotFound(t *testing.T) {
	store := passkey.NewMemoryChallengeStore()
	_, err := store.Consume("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

// --- MemoryCredentialStore tests ---

func TestMemoryCredentialStore_StoreAndGet(t *testing.T) {
	store := passkey.NewMemoryCredentialStore()
	cred := passkey.StoredCredential{
		CredentialID:  []byte{1, 2, 3},
		PublicKeyCOSE: []byte{4, 5, 6},
		SignCount:     0,
		UserID:        "user-123",
	}
	if err := store.Store(cred); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	got, err := store.Get([]byte{1, 2, 3})
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.UserID != "user-123" {
		t.Errorf("UserID: got %q, want %q", got.UserID, "user-123")
	}
}

func TestMemoryCredentialStore_GetByUser(t *testing.T) {
	store := passkey.NewMemoryCredentialStore()
	store.Store(passkey.StoredCredential{CredentialID: []byte{1}, UserID: "alice"})
	store.Store(passkey.StoredCredential{CredentialID: []byte{2}, UserID: "alice"})
	store.Store(passkey.StoredCredential{CredentialID: []byte{3}, UserID: "bob"})

	creds, err := store.GetByUser("alice")
	if err != nil {
		t.Fatalf("GetByUser failed: %v", err)
	}
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials for alice, got %d", len(creds))
	}
}

func TestMemoryCredentialStore_Update(t *testing.T) {
	store := passkey.NewMemoryCredentialStore()
	store.Store(passkey.StoredCredential{CredentialID: []byte{1}, SignCount: 0, UserID: "alice"})

	err := store.Update(passkey.StoredCredential{CredentialID: []byte{1}, SignCount: 5, UserID: "alice"})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	got, _ := store.Get([]byte{1})
	if got.SignCount != 5 {
		t.Errorf("SignCount: got %d, want 5", got.SignCount)
	}
}

func TestMemoryCredentialStore_NotFound(t *testing.T) {
	store := passkey.NewMemoryCredentialStore()
	_, err := store.Get([]byte{99})
	if err == nil {
		t.Error("expected error for nonexistent credential")
	}
}

// --- PRF extension tests ---

func TestMemoryCredentialStore_PRFFields(t *testing.T) {
	store := passkey.NewMemoryCredentialStore()
	cred := passkey.StoredCredential{
		CredentialID:  []byte{10, 20, 30},
		PublicKeyCOSE: []byte{40, 50, 60},
		SignCount:     0,
		UserID:        "user-prf",
		PRFSalt:       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		PRFSupported:  true,
	}
	if err := store.Store(cred); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	got, err := store.Get([]byte{10, 20, 30})
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !got.PRFSupported {
		t.Error("expected PRFSupported to be true")
	}
	if len(got.PRFSalt) != 32 {
		t.Errorf("expected PRFSalt length 32, got %d", len(got.PRFSalt))
	}
}

func TestBeginAuthentication_WithPRFCredentials(t *testing.T) {
	cs := passkey.NewMemoryChallengeStore()
	credStore := passkey.NewMemoryCredentialStore()

	// Store two PRF-enabled credentials for the same user
	credStore.Store(passkey.StoredCredential{
		CredentialID: []byte{1, 2, 3},
		UserID:       "alice",
		PRFSalt:      []byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210, 220, 230, 240, 250, 1, 2, 3, 4, 5, 6, 7},
		PRFSupported: true,
	})
	credStore.Store(passkey.StoredCredential{
		CredentialID: []byte{4, 5, 6},
		UserID:       "alice",
		PRFSalt:      []byte{7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38},
		PRFSupported: true,
	})

	p, err := passkey.New(passkey.Config{
		RPID:            "example.com",
		RPDisplayName:   "Example",
		Origin:          "https://example.com",
		ChallengeStore:  cs,
		CredentialStore: credStore,
	})
	if err != nil {
		t.Fatalf("failed to create Passkey: %v", err)
	}

	w := postJSON(p.BeginAuthentication, map[string]string{"userId": "alice"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	extensions, ok := resp["extensions"].(map[string]any)
	if !ok {
		t.Fatal("response missing extensions for PRF-enabled credentials")
	}
	prf, ok := extensions["prf"].(map[string]any)
	if !ok {
		t.Fatal("extensions missing prf object")
	}
	evalByCredential, ok := prf["evalByCredential"].(map[string]any)
	if !ok {
		t.Fatal("prf missing evalByCredential object")
	}
	if len(evalByCredential) != 2 {
		t.Errorf("expected 2 entries in evalByCredential, got %d", len(evalByCredential))
	}
}

func TestBeginAuthentication_NoPRFWithoutUserId(t *testing.T) {
	p := newTestPasskey(t)
	w := postJSON(p.BeginAuthentication, map[string]string{})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["extensions"] != nil {
		t.Error("discoverable flow should not include extensions")
	}
}

// --- Input validation tests (Step 4) ---

func TestNew_InvalidRPID_WithScheme(t *testing.T) {
	_, err := passkey.New(passkey.Config{
		RPID:            "https://example.com",
		Origin:          "https://example.com",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err == nil {
		t.Fatal("expected error for RPID with scheme")
	}
}

func TestNew_InvalidRPID_WithPath(t *testing.T) {
	_, err := passkey.New(passkey.Config{
		RPID:            "example.com/path",
		Origin:          "https://example.com",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err == nil {
		t.Fatal("expected error for RPID with path")
	}
}

func TestNew_InvalidRPID_WithPort(t *testing.T) {
	_, err := passkey.New(passkey.Config{
		RPID:            "example.com:8080",
		Origin:          "https://example.com",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err == nil {
		t.Fatal("expected error for RPID with port")
	}
}

func TestNew_InvalidOrigin_NoScheme(t *testing.T) {
	_, err := passkey.New(passkey.Config{
		RPID:            "example.com",
		Origin:          "example.com",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err == nil {
		t.Fatal("expected error for Origin without scheme")
	}
}

func TestNew_ValidOrigin_HTTP(t *testing.T) {
	_, err := passkey.New(passkey.Config{
		RPID:            "localhost",
		RPDisplayName:   "Test",
		Origin:          "http://localhost",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err != nil {
		t.Fatalf("http:// origin should be allowed: %v", err)
	}
}

// --- Credential Store Delete tests (Step 5) ---

func TestMemoryCredentialStore_Delete(t *testing.T) {
	store := passkey.NewMemoryCredentialStore()
	store.Store(passkey.StoredCredential{CredentialID: []byte{1}, UserID: "alice"})
	store.Store(passkey.StoredCredential{CredentialID: []byte{2}, UserID: "alice"})

	if err := store.Delete([]byte{1}); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Should not be found anymore
	_, err := store.Get([]byte{1})
	if err == nil {
		t.Error("expected error after delete")
	}

	// Other credential should still exist
	_, err = store.Get([]byte{2})
	if err != nil {
		t.Fatalf("second credential should still exist: %v", err)
	}
}

func TestMemoryCredentialStore_Delete_NotFound(t *testing.T) {
	store := passkey.NewMemoryCredentialStore()
	err := store.Delete([]byte{99})
	if err == nil {
		t.Error("expected error for deleting nonexistent credential")
	}
}

// --- Challenge Store Cleanup tests (Step 6) ---

func TestMemoryChallengeStore_ExpiredCleanup(t *testing.T) {
	store := passkey.NewMemoryChallengeStore()

	// Store 100 challenges with 1ns timeout (effectively expired immediately)
	for i := 0; i < 100; i++ {
		store.Store(fmt.Sprintf("key-%d", i), "challenge", 1)
	}

	// The 100th Store should trigger cleanup. All 100 entries should be expired.
	// Trying to consume any of them should fail.
	_, err := store.Consume("key-0")
	if err == nil {
		t.Error("expected expired challenge to not be consumable")
	}
}

func TestBeginAuthentication_NoPRFForNonPRFCredentials(t *testing.T) {
	cs := passkey.NewMemoryChallengeStore()
	credStore := passkey.NewMemoryCredentialStore()

	// Store a credential without PRF
	credStore.Store(passkey.StoredCredential{
		CredentialID: []byte{1, 2, 3},
		UserID:       "bob",
	})

	p, err := passkey.New(passkey.Config{
		RPID:            "example.com",
		RPDisplayName:   "Example",
		Origin:          "https://example.com",
		ChallengeStore:  cs,
		CredentialStore: credStore,
	})
	if err != nil {
		t.Fatalf("failed to create Passkey: %v", err)
	}

	w := postJSON(p.BeginAuthentication, map[string]string{"userId": "bob"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["extensions"] != nil {
		t.Error("non-PRF credentials should not include extensions")
	}
}
