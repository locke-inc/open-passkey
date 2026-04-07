package passkey

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func boolPtr(b bool) *bool { return &b }

func validSessionConfig() *SessionConfig {
	cfg := &SessionConfig{
		Secret:   "this-is-a-long-enough-secret-key!!", // 34 chars
		Duration: 24 * time.Hour,
	}
	cfg.applyDefaults()
	return cfg
}

// --- Token Logic ---

func TestCreateSessionToken_Format(t *testing.T) {
	cfg := validSessionConfig()
	token := createSessionToken("user-42", cfg)

	parts := strings.Split(token, ":")
	if len(parts) != 3 {
		t.Fatalf("expected 3 colon-separated parts, got %d: %q", len(parts), token)
	}
	if parts[0] != "user-42" {
		t.Errorf("userId: got %q, want %q", parts[0], "user-42")
	}
	// parts[1] should be a numeric timestamp
	if len(parts[1]) == 0 {
		t.Error("expiresAt part is empty")
	}
	// parts[2] should be a base64url signature
	if len(parts[2]) == 0 {
		t.Error("signature part is empty")
	}
}

func TestValidateSessionToken_Fresh(t *testing.T) {
	cfg := validSessionConfig()
	token := createSessionToken("alice", cfg)

	data, err := validateSessionToken(token, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.UserID != "alice" {
		t.Errorf("UserID: got %q, want %q", data.UserID, "alice")
	}
	if data.ExpiresAt.Before(time.Now()) {
		t.Error("expected ExpiresAt to be in the future")
	}
}

func TestValidateSessionToken_TamperedUserId(t *testing.T) {
	cfg := validSessionConfig()
	token := createSessionToken("alice", cfg)

	// Replace "alice" with "eve"
	tampered := "eve" + token[len("alice"):]
	_, err := validateSessionToken(tampered, cfg)
	if err == nil {
		t.Fatal("expected error for tampered userId")
	}
}

func TestValidateSessionToken_TamperedSignature(t *testing.T) {
	cfg := validSessionConfig()
	token := createSessionToken("alice", cfg)

	// Flip the last character of the signature
	lastChar := token[len(token)-1]
	var replacement byte
	if lastChar == 'A' {
		replacement = 'B'
	} else {
		replacement = 'A'
	}
	tampered := token[:len(token)-1] + string(replacement)

	_, err := validateSessionToken(tampered, cfg)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestValidateSessionToken_Expired(t *testing.T) {
	cfg := validSessionConfig()
	cfg.Duration = 1 * time.Millisecond
	cfg.ClockSkewGrace = 0

	token := createSessionToken("alice", cfg)
	time.Sleep(10 * time.Millisecond)

	_, err := validateSessionToken(token, cfg)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired error, got: %v", err)
	}
}

func TestValidateSessionToken_WrongSecret(t *testing.T) {
	cfg := validSessionConfig()
	token := createSessionToken("alice", cfg)

	cfg2 := validSessionConfig()
	cfg2.Secret = "a-completely-different-secret-key!!"

	_, err := validateSessionToken(token, cfg2)
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestValidateSessionToken_Malformed(t *testing.T) {
	cfg := validSessionConfig()

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no colons", "justgarbage"},
		{"one colon", "foo:bar"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateSessionToken(tc.token, cfg)
			if err == nil {
				t.Fatalf("expected error for malformed token %q", tc.token)
			}
		})
	}
}

func TestValidateSessionToken_UserIdWithColons(t *testing.T) {
	cfg := validSessionConfig()
	token := createSessionToken("urn:user:123", cfg)

	data, err := validateSessionToken(token, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.UserID != "urn:user:123" {
		t.Errorf("UserID: got %q, want %q", data.UserID, "urn:user:123")
	}
}

func TestValidateSessionToken_ClockSkewGraceAccepts(t *testing.T) {
	cfg := validSessionConfig()
	cfg.Duration = 1 * time.Millisecond
	cfg.ClockSkewGrace = 10 * time.Second

	token := createSessionToken("alice", cfg)
	time.Sleep(10 * time.Millisecond) // token expired ~10ms ago, but 10s grace allows it

	data, err := validateSessionToken(token, cfg)
	if err != nil {
		t.Fatalf("expected grace period to accept token, got: %v", err)
	}
	if data.UserID != "alice" {
		t.Errorf("UserID: got %q, want %q", data.UserID, "alice")
	}
}

func TestValidateSessionToken_ClockSkewGraceRejects(t *testing.T) {
	cfg := validSessionConfig()
	cfg.Duration = 1 * time.Millisecond
	cfg.ClockSkewGrace = 0

	token := createSessionToken("alice", cfg)
	time.Sleep(10 * time.Millisecond)

	_, err := validateSessionToken(token, cfg)
	if err == nil {
		t.Fatal("expected rejection with 0 grace period")
	}
}

// --- Cookie/Config Tests ---

func TestBuildSetCookieHeader(t *testing.T) {
	cfg := validSessionConfig()
	header := buildSetCookieHeader("mytoken", cfg)

	checks := []string{"HttpOnly", "Path=/", "SameSite=Lax", "Secure", "op_session=mytoken"}
	for _, c := range checks {
		if !strings.Contains(header, c) {
			t.Errorf("Set-Cookie header missing %q: %s", c, header)
		}
	}
	if !strings.Contains(header, "Max-Age=") {
		t.Errorf("Set-Cookie header missing Max-Age: %s", header)
	}
}

func TestBuildClearCookieHeader(t *testing.T) {
	cfg := validSessionConfig()
	header := buildClearCookieHeader(cfg)

	if !strings.Contains(header, "Max-Age=0") {
		t.Errorf("clear cookie missing Max-Age=0: %s", header)
	}
	if !strings.Contains(header, "op_session=") {
		t.Errorf("clear cookie missing cookie name: %s", header)
	}
}

func TestParseCookieToken(t *testing.T) {
	cfg := validSessionConfig()

	t.Run("found", func(t *testing.T) {
		got := parseCookieToken("op_session=abc123", cfg)
		if got != "abc123" {
			t.Errorf("got %q, want %q", got, "abc123")
		}
	})

	t.Run("not found", func(t *testing.T) {
		got := parseCookieToken("other=xyz", cfg)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("multiple cookies", func(t *testing.T) {
		got := parseCookieToken("foo=bar; op_session=tok123; baz=qux", cfg)
		if got != "tok123" {
			t.Errorf("got %q, want %q", got, "tok123")
		}
	})

	t.Run("empty", func(t *testing.T) {
		got := parseCookieToken("", cfg)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

func TestSessionConfig_ShortSecret(t *testing.T) {
	cfg := &SessionConfig{Secret: "short"}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for short secret")
	}
}

func TestSessionConfig_Valid(t *testing.T) {
	cfg := &SessionConfig{Secret: "this-is-a-long-enough-secret-key!!"}
	err := cfg.validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Handler Tests ---

func newTestPasskeyWithSession(t *testing.T) *Passkey {
	t.Helper()
	p, err := New(Config{
		RPID:            "example.com",
		RPDisplayName:   "Example",
		Origin:          "https://example.com",
		ChallengeStore:  NewMemoryChallengeStore(),
		CredentialStore: NewMemoryCredentialStore(),
		Session: &SessionConfig{
			Secret: "this-is-a-long-enough-secret-key!!",
		},
	})
	if err != nil {
		t.Fatalf("failed to create Passkey: %v", err)
	}
	return p
}

func decodeJSONResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	return result
}

func TestGetSession_ValidCookie(t *testing.T) {
	p := newTestPasskeyWithSession(t)
	token := createSessionToken("user-99", p.config.Session)

	req := httptest.NewRequest(http.MethodGet, "/session", nil)
	req.Header.Set("Cookie", "op_session="+token)
	w := httptest.NewRecorder()

	p.GetSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := decodeJSONResponse(t, w)
	if resp["userId"] != "user-99" {
		t.Errorf("userId: got %v, want user-99", resp["userId"])
	}
	if resp["authenticated"] != true {
		t.Errorf("authenticated: got %v, want true", resp["authenticated"])
	}
}

func TestGetSession_NoCookie(t *testing.T) {
	p := newTestPasskeyWithSession(t)

	req := httptest.NewRequest(http.MethodGet, "/session", nil)
	w := httptest.NewRecorder()

	p.GetSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetSession_ExpiredCookie(t *testing.T) {
	p := newTestPasskeyWithSession(t)
	p.config.Session.Duration = 1 * time.Millisecond
	p.config.Session.ClockSkewGrace = 0

	token := createSessionToken("user-99", p.config.Session)
	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/session", nil)
	req.Header.Set("Cookie", "op_session="+token)
	w := httptest.NewRecorder()

	p.GetSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetSession_InvalidCookie(t *testing.T) {
	p := newTestPasskeyWithSession(t)

	req := httptest.NewRequest(http.MethodGet, "/session", nil)
	req.Header.Set("Cookie", "op_session=tampered:garbage:data")
	w := httptest.NewRecorder()

	p.GetSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetSession_NotEnabled(t *testing.T) {
	p, err := New(Config{
		RPID:            "example.com",
		RPDisplayName:   "Example",
		Origin:          "https://example.com",
		ChallengeStore:  NewMemoryChallengeStore(),
		CredentialStore: NewMemoryCredentialStore(),
		// Session: nil — not configured
	})
	if err != nil {
		t.Fatalf("failed to create Passkey: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/session", nil)
	w := httptest.NewRecorder()

	p.GetSession(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	p := newTestPasskeyWithSession(t)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	w := httptest.NewRecorder()

	p.Logout(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "Max-Age=0") {
		t.Errorf("expected Set-Cookie with Max-Age=0, got: %s", setCookie)
	}
}
