package passkey

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidSessionConfig = errors.New("invalid session configuration")
	ErrInvalidToken         = errors.New("invalid session token")
	ErrTokenExpired         = errors.New("session token expired")
)

// SessionConfig holds configuration for HMAC-SHA256 stateless session tokens.
type SessionConfig struct {
	Secret         string
	Duration       time.Duration // default 24h
	ClockSkewGrace time.Duration // default 10s
	CookieName     string        // default "op_session"
	CookiePath     string        // default "/"
	Secure         *bool         // default true (nil = true)
	SameSite       string        // "Strict", "Lax", "None"; default "Lax"
	Domain         string        // optional
}

// SessionTokenData holds the parsed contents of a validated session token.
type SessionTokenData struct {
	UserID    string
	ExpiresAt time.Time
}

func (c *SessionConfig) applyDefaults() {
	if c.Duration == 0 {
		c.Duration = 24 * time.Hour
	}
	if c.ClockSkewGrace == 0 {
		c.ClockSkewGrace = 10 * time.Second
	}
	if c.CookieName == "" {
		c.CookieName = "op_session"
	}
	if c.CookiePath == "" {
		c.CookiePath = "/"
	}
	if c.SameSite == "" {
		c.SameSite = "Lax"
	}
}

func (c *SessionConfig) validate() error {
	if len(c.Secret) < 32 {
		return fmt.Errorf("%w: Secret must be at least 32 characters", ErrInvalidSessionConfig)
	}
	return nil
}

// createSessionToken creates a stateless HMAC-SHA256 session token.
// Format: userId:expiresAtUnixMs:base64urlSignature
func createSessionToken(userID string, config *SessionConfig) string {
	expiresAtMs := time.Now().Add(config.Duration).UnixMilli()
	payload := userID + ":" + strconv.FormatInt(expiresAtMs, 10)

	mac := hmac.New(sha256.New, []byte(config.Secret))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payload + ":" + sig
}

// validateSessionToken parses and validates a stateless session token.
// It splits from the right to handle userIDs that contain colons.
func validateSessionToken(token string, config *SessionConfig) (*SessionTokenData, error) {
	// Find the last colon (separates signature)
	lastColon := strings.LastIndex(token, ":")
	if lastColon < 0 {
		return nil, fmt.Errorf("%w: missing signature", ErrInvalidToken)
	}
	payloadAndExpiry := token[:lastColon]
	sigEncoded := token[lastColon+1:]

	// Find the second-to-last colon (separates expiresAtMs from userId)
	secondLastColon := strings.LastIndex(payloadAndExpiry, ":")
	if secondLastColon < 0 {
		return nil, fmt.Errorf("%w: missing expiry", ErrInvalidToken)
	}
	userID := payloadAndExpiry[:secondLastColon]
	expiryStr := payloadAndExpiry[secondLastColon+1:]

	if userID == "" {
		return nil, fmt.Errorf("%w: empty user ID", ErrInvalidToken)
	}

	expiresAtMs, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid expiry timestamp", ErrInvalidToken)
	}

	// Verify HMAC signature (constant-time comparison)
	payload := userID + ":" + expiryStr
	mac := hmac.New(sha256.New, []byte(config.Secret))
	mac.Write([]byte(payload))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sigEncoded), []byte(expectedSig)) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
	}

	// Check expiry with clock skew grace
	expiresAt := time.UnixMilli(expiresAtMs)
	if time.Now().After(expiresAt.Add(config.ClockSkewGrace)) {
		return nil, ErrTokenExpired
	}

	return &SessionTokenData{
		UserID:    userID,
		ExpiresAt: expiresAt,
	}, nil
}

// buildSetCookieHeader returns a Set-Cookie header value for the session token.
func buildSetCookieHeader(token string, config *SessionConfig) string {
	maxAge := int(config.Duration.Seconds())

	parts := []string{
		config.CookieName + "=" + token,
		"HttpOnly",
		"Path=" + config.CookiePath,
		"Max-Age=" + strconv.Itoa(maxAge),
		"SameSite=" + config.SameSite,
	}

	if config.Secure == nil || *config.Secure {
		parts = append(parts, "Secure")
	}

	if config.Domain != "" {
		parts = append(parts, "Domain="+config.Domain)
	}

	return strings.Join(parts, "; ")
}

// buildClearCookieHeader returns a Set-Cookie header value that clears the session cookie.
func buildClearCookieHeader(config *SessionConfig) string {
	parts := []string{
		config.CookieName + "=",
		"HttpOnly",
		"Path=" + config.CookiePath,
		"Max-Age=0",
		"SameSite=" + config.SameSite,
	}

	if config.Secure == nil || *config.Secure {
		parts = append(parts, "Secure")
	}

	if config.Domain != "" {
		parts = append(parts, "Domain="+config.Domain)
	}

	return strings.Join(parts, "; ")
}

// parseCookieToken extracts the session token from a Cookie header string.
// Returns "" if the cookie is not found.
func parseCookieToken(cookieHeader string, config *SessionConfig) string {
	prefix := config.CookieName + "="
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, prefix) {
			return part[len(prefix):]
		}
	}
	return ""
}
