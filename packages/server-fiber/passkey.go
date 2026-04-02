// Package passkey provides a Fiber framework WebAuthn server binding.
//
// It wraps the core-go webauthn verification library with challenge management,
// credential storage interfaces, and HTTP handlers that implement the full
// registration and authentication ceremonies using the Fiber framework.
//
// Usage:
//
//	p, _ := passkey.New(passkey.Config{
//	    RPID:           "example.com",
//	    RPDisplayName:  "Example",
//	    Origin:         "https://example.com",
//	    ChallengeStore: passkey.NewMemoryChallengeStore(),
//	    CredentialStore: myDBStore,
//	})
//	app := fiber.New()
//	p.RegisterRoutes(app, "/passkey")
package passkey

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/locke-inc/open-passkey/packages/core-go/webauthn"
)

var (
	ErrInvalidConfig      = errors.New("invalid passkey configuration")
	ErrChallengeNotFound  = errors.New("challenge not found or expired")
	ErrUserNotFound       = errors.New("user not found")
	ErrCredentialNotFound = errors.New("credential not found")
)

// Config holds the relying party configuration.
type Config struct {
	RPID             string
	RPDisplayName    string
	Origin           string
	ChallengeStore   ChallengeStore
	CredentialStore  CredentialStore
	ChallengeLength  int           // bytes of randomness; default 32
	ChallengeTimeout time.Duration // how long a challenge is valid; default 5 minutes
}

func (c *Config) applyDefaults() {
	if c.ChallengeLength <= 0 {
		c.ChallengeLength = 32
	}
	if c.ChallengeTimeout <= 0 {
		c.ChallengeTimeout = 5 * time.Minute
	}
}

func (c *Config) validate() error {
	if c.RPID == "" {
		return fmt.Errorf("%w: RPID is required", ErrInvalidConfig)
	}
	if c.Origin == "" {
		return fmt.Errorf("%w: Origin is required", ErrInvalidConfig)
	}
	if c.ChallengeStore == nil {
		return fmt.Errorf("%w: ChallengeStore is required", ErrInvalidConfig)
	}
	if c.CredentialStore == nil {
		return fmt.Errorf("%w: CredentialStore is required", ErrInvalidConfig)
	}
	if strings.Contains(c.RPID, "://") || strings.Contains(c.RPID, "/") || strings.Contains(c.RPID, ":") {
		return fmt.Errorf("%w: RPID must be a bare domain (got %q)", ErrInvalidConfig, c.RPID)
	}
	if !strings.HasPrefix(c.Origin, "https://") && !strings.HasPrefix(c.Origin, "http://") {
		return fmt.Errorf("%w: Origin must start with https:// or http:// (got %q)", ErrInvalidConfig, c.Origin)
	}
	return nil
}

// Passkey is the main server-side handler.
type Passkey struct {
	config Config
}

// New creates a Passkey instance with the given configuration.
func New(config Config) (*Passkey, error) {
	config.applyDefaults()
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Passkey{config: config}, nil
}

// RegisterRoutes registers all passkey routes on the Fiber app under the given prefix.
// Routes:
//
//	POST {prefix}/register/begin
//	POST {prefix}/register/finish
//	POST {prefix}/login/begin
//	POST {prefix}/login/finish
func (p *Passkey) RegisterRoutes(app *fiber.App, prefix string) {
	g := app.Group(prefix)
	g.Post("/register/begin", p.BeginRegistration)
	g.Post("/register/finish", p.FinishRegistration)
	g.Post("/login/begin", p.BeginAuthentication)
	g.Post("/login/finish", p.FinishAuthentication)
}

// generateChallenge creates a cryptographically random challenge, base64url-encoded.
func (p *Passkey) generateChallenge() (string, error) {
	buf := make([]byte, p.config.ChallengeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// --- Fiber Handlers ---

// BeginRegistration generates a challenge and returns PublicKeyCredentialCreationOptions.
// Expects JSON body: {"userId": "...", "username": "..."}
func (p *Passkey) BeginRegistration(c *fiber.Ctx) error {
	var req struct {
		UserID   string `json:"userId"`
		Username string `json:"username"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "invalid request body"})
	}
	if req.UserID == "" || req.Username == "" {
		return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "userId and username are required"})
	}

	challenge, err := p.generateChallenge()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(map[string]string{"error": "failed to generate challenge"})
	}

	prfSalt := make([]byte, 32)
	if _, err := rand.Read(prfSalt); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(map[string]string{"error": "failed to generate PRF salt"})
	}

	challengeData, _ := json.Marshal(map[string]string{
		"challenge": challenge,
		"prfSalt":   base64.RawURLEncoding.EncodeToString(prfSalt),
	})
	if err := p.config.ChallengeStore.Store(req.UserID, string(challengeData), p.config.ChallengeTimeout); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(map[string]string{"error": "failed to store challenge"})
	}

	options := map[string]any{
		"challenge": challenge,
		"rp": map[string]string{
			"id":   p.config.RPID,
			"name": p.config.RPDisplayName,
		},
		"user": map[string]string{
			"id":          base64.RawURLEncoding.EncodeToString([]byte(req.UserID)),
			"name":        req.Username,
			"displayName": req.Username,
		},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": -52},
			{"type": "public-key", "alg": -49},
			{"type": "public-key", "alg": -7},
		},
		"authenticatorSelection": map[string]any{
			"residentKey":      "preferred",
			"userVerification": "preferred",
		},
		"timeout":     p.config.ChallengeTimeout.Milliseconds(),
		"attestation": "none",
		"extensions": map[string]any{
			"prf": map[string]any{
				"eval": map[string]string{
					"first": base64.RawURLEncoding.EncodeToString(prfSalt),
				},
			},
		},
	}

	return c.Status(http.StatusOK).JSON(options)
}

// FinishRegistration verifies a registration response and stores the credential.
func (p *Passkey) FinishRegistration(c *fiber.Ctx) error {
	var req struct {
		UserID       string `json:"userId"`
		PRFSupported *bool  `json:"prfSupported,omitempty"`
		Credential   struct {
			ID       string `json:"id"`
			RawID    string `json:"rawId"`
			Type     string `json:"type"`
			Response struct {
				ClientDataJSON    string `json:"clientDataJSON"`
				AttestationObject string `json:"attestationObject"`
			} `json:"response"`
		} `json:"credential"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "invalid request body"})
	}

	challengeData, err := p.config.ChallengeStore.Consume(req.UserID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "challenge not found or expired"})
	}
	var stored struct {
		Challenge string `json:"challenge"`
		PRFSalt   string `json:"prfSalt"`
	}
	if err := json.Unmarshal([]byte(challengeData), &stored); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(map[string]string{"error": "failed to decode challenge data"})
	}

	result, err := webauthn.VerifyRegistration(webauthn.RegistrationInput{
		RPID:              p.config.RPID,
		ExpectedChallenge: stored.Challenge,
		ExpectedOrigin:    p.config.Origin,
		ClientDataJSON:    req.Credential.Response.ClientDataJSON,
		AttestationObject: req.Credential.Response.AttestationObject,
	})
	if err != nil {
		log.Printf("registration verification failed: %s", err.Error())
		return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "registration verification failed"})
	}

	prfEnabled := req.PRFSupported != nil && *req.PRFSupported

	cred := StoredCredential{
		CredentialID:  result.CredentialID,
		PublicKeyCOSE: result.PublicKeyCOSE,
		SignCount:     result.SignCount,
		UserID:        req.UserID,
	}

	if prfEnabled {
		prfSaltBytes, err := base64.RawURLEncoding.DecodeString(stored.PRFSalt)
		if err == nil {
			cred.PRFSalt = prfSaltBytes
			cred.PRFSupported = true
		}
	}

	if err := p.config.CredentialStore.Store(cred); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(map[string]string{"error": "failed to store credential"})
	}

	return c.Status(http.StatusOK).JSON(map[string]any{
		"credentialId": base64.RawURLEncoding.EncodeToString(result.CredentialID),
		"registered":   true,
		"prfSupported": prfEnabled,
	})
}

// BeginAuthentication generates a challenge and returns PublicKeyCredentialRequestOptions.
func (p *Passkey) BeginAuthentication(c *fiber.Ctx) error {
	var req struct {
		UserID string `json:"userId"`
	}
	// Body is optional for discoverable credentials
	_ = c.BodyParser(&req)

	challenge, err := p.generateChallenge()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(map[string]string{"error": "failed to generate challenge"})
	}

	challengeKey := req.UserID
	if challengeKey == "" {
		challengeKey = challenge
	}

	if err := p.config.ChallengeStore.Store(challengeKey, challenge, p.config.ChallengeTimeout); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(map[string]string{"error": "failed to store challenge"})
	}

	options := map[string]any{
		"challenge":        challenge,
		"rpId":             p.config.RPID,
		"timeout":          p.config.ChallengeTimeout.Milliseconds(),
		"userVerification": "preferred",
	}

	if req.UserID != "" {
		allowCredentials := []map[string]any{}
		evalByCredential := map[string]map[string]string{}
		hasPRF := false

		creds, err := p.config.CredentialStore.GetByUser(req.UserID)
		if err == nil {
			for _, cr := range creds {
				credIDEncoded := base64.RawURLEncoding.EncodeToString(cr.CredentialID)
				allowCredentials = append(allowCredentials, map[string]any{
					"type": "public-key",
					"id":   credIDEncoded,
				})
				if cr.PRFSupported && len(cr.PRFSalt) > 0 {
					evalByCredential[credIDEncoded] = map[string]string{
						"first": base64.RawURLEncoding.EncodeToString(cr.PRFSalt),
					}
					hasPRF = true
				}
			}
		}
		options["allowCredentials"] = allowCredentials

		if hasPRF {
			options["extensions"] = map[string]any{
				"prf": map[string]any{
					"evalByCredential": evalByCredential,
				},
			}
		}
	}

	return c.Status(http.StatusOK).JSON(options)
}

// FinishAuthentication verifies an authentication response.
func (p *Passkey) FinishAuthentication(c *fiber.Ctx) error {
	var req struct {
		UserID     string `json:"userId"`
		Credential struct {
			ID       string `json:"id"`
			RawID    string `json:"rawId"`
			Type     string `json:"type"`
			Response struct {
				ClientDataJSON    string `json:"clientDataJSON"`
				AuthenticatorData string `json:"authenticatorData"`
				Signature         string `json:"signature"`
				UserHandle        string `json:"userHandle,omitempty"`
			} `json:"response"`
		} `json:"credential"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "invalid request body"})
	}

	challenge, err := p.config.ChallengeStore.Consume(req.UserID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "challenge not found or expired"})
	}

	credIDBytes, err := base64.RawURLEncoding.DecodeString(req.Credential.ID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "invalid credential ID encoding"})
	}

	storedCred, err := p.config.CredentialStore.Get(credIDBytes)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "credential not found"})
	}

	if req.Credential.Response.UserHandle != "" {
		userHandleBytes, err := base64.RawURLEncoding.DecodeString(req.Credential.Response.UserHandle)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "invalid userHandle encoding"})
		}
		if string(userHandleBytes) != storedCred.UserID {
			return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "userHandle does not match credential owner"})
		}
	}

	result, err := webauthn.VerifyAuthentication(webauthn.AuthenticationInput{
		RPID:                p.config.RPID,
		ExpectedChallenge:   challenge,
		ExpectedOrigin:      p.config.Origin,
		StoredPublicKeyCOSE: storedCred.PublicKeyCOSE,
		StoredSignCount:     storedCred.SignCount,
		ClientDataJSON:      req.Credential.Response.ClientDataJSON,
		AuthenticatorData:   req.Credential.Response.AuthenticatorData,
		Signature:           req.Credential.Response.Signature,
	})
	if err != nil {
		log.Printf("authentication verification failed: %s", err.Error())
		return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "authentication verification failed"})
	}

	storedCred.SignCount = result.SignCount
	if err := p.config.CredentialStore.Update(storedCred); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(map[string]string{"error": "failed to update credential"})
	}

	resp := map[string]any{
		"userId":        storedCred.UserID,
		"authenticated": true,
	}
	if storedCred.PRFSupported {
		resp["prfSupported"] = true
	}
	return c.Status(http.StatusOK).JSON(resp)
}
