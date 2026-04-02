// Package passkey provides a Chi router WebAuthn server binding.
//
// It wraps the core-go webauthn verification library with challenge management,
// credential storage interfaces, and HTTP handlers that implement the full
// registration and authentication ceremonies using the Chi router.
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
//	r := chi.NewRouter()
//	r.Mount("/passkey", p.Routes())
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

	"github.com/go-chi/chi/v5"
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

// Routes returns a chi.Router with all passkey routes registered.
// Mount it on your main router:
//
//	r.Mount("/passkey", p.Routes())
//
// Routes:
//
//	POST /register/begin
//	POST /register/finish
//	POST /login/begin
//	POST /login/finish
func (p *Passkey) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/register/begin", p.BeginRegistration)
	r.Post("/register/finish", p.FinishRegistration)
	r.Post("/login/begin", p.BeginAuthentication)
	r.Post("/login/finish", p.FinishAuthentication)
	return r
}

// generateChallenge creates a cryptographically random challenge, base64url-encoded.
func (p *Passkey) generateChallenge() (string, error) {
	buf := make([]byte, p.config.ChallengeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// --- HTTP Handlers ---

// BeginRegistration generates a challenge and returns PublicKeyCredentialCreationOptions.
// Expects JSON body: {"userId": "...", "username": "..."}
func (p *Passkey) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID   string `json:"userId"`
		Username string `json:"username"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UserID == "" || req.Username == "" {
		writeError(w, http.StatusBadRequest, "userId and username are required")
		return
	}

	challenge, err := p.generateChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}

	prfSalt := make([]byte, 32)
	if _, err := rand.Read(prfSalt); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate PRF salt")
		return
	}

	challengeData, _ := json.Marshal(map[string]string{
		"challenge": challenge,
		"prfSalt":   base64.RawURLEncoding.EncodeToString(prfSalt),
	})
	if err := p.config.ChallengeStore.Store(req.UserID, string(challengeData), p.config.ChallengeTimeout); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store challenge")
		return
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

	writeJSON(w, http.StatusOK, options)
}

// FinishRegistration verifies a registration response and stores the credential.
func (p *Passkey) FinishRegistration(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	challengeData, err := p.config.ChallengeStore.Consume(req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "challenge not found or expired")
		return
	}
	var stored struct {
		Challenge string `json:"challenge"`
		PRFSalt   string `json:"prfSalt"`
	}
	if err := json.Unmarshal([]byte(challengeData), &stored); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to decode challenge data")
		return
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
		writeError(w, http.StatusBadRequest, "registration verification failed")
		return
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
		writeError(w, http.StatusInternalServerError, "failed to store credential")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"credentialId": base64.RawURLEncoding.EncodeToString(result.CredentialID),
		"registered":   true,
		"prfSupported": prfEnabled,
	})
}

// BeginAuthentication generates a challenge and returns PublicKeyCredentialRequestOptions.
func (p *Passkey) BeginAuthentication(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userId"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	_ = json.NewDecoder(r.Body).Decode(&req)

	challenge, err := p.generateChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}

	challengeKey := req.UserID
	if challengeKey == "" {
		challengeKey = challenge
	}

	if err := p.config.ChallengeStore.Store(challengeKey, challenge, p.config.ChallengeTimeout); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store challenge")
		return
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
			for _, c := range creds {
				credIDEncoded := base64.RawURLEncoding.EncodeToString(c.CredentialID)
				allowCredentials = append(allowCredentials, map[string]any{
					"type": "public-key",
					"id":   credIDEncoded,
				})
				if c.PRFSupported && len(c.PRFSalt) > 0 {
					evalByCredential[credIDEncoded] = map[string]string{
						"first": base64.RawURLEncoding.EncodeToString(c.PRFSalt),
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

	writeJSON(w, http.StatusOK, options)
}

// FinishAuthentication verifies an authentication response.
func (p *Passkey) FinishAuthentication(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	challenge, err := p.config.ChallengeStore.Consume(req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "challenge not found or expired")
		return
	}

	credIDBytes, err := base64.RawURLEncoding.DecodeString(req.Credential.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid credential ID encoding")
		return
	}

	storedCred, err := p.config.CredentialStore.Get(credIDBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "credential not found")
		return
	}

	if req.Credential.Response.UserHandle != "" {
		userHandleBytes, err := base64.RawURLEncoding.DecodeString(req.Credential.Response.UserHandle)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid userHandle encoding")
			return
		}
		if string(userHandleBytes) != storedCred.UserID {
			writeError(w, http.StatusBadRequest, "userHandle does not match credential owner")
			return
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
		writeError(w, http.StatusBadRequest, "authentication verification failed")
		return
	}

	storedCred.SignCount = result.SignCount
	if err := p.config.CredentialStore.Update(storedCred); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update credential")
		return
	}

	resp := map[string]any{
		"userId":        storedCred.UserID,
		"authenticated": true,
	}
	if storedCred.PRFSupported {
		resp["prfSupported"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- HTTP helpers ---

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
