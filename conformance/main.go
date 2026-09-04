// Command conformance runs a FIDO2 conformance test server.
//
// It implements the FIDO Alliance conformance testing API
// (/tmp/conformance-api.md) on top of packages/server-go:
//
//	POST /attestation/options  - ServerPublicKeyCredentialCreationOptionsRequest
//	POST /attestation/result   - ServerPublicKeyCredential (attestation response)
//	POST /assertion/options    - ServerPublicKeyCredentialGetOptionsRequest
//	POST /assertion/result     - ServerPublicKeyCredential (assertion response)
//
// Configuration via environment:
//
//	RP_ID   - relying party ID, bare domain (default "localhost")
//	ORIGIN  - expected WebAuthn origin, e.g. http://localhost:8099
//	          (default "http://" + RP_ID + ":" + PORT)
//	PORT    - listen port (default "8099")
//	RP_NAME - RP display name (default "Conformance RP")
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"

	passkey "github.com/locke-inc/open-passkey/packages/server-go"
)

// serverResponse is the Common IDL ServerResponse.
type serverResponse struct {
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage"`
}

func okResponse() serverResponse { return serverResponse{Status: "ok", ErrorMessage: ""} }

func failResponse(msg string) serverResponse {
	return serverResponse{Status: "failed", ErrorMessage: msg}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeFail(w http.ResponseWriter, httpStatus int, msg string) {
	writeJSON(w, httpStatus, failResponse(msg))
}

// conformanceServer adapts the FIDO conformance API to a passkey.Passkey.
//
// server-go keys challenges by userId, while the conformance /result calls
// carry no username. The adapter therefore records which challenge was issued
// for which user (challenge -> lookup key) at /options time and, at /result
// time, decodes the challenge out of clientDataJSON to recover the user.
type conformanceServer struct {
	pk          *passkey.Passkey
	rpID        string
	rpName      string
	mu          sync.Mutex
	pendingReg  map[string]string // reg challenge -> userId
	pendingAuth map[string]string // auth challenge -> challenge-store lookup key
	lastRegUser string
}

func (s *conformanceServer) rememberReg(challenge, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingReg[challenge] = userID
	s.lastRegUser = userID
}

func (s *conformanceServer) lookupReg(challenge string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.pendingReg[challenge]; ok {
		return u
	}
	return ""
}

func (s *conformanceServer) forgetReg(challenge string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingReg, challenge)
}

func (s *conformanceServer) rememberAuth(challenge, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingAuth[challenge] = key
}

func (s *conformanceServer) lookupAuth(challenge string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingAuth[challenge]
}

func (s *conformanceServer) forgetAuth(challenge string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingAuth, challenge)
}

// challengeFromClientData extracts the challenge string from base64url
// clientDataJSON without validating anything.
func challengeFromClientData(clientDataB64 string) string {
	raw, err := base64.RawURLEncoding.DecodeString(clientDataB64)
	if err != nil {
		return ""
	}
	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(raw, &cd); err != nil {
		return ""
	}
	return cd.Challenge
}

// callPK invokes a passkey handler with a synthetic JSON request and returns
// the recorded status code and decoded JSON body.
func (s *conformanceServer) callPK(handler func(http.ResponseWriter, *http.Request), body any) (int, map[string]any) {
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)
	var decoded map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
	if decoded == nil {
		decoded = map[string]any{}
	}
	return rec.Code, decoded
}

func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeFail(w, http.StatusMethodNotAllowed, "method must be POST")
		return false
	}
	return true
}

// pkError extracts server-go's error string for errorMessage passthrough.
// It never returns empty, so errorMessage stays non-empty per spec even when
// server-go gives no detail.
func pkError(resp map[string]any) string {
	if e, ok := resp["error"].(string); ok && e != "" {
		return e
	}
	return "unknown error"
}

// POST /attestation/options
func (s *conformanceServer) attestationOptions(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Username               string         `json:"username"`
		DisplayName            string         `json:"displayName"`
		AuthenticatorSelection map[string]any `json:"authenticatorSelection"`
		Attestation            string         `json:"attestation"`
		Extensions             map[string]any `json:"extensions"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeFail(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" {
		writeFail(w, http.StatusBadRequest, "username is required")
		return
	}
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	// server-go identifies users by userId; the conformance tool only knows
	// usernames, so userId = username. Forward authenticatorSelection so the
	// userVerification requirement reaches server-go challenge storage.
	beginBody := map[string]any{
		"userId":   req.Username,
		"username": displayName,
	}
	if req.AuthenticatorSelection != nil {
		beginBody["authenticatorSelection"] = req.AuthenticatorSelection
	}
	code, opts := s.callPK(s.pk.BeginRegistration, beginBody)
	if code != http.StatusOK {
		msg := "failed to create registration options"
		if e, ok := opts["error"].(string); ok && e != "" {
			msg = e
		}
		writeFail(w, http.StatusBadRequest, msg)
		return
	}

	challenge, _ := opts["challenge"].(string)
	if challenge == "" {
		writeFail(w, http.StatusInternalServerError, "missing challenge field")
		return
	}
	s.rememberReg(challenge, req.Username)

	userMap, _ := opts["user"].(map[string]any)
	userID, _ := userMap["id"].(string)

	attestation := req.Attestation
	if attestation == "" {
		if a, ok := opts["attestation"].(string); ok && a != "" {
			attestation = a
		} else {
			attestation = "none"
		}
	}
	authSel := req.AuthenticatorSelection
	if authSel == nil {
		if a, ok := opts["authenticatorSelection"].(map[string]any); ok {
			authSel = a
		}
	}
	excludeCreds := opts["excludeCredentials"]
	if excludeCreds == nil {
		excludeCreds = []any{}
	}
	pubKeyCredParams := opts["pubKeyCredParams"]
	if pubKeyCredParams == nil {
		pubKeyCredParams = []any{map[string]any{"type": "public-key", "alg": -7}}
	}

	resp := map[string]any{
		"status":       "ok",
		"errorMessage": "",
		"rp": map[string]string{
			"id":   s.rpID,
			"name": s.rpName,
		},
		"user": map[string]string{
			"id":          userID,
			"name":        req.Username,
			"displayName": displayName,
		},
		"challenge":              challenge,
		"pubKeyCredParams":       pubKeyCredParams,
		"timeout":                opts["timeout"],
		"excludeCredentials":     excludeCreds,
		"authenticatorSelection": authSel,
		"attestation":            attestation,
	}
	// Mirror requested extensions verbatim. The conformance tool
	// deep-compares response.extensions against the request, so server-go's
	// own extensions (e.g. prf) must NOT be merged in when the tool asked
	// for specific extensions.
	if len(req.Extensions) > 0 {
		resp["extensions"] = req.Extensions
	}
	writeJSON(w, http.StatusOK, resp)
}

// validateEnvelope checks the credential envelope shared by both /result
// endpoints before server-go is invoked: id must be a present, non-empty,
// base64url-encoded string; type must be present and equal "public-key".
// It returns the validated id or an error message (empty when valid).
func validateEnvelope(id, credType any) (string, string) {
	idStr, ok := id.(string)
	if !ok || idStr == "" {
		return "", "id must be a base64url-encoded string"
	}
	if _, err := base64.RawURLEncoding.DecodeString(idStr); err != nil {
		return "", "id must be a base64url-encoded string"
	}
	typeStr, ok := credType.(string)
	if !ok || typeStr == "" {
		return "", `type is required and must be "public-key"`
	}
	if typeStr != "public-key" {
		return "", `type must be "public-key"`
	}
	return idStr, ""
}

// POST /attestation/result
func (s *conformanceServer) attestationResult(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		ID       any `json:"id"`
		Type     any `json:"type"`
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		} `json:"response"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeFail(w, http.StatusBadRequest, "invalid request body")
		return
	}
	credID, msg := validateEnvelope(req.ID, req.Type)
	if msg != "" {
		writeFail(w, http.StatusBadRequest, msg)
		return
	}
	if req.Response.ClientDataJSON == "" || req.Response.AttestationObject == "" {
		writeFail(w, http.StatusBadRequest, "response.clientDataJSON and response.attestationObject are required")
		return
	}

	username := s.lookupReg(challengeFromClientData(req.Response.ClientDataJSON))
	if username == "" {
		s.mu.Lock()
		username = s.lastRegUser
		s.mu.Unlock()
	}
	if username == "" {
		writeFail(w, http.StatusBadRequest, "no pending registration challenge for this response")
		return
	}

	code, finishResp := s.callPK(s.pk.FinishRegistration, map[string]any{
		"userId": username,
		"credential": map[string]any{
			"id":    credID,
			"rawId": credID,
			"type":  "public-key",
			"response": map[string]string{
				"clientDataJSON":    req.Response.ClientDataJSON,
				"attestationObject": req.Response.AttestationObject,
			},
		},
	})
	if code != http.StatusOK {
		writeFail(w, http.StatusBadRequest, "registration verification failed: "+pkError(finishResp))
		return
	}
	s.forgetReg(challengeFromClientData(req.Response.ClientDataJSON))
	writeJSON(w, http.StatusOK, okResponse())
}

// POST /assertion/options
func (s *conformanceServer) assertionOptions(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Username         string         `json:"username"`
		UserVerification string         `json:"userVerification"`
		Extensions       map[string]any `json:"extensions"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeFail(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" {
		writeFail(w, http.StatusBadRequest, "username is required")
		return
	}

	// Forward userVerification so server-go persists and enforces it.
	beginBody := map[string]string{
		"userId": req.Username,
	}
	if req.UserVerification != "" {
		beginBody["userVerification"] = req.UserVerification
	}
	code, opts := s.callPK(s.pk.BeginAuthentication, beginBody)
	if code != http.StatusOK {
		msg := "failed to create authentication options"
		if e, ok := opts["error"].(string); ok && e != "" {
			msg = e
		}
		writeFail(w, http.StatusBadRequest, msg)
		return
	}

	challenge, _ := opts["challenge"].(string)
	if challenge == "" {
		writeFail(w, http.StatusInternalServerError, "missing challenge field")
		return
	}
	// server-go stores this challenge under the userId key.
	s.rememberAuth(challenge, req.Username)

	allowCreds := opts["allowCredentials"]
	if allowCreds == nil {
		allowCreds = []any{}
	}
	userVerification := req.UserVerification
	if userVerification == "" {
		if uv, ok := opts["userVerification"].(string); ok && uv != "" {
			userVerification = uv
		} else {
			userVerification = "preferred"
		}
	}

	resp := map[string]any{
		"status":           "ok",
		"errorMessage":     "",
		"challenge":        challenge,
		"timeout":          opts["timeout"],
		"rpId":             s.rpID,
		"allowCredentials": allowCreds,
		"userVerification": userVerification,
	}
	// Mirror requested extensions verbatim, as in attestation/options.
	if len(req.Extensions) > 0 {
		resp["extensions"] = req.Extensions
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /assertion/result
func (s *conformanceServer) assertionResult(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		ID       any `json:"id"`
		Type     any `json:"type"`
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
			UserHandle        string `json:"userHandle"`
		} `json:"response"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeFail(w, http.StatusBadRequest, "invalid request body")
		return
	}
	credID, msg := validateEnvelope(req.ID, req.Type)
	if msg != "" {
		writeFail(w, http.StatusBadRequest, msg)
		return
	}
	if req.Response.ClientDataJSON == "" ||
		req.Response.AuthenticatorData == "" || req.Response.Signature == "" {
		writeFail(w, http.StatusBadRequest, "response.clientDataJSON, response.authenticatorData and response.signature are required")
		return
	}

	challenge := challengeFromClientData(req.Response.ClientDataJSON)
	lookupKey := s.lookupAuth(challenge)
	if lookupKey == "" {
		writeFail(w, http.StatusBadRequest, "challenge not found or expired")
		return
	}

	code, finishResp := s.callPK(s.pk.FinishAuthentication, map[string]any{
		"userId":    lookupKey,
		"challenge": lookupKey, // harmless when userId is set; used for discoverable flow
		"credential": map[string]any{
			"id":    credID,
			"rawId": credID,
			"type":  "public-key",
			"response": map[string]string{
				"clientDataJSON":    req.Response.ClientDataJSON,
				"authenticatorData": req.Response.AuthenticatorData,
				"signature":         req.Response.Signature,
				"userHandle":        req.Response.UserHandle,
			},
		},
	})
	if code != http.StatusOK {
		writeFail(w, http.StatusBadRequest, "authentication verification failed: "+pkError(finishResp))
		return
	}
	s.forgetAuth(challenge)
	writeJSON(w, http.StatusOK, okResponse())
}

func newConformanceServer(pk *passkey.Passkey, rpID, rpName string) *conformanceServer {
	return &conformanceServer{
		pk:          pk,
		rpID:        rpID,
		rpName:      rpName,
		pendingReg:  make(map[string]string),
		pendingAuth: make(map[string]string),
	}
}

func buildMux(s *conformanceServer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/attestation/options", s.attestationOptions)
	mux.HandleFunc("/attestation/result", s.attestationResult)
	mux.HandleFunc("/assertion/options", s.assertionOptions)
	mux.HandleFunc("/assertion/result", s.assertionResult)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	port := getenv("PORT", "8099")
	rpID := getenv("RP_ID", getenv("RPID", "localhost"))
	rpName := getenv("RP_NAME", "Conformance RP")
	origin := getenv("ORIGIN", getenv("RP_ORIGIN", "http://"+rpID+":"+port))

	pk, err := passkey.New(passkey.Config{
		RPID:                     rpID,
		RPDisplayName:            rpName,
		Origin:                   origin,
		ChallengeStore:           passkey.NewMemoryChallengeStore(),
		CredentialStore:          passkey.NewMemoryCredentialStore(),
		AllowMultipleCredentials: true, // conformance tool registers repeatedly
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create passkey: %v\n", err)
		os.Exit(1)
	}

	s := newConformanceServer(pk, rpID, rpName)

	mux := buildMux(s)

	fmt.Printf("Conformance server listening on :%s (rpId=%s origin=%s)\n", port, rpID, origin)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
