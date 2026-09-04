// Smoke tests for the FIDO2 conformance server (in-process httptest;
// the sandbox blocks listening sockets, so this stands in for curl).
package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	passkey "github.com/locke-inc/open-passkey/packages/server-go"
)

func testMux(t *testing.T) *http.ServeMux {
	t.Helper()
	pk, err := passkey.New(passkey.Config{
		RPID:                     "localhost",
		RPDisplayName:            "Conformance RP",
		Origin:                   "http://localhost:8099",
		ChallengeStore:           passkey.NewMemoryChallengeStore(),
		CredentialStore:          passkey.NewMemoryCredentialStore(),
		AllowMultipleCredentials: true,
	})
	if err != nil {
		t.Fatalf("failed to create passkey: %v", err)
	}
	return buildMux(newConformanceServer(pk, "localhost", "Conformance RP"))
}

func post(t *testing.T, mux *http.ServeMux, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("POST %s: response is not JSON: %v (%q)", path, err, rec.Body.String())
	}
	t.Logf("POST %s -> HTTP %d %s", path, rec.Code, rec.Body.String())
	return rec.Code, decoded
}

func TestSmokeAllFourEndpoints(t *testing.T) {
	mux := testMux(t)

	// 1. POST /attestation/options (spec example body)
	code, opts := post(t, mux, "/attestation/options", `{
		"username": "johndoe@example.com",
		"displayName": "John Doe",
		"authenticatorSelection": {
			"requireResidentKey": false,
			"authenticatorAttachment": "cross-platform",
			"userVerification": "preferred"
		},
		"attestation": "direct"
	}`)
	if code != http.StatusOK || opts["status"] != "ok" {
		t.Fatalf("attestation/options failed: code=%d body=%v", code, opts)
	}
	for _, f := range []string{"challenge", "rp", "user", "pubKeyCredParams", "attestation"} {
		if _, ok := opts[f]; !ok {
			t.Fatalf("attestation/options response missing %q: %v", f, opts)
		}
	}
	if opts["rp"].(map[string]any)["name"] != "Conformance RP" {
		t.Fatalf("unexpected rp: %v", opts["rp"])
	}

	// 2. POST /assertion/options (spec example body)
	code, ao := post(t, mux, "/assertion/options", `{
		"username": "johndoe@example.com",
		"userVerification": "required"
	}`)
	if code != http.StatusOK || ao["status"] != "ok" {
		t.Fatalf("assertion/options failed: code=%d body=%v", code, ao)
	}
	for _, f := range []string{"challenge", "rpId", "allowCredentials", "userVerification"} {
		if _, ok := ao[f]; !ok {
			t.Fatalf("assertion/options response missing %q: %v", f, ao)
		}
	}
	if ao["rpId"] != "localhost" || ao["userVerification"] != "required" {
		t.Fatalf("unexpected assertion options: %v", ao)
	}

	// 3. POST /attestation/result (spec example body: stale challenge -> graceful fail)
	code, ar := post(t, mux, "/attestation/result", `{
		"id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
		"response": {
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
			"attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
		},
		"getClientExtensionResults": {},
		"type": "public-key"
	}`)
	if ar["status"] != "failed" || ar["errorMessage"] == "" {
		t.Fatalf("attestation/result should fail gracefully: code=%d body=%v", code, ar)
	}

	// 4. POST /assertion/result (spec example body: unknown challenge -> graceful fail)
	code, sr := post(t, mux, "/assertion/result", `{
		"id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
		"response": {
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
			"signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
			"userHandle": "",
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
		},
		"getClientExtensionResults": {},
		"type": "public-key"
	}`)
	if sr["status"] != "failed" || sr["errorMessage"] == "" {
		t.Fatalf("assertion/result should fail gracefully: code=%d body=%v", code, sr)
	}

	// Error shape: missing username
	code, er := post(t, mux, "/attestation/options", `{"displayName":"No Name"}`)
	if code != http.StatusBadRequest || er["status"] != "failed" {
		t.Fatalf("expected failed/400 for missing username: code=%d body=%v", code, er)
	}
}

func TestExtensionsMirroredVerbatim(t *testing.T) {
	mux := testMux(t)

	code, opts := post(t, mux, "/attestation/options", `{
		"username": "extuser@example.com",
		"extensions": {"example.extension": {"flag": true, "n": 3}}
	}`)
	if code != http.StatusOK || opts["status"] != "ok" {
		t.Fatalf("attestation/options failed: code=%d body=%v", code, opts)
	}
	ext, ok := opts["extensions"].(map[string]any)
	if !ok {
		t.Fatalf("response missing extensions: %v", opts)
	}
	got, ok := ext["example.extension"].(map[string]any)
	if !ok || got["flag"] != true || got["n"] != float64(3) {
		t.Fatalf("example.extension not mirrored verbatim: %v", ext)
	}
	if len(ext) != 1 {
		t.Fatalf("extensions must deep-equal the request (no extra keys): %v", ext)
	}

	code, ao := post(t, mux, "/assertion/options", `{
		"username": "extuser@example.com",
		"extensions": {"example.extension": "hello"}
	}`)
	if code != http.StatusOK || ao["status"] != "ok" {
		t.Fatalf("assertion/options failed: code=%d body=%v", code, ao)
	}
	ext, ok = ao["extensions"].(map[string]any)
	if !ok || ext["example.extension"] != "hello" {
		t.Fatalf("example.extension not mirrored verbatim: %v", ao)
	}
}

func TestResultEnvelopeValidation(t *testing.T) {
	mux := testMux(t)

	validResp := `"response": {"clientDataJSON": "e30", "attestationObject": "e30", "authenticatorData": "e30", "signature": "e30"}`
	cases := []struct {
		name string
		body string
	}{
		{"missing-id", `{"type": "public-key", ` + validResp + `}`},
		{"numeric-id", `{"id": 12345, "type": "public-key", ` + validResp + `}`},
		{"non-b64url-id", `{"id": "!!!not-base64url!!!", "type": "public-key", ` + validResp + `}`},
		{"missing-type", `{"id": "aGVsbG8", ` + validResp + `}`},
		{"wrong-type", `{"id": "aGVsbG8", "type": "totally-wrong", ` + validResp + `}`},
		{"null-type", `{"id": "aGVsbG8", "type": null, ` + validResp + `}`},
	}
	for _, path := range []string{"/attestation/result", "/assertion/result"} {
		for _, tc := range cases {
			code, resp := post(t, mux, path, tc.body)
			if code != http.StatusBadRequest {
				t.Errorf("%s %s: expected HTTP 400, got %d (%v)", path, tc.name, code, resp)
			}
			if resp["status"] != "failed" || resp["errorMessage"] == "" {
				t.Errorf("%s %s: expected failed with non-empty errorMessage, got %v", path, tc.name, resp)
			}
		}
	}
}

func TestErrorMessagePassthrough(t *testing.T) {
	mux := testMux(t)

	// Create a pending registration so the envelope passes and server-go
	// itself fails (garbage attestationObject). errorMessage must carry the
	// underlying server-go error, not just a generic string.
	_, opts := post(t, mux, "/attestation/options", `{"username": "erruser@example.com"}`)
	challenge, _ := opts["challenge"].(string)
	if challenge == "" {
		t.Fatalf("no challenge in options: %v", opts)
	}
	cd, _ := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": challenge,
		"origin":    "http://localhost:8099",
	})
	cdB64 := base64.RawURLEncoding.EncodeToString(cd)

	code, resp := post(t, mux, "/attestation/result", `{
		"id": "aGVsbG8",
		"type": "public-key",
		"response": {"clientDataJSON": "`+cdB64+`", "attestationObject": "QUJD"}
	}`)
	if code != http.StatusBadRequest || resp["status"] != "failed" {
		t.Fatalf("expected failed/400, got code=%d body=%v", code, resp)
	}
	msg, _ := resp["errorMessage"].(string)
	if !strings.Contains(msg, "registration verification failed: ") || len(msg) <= len("registration verification failed: ") {
		t.Fatalf("errorMessage does not pass through the underlying error: %q", msg)
	}
}
