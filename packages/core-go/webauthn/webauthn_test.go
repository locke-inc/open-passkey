package webauthn_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/locke-inc/open-passkey/packages/core-go/webauthn"
)

const vectorsDir = "../../../spec/vectors"

// --- JSON vector schema types ---

type VectorFile struct {
	Description string       `json:"description"`
	Vectors     []TestVector `json:"vectors"`
}

type TestVector struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Input       map[string]any `json:"input"`
	Expected    Expected       `json:"expected"`
}

type Expected struct {
	Success       bool    `json:"success"`
	Error         string  `json:"error,omitempty"`
	CredentialID  string  `json:"credentialId,omitempty"`
	PublicKeyCOSE string  `json:"publicKeyCose,omitempty"`
	SignCount     *uint32 `json:"signCount,omitempty"`
	RPIDHash      string  `json:"rpIdHash,omitempty"`
}

func loadVectors(t *testing.T, filename string) VectorFile {
	t.Helper()
	path := filepath.Join(vectorsDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read vector file %s: %v", path, err)
	}
	var vf VectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("failed to parse vector file %s: %v", path, err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatalf("vector file %s contains no test vectors", path)
	}
	return vf
}

func b64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// sentinelErrors maps vector error codes to sentinel errors for errors.Is matching.
var sentinelErrors = map[string]error{
	"type_mismatch":                   webauthn.ErrTypeMismatch,
	"challenge_mismatch":              webauthn.ErrChallengeMismatch,
	"origin_mismatch":                 webauthn.ErrOriginMismatch,
	"rp_id_mismatch":                  webauthn.ErrRPIDMismatch,
	"signature_invalid":               webauthn.ErrSignatureInvalid,
	"authenticator_data_too_short":    webauthn.ErrAuthDataTooShort,
	"no_attested_credential_data":     webauthn.ErrNoCredentialData,
	"unsupported_cose_algorithm":      webauthn.ErrUnsupportedAlg,
	"sign_count_rollback":             webauthn.ErrSignCountRollback,
	"user_presence_required":          webauthn.ErrUserPresenceRequired,
	"user_verification_required":      webauthn.ErrUserVerificationRequired,
	"unsupported_attestation_format":  webauthn.ErrUnsupportedAttestationFormat,
	"token_binding_unsupported":       webauthn.ErrTokenBindingUnsupported,
	"invalid_backup_state":            webauthn.ErrInvalidBackupState,
	"invalid_attestation_statement":   webauthn.ErrInvalidAttestationStatement,
}

func assertExpectedError(t *testing.T, err error, expectedCode string) {
	t.Helper()
	sentinel, ok := sentinelErrors[expectedCode]
	if ok {
		if !errors.Is(err, sentinel) {
			t.Errorf("error: got %q, want errors.Is(%q)", err.Error(), expectedCode)
		}
	} else {
		if err.Error() != expectedCode {
			t.Errorf("error: got %q, want %q", err.Error(), expectedCode)
		}
	}
}

// --- Registration ceremony tests ---

func TestRegistrationVectors(t *testing.T) {
	vf := loadVectors(t, "registration.json")

	for _, vec := range vf.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			input := vec.Input
			credential := input["credential"].(map[string]any)
			response := credential["response"].(map[string]any)

			result, err := webauthn.VerifyRegistration(webauthn.RegistrationInput{
				RPID:              input["rpId"].(string),
				ExpectedChallenge: input["expectedChallenge"].(string),
				ExpectedOrigin:    input["expectedOrigin"].(string),
				ClientDataJSON:    response["clientDataJSON"].(string),
				AttestationObject: response["attestationObject"].(string),
			})

			if vec.Expected.Success {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if vec.Expected.CredentialID != "" {
					got := b64Encode(result.CredentialID)
					if got != vec.Expected.CredentialID {
						t.Errorf("credentialId: got %s, want %s", got, vec.Expected.CredentialID)
					}
				}
				if vec.Expected.PublicKeyCOSE != "" {
					got := b64Encode(result.PublicKeyCOSE)
					if got != vec.Expected.PublicKeyCOSE {
						t.Errorf("publicKeyCose: got %s, want %s", got, vec.Expected.PublicKeyCOSE)
					}
				}
				if vec.Expected.SignCount != nil {
					if result.SignCount != *vec.Expected.SignCount {
						t.Errorf("signCount: got %d, want %d", result.SignCount, *vec.Expected.SignCount)
					}
				}
				if vec.Expected.RPIDHash != "" {
					got := b64Encode(result.RPIDHash)
					if got != vec.Expected.RPIDHash {
						t.Errorf("rpIdHash: got %s, want %s", got, vec.Expected.RPIDHash)
					}
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %q, got success", vec.Expected.Error)
				}
				assertExpectedError(t, err, vec.Expected.Error)
			}
		})
	}
}

// --- Authentication ceremony tests ---

func TestAuthenticationVectors(t *testing.T) {
	testAuthenticationVectorFile(t, "authentication.json")
}

func TestHybridAuthenticationVectors(t *testing.T) {
	testAuthenticationVectorFile(t, "hybrid_authentication.json")
}

func testAuthenticationVectorFile(t *testing.T, filename string) {
	t.Helper()
	vf := loadVectors(t, filename)

	for _, vec := range vf.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			input := vec.Input
			credential := input["credential"].(map[string]any)
			response := credential["response"].(map[string]any)

			storedPubKeyB64 := input["storedPublicKeyCose"].(string)
			storedPubKey, err := base64.RawURLEncoding.DecodeString(storedPubKeyB64)
			if err != nil {
				t.Fatalf("decoding storedPublicKeyCose: %v", err)
			}

			storedSignCount := uint32(input["storedSignCount"].(float64))

			result, err := webauthn.VerifyAuthentication(webauthn.AuthenticationInput{
				RPID:                input["rpId"].(string),
				ExpectedChallenge:   input["expectedChallenge"].(string),
				ExpectedOrigin:      input["expectedOrigin"].(string),
				StoredPublicKeyCOSE: storedPubKey,
				StoredSignCount:     storedSignCount,
				ClientDataJSON:      response["clientDataJSON"].(string),
				AuthenticatorData:   response["authenticatorData"].(string),
				Signature:           response["signature"].(string),
			})

			if vec.Expected.Success {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if vec.Expected.SignCount != nil {
					if result.SignCount != *vec.Expected.SignCount {
						t.Errorf("signCount: got %d, want %d", result.SignCount, *vec.Expected.SignCount)
					}
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %q, got success", vec.Expected.Error)
				}
				assertExpectedError(t, err, vec.Expected.Error)
			}
		})
	}
}
