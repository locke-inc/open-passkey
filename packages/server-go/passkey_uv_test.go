package passkey_test

// End-to-end userVerification threading tests: a hand-rolled ES256 ceremony
// (stdlib crypto + manual CBOR, no extra dependencies) drives Begin/Finish
// through httptest to prove the UV requirement flows from the begin request,
// through challenge storage, into verification.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"

	"github.com/locke-inc/open-passkey/packages/server-go"
)

func uvTestPasskey(t *testing.T) *passkey.Passkey {
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

func mustP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating P-256 key: %v", err)
	}
	return k
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// cborCOSEES256 hand-encodes {1:2, 3:-7, -1:1, -2:x, -3:y}.
func cborCOSEES256(x, y []byte) []byte {
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01}
	out = append(out, 0x21, 0x58, 0x20)
	out = append(out, pad32(x)...)
	out = append(out, 0x22, 0x58, 0x20)
	out = append(out, pad32(y)...)
	return out
}

func cborBstr(b []byte) []byte {
	var out []byte
	switch {
	case len(b) < 24:
		out = append(out, 0x40+byte(len(b)))
	case len(b) < 256:
		out = append(out, 0x58, byte(len(b)))
	default:
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(b)))
		out = append(out, 0x59, l[0], l[1])
	}
	return append(out, b...)
}

// cborNoneAttestationObject hand-encodes
// {"fmt":"none","authData":h'..',"attStmt":{}}.
func cborNoneAttestationObject(authData []byte) []byte {
	out := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e'}
	out = append(out, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a')
	out = append(out, cborBstr(authData)...)
	out = append(out, 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0)
	return out
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// uvRegCeremony builds a fmt=none registration ceremony for rpId
// example.com. uv controls the UV flag bit.
func uvRegCeremony(t *testing.T, key *ecdsa.PrivateKey, challenge string, uv bool) (credID, clientDataJSON, attObj string) {
	t.Helper()
	credIDBytes := []byte("uv-test-cred-0001")
	rpHash := sha256.Sum256([]byte("example.com"))
	var flags byte = 0x41 // UP + AT
	if uv {
		flags |= 0x04
	}
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, flags, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...) // aaguid
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(credIDBytes)))
	authData = append(authData, l[:]...)
	authData = append(authData, credIDBytes...)
	authData = append(authData, cborCOSEES256(key.PublicKey.X.Bytes(), key.PublicKey.Y.Bytes())...)

	cd, _ := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": challenge,
		"origin":    "https://example.com",
	})
	return b64u(credIDBytes), b64u(cd), b64u(cborNoneAttestationObject(authData))
}

func uvBeginReg(t *testing.T, p *passkey.Passkey, userID, uv string) string {
	t.Helper()
	body := map[string]any{"userId": userID, "username": userID}
	if uv != "" {
		body["authenticatorSelection"] = map[string]any{"userVerification": uv}
	}
	w := postJSON(p.BeginRegistration, body)
	if w.Code != http.StatusOK {
		t.Fatalf("BeginRegistration: got %d: %s", w.Code, w.Body.String())
	}
	resp := decodeResponse(t, w)
	if uv != "" {
		authSel, ok := resp["authenticatorSelection"].(map[string]any)
		if !ok || authSel["userVerification"] != uv {
			t.Fatalf("authenticatorSelection.userVerification: got %v, want %s", resp["authenticatorSelection"], uv)
		}
	}
	ch, _ := resp["challenge"].(string)
	if ch == "" {
		t.Fatal("BeginRegistration response missing challenge")
	}
	return ch
}

func uvFinishReg(t *testing.T, p *passkey.Passkey, userID, credID, cd, ao string) *http.Response {
	t.Helper()
	w := postJSON(p.FinishRegistration, map[string]any{
		"userId": userID,
		"credential": map[string]any{
			"id": credID, "rawId": credID, "type": "public-key",
			"response": map[string]string{"clientDataJSON": cd, "attestationObject": ao},
		},
	})
	return w.Result()
}

func TestRegistrationUserVerificationEnforced(t *testing.T) {
	// UV required + UV flag set -> success.
	p := uvTestPasskey(t)
	key := mustP256Key(t)
	ch := uvBeginReg(t, p, "uv-user-1", "required")
	credID, cd, ao := uvRegCeremony(t, key, ch, true)
	if resp := uvFinishReg(t, p, "uv-user-1", credID, cd, ao); resp.StatusCode != http.StatusOK {
		t.Fatalf("UV-required with UV flag: got %d, want 200", resp.StatusCode)
	}

	// UV required + UV flag missing -> 400.
	p = uvTestPasskey(t)
	ch = uvBeginReg(t, p, "uv-user-2", "required")
	credID, cd, ao = uvRegCeremony(t, key, ch, false)
	if resp := uvFinishReg(t, p, "uv-user-2", credID, cd, ao); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("UV-required without UV flag: got %d, want 400", resp.StatusCode)
	}

	// UV not requested + UV flag missing -> success (no behavior change).
	p = uvTestPasskey(t)
	ch = uvBeginReg(t, p, "uv-user-3", "")
	credID, cd, ao = uvRegCeremony(t, key, ch, false)
	if resp := uvFinishReg(t, p, "uv-user-3", credID, cd, ao); resp.StatusCode != http.StatusOK {
		t.Fatalf("UV-default without UV flag: got %d, want 200", resp.StatusCode)
	}
}

// uvAuthCeremony builds an assertion over the registered key. uv controls
// the UV flag bit; signCount must exceed the stored count.
func uvAuthCeremony(t *testing.T, key *ecdsa.PrivateKey, challenge string, uv bool, signCount uint32) (cd, authData, sig string) {
	t.Helper()
	rpHash := sha256.Sum256([]byte("example.com"))
	var flags byte = 0x01 // UP
	if uv {
		flags |= 0x04
	}
	ad := append([]byte{}, rpHash[:]...)
	ad = append(ad, flags)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	ad = append(ad, sc[:]...)

	cdRaw, _ := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": challenge,
		"origin":    "https://example.com",
	})
	cdHash := sha256.Sum256(cdRaw)
	verifyData := append(append([]byte{}, ad...), cdHash[:]...)
	hash := sha256.Sum256(verifyData)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("signing assertion: %v", err)
	}
	derSig, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		t.Fatalf("marshaling signature: %v", err)
	}
	return b64u(cdRaw), b64u(ad), b64u(derSig)
}

func TestAuthenticationUserVerificationEnforced(t *testing.T) {
	p := uvTestPasskey(t)
	key := mustP256Key(t)

	// Register (no UV requirement so plain flags pass).
	ch := uvBeginReg(t, p, "uv-auth-user", "")
	credID, cd, ao := uvRegCeremony(t, key, ch, false)
	if resp := uvFinishReg(t, p, "uv-auth-user", credID, cd, ao); resp.StatusCode != http.StatusOK {
		t.Fatalf("registration: got %d, want 200", resp.StatusCode)
	}

	beginAuth := func(uv string) string {
		t.Helper()
		body := map[string]string{"userId": "uv-auth-user"}
		if uv != "" {
			body["userVerification"] = uv
		}
		w := postJSON(p.BeginAuthentication, body)
		if w.Code != http.StatusOK {
			t.Fatalf("BeginAuthentication: got %d: %s", w.Code, w.Body.String())
		}
		resp := decodeResponse(t, w)
		if uv != "" && resp["userVerification"] != uv {
			t.Fatalf("userVerification echo: got %v, want %s", resp["userVerification"], uv)
		}
		ch, _ := resp["challenge"].(string)
		if ch == "" {
			t.Fatal("BeginAuthentication response missing challenge")
		}
		return ch
	}
	finishAuth := func(cd, ad, sig string) int {
		t.Helper()
		w := postJSON(p.FinishAuthentication, map[string]any{
			"userId": "uv-auth-user",
			"credential": map[string]any{
				"id": credID, "rawId": credID, "type": "public-key",
				"response": map[string]string{
					"clientDataJSON": cd, "authenticatorData": ad, "signature": sig,
				},
			},
		})
		return w.Code
	}

	// UV required + UV flag set -> success.
	cd2, ad2, sig2 := uvAuthCeremony(t, key, beginAuth("required"), true, 1)
	if code := finishAuth(cd2, ad2, sig2); code != http.StatusOK {
		t.Fatalf("UV-required with UV flag: got %d, want 200", code)
	}

	// UV required + UV flag missing -> 400.
	cd3, ad3, sig3 := uvAuthCeremony(t, key, beginAuth("required"), false, 2)
	if code := finishAuth(cd3, ad3, sig3); code != http.StatusBadRequest {
		t.Fatalf("UV-required without UV flag: got %d, want 400", code)
	}

	// UV default + UV flag missing -> success.
	cd4, ad4, sig4 := uvAuthCeremony(t, key, beginAuth(""), false, 2)
	if code := finishAuth(cd4, ad4, sig4); code != http.StatusOK {
		t.Fatalf("UV-default without UV flag: got %d, want 200", code)
	}
}
