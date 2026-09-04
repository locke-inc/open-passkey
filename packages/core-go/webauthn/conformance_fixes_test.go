package webauthn

// Unit tests for the FIDO conformance fixes: strict tokenBinding validation,
// fmt=none with non-empty attStmt, trailing bytes after attested credential
// data, and packed x5c leaf validity periods.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func b64urlStr(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- tokenBinding (verifyClientData) ---

func testClientDataWithTokenBinding(t *testing.T, tokenBinding string) string {
	t.Helper()
	cd := `{"type":"webauthn.create","challenge":"c","origin":"https://example.com"`
	if tokenBinding != "" {
		cd += `,"tokenBinding":` + tokenBinding
	}
	cd += `}`
	return b64urlStr([]byte(cd))
}

func TestVerifyClientDataTokenBinding(t *testing.T) {
	cases := []struct {
		name         string
		tokenBinding string
		wantErr      bool
		wantSentinel error
	}{
		{"absent", "", false, nil},
		{"null", "null", false, nil},
		{"supported", `{"status":"supported"}`, false, nil},
		{"not-supported", `{"status":"not-supported"}`, false, nil},
		{"with-id", `{"id":"dGVzdA","status":"supported"}`, false, nil},
		{"present", `{"status":"present"}`, true, ErrTokenBindingUnsupported},
		{"unknown-status", `{"status":"bogus"}`, true, ErrTokenBindingUnsupported},
		{"empty-object", `{}`, true, ErrTokenBindingUnsupported},
		{"string", `"notaobject"`, true, nil},
		{"number", `42`, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifyClientData(
				testClientDataWithTokenBinding(t, tc.tokenBinding),
				"webauthn.create", "c", "https://example.com", nil,
			)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got success")
			}
			if tc.wantSentinel != nil && !errors.Is(err, tc.wantSentinel) {
				t.Fatalf("expected errors.Is(%v), got %v", tc.wantSentinel, err)
			}
		})
	}
}

// --- fmt=none with non-empty attStmt (decodeAttestationObject) ---

func testNoneAttestationObject(t *testing.T, attStmt map[string]any, rawAttStmt cbor.RawMessage) string {
	t.Helper()
	authData := append(testFakeAuthData(), make([]byte, 16+2+8)...)
	obj := map[string]any{
		"fmt":      "none",
		"authData": authData,
	}
	if rawAttStmt != nil {
		obj["attStmt"] = rawAttStmt
	} else {
		obj["attStmt"] = attStmt
	}
	encoded, err := cbor.Marshal(obj)
	if err != nil {
		t.Fatalf("marshaling attestation object: %v", err)
	}
	return b64urlStr(encoded)
}

func TestDecodeNoneAttestationStatement(t *testing.T) {
	if _, err := decodeAttestationObject(testNoneAttestationObject(t, map[string]any{}, nil)); err != nil {
		t.Fatalf("empty attStmt should be accepted: %v", err)
	}
	_, err := decodeAttestationObject(testNoneAttestationObject(t, map[string]any{"alg": -7}, nil))
	if err == nil {
		t.Fatal("non-empty attStmt with fmt=none should be rejected")
	}
	if !errors.Is(err, ErrInvalidAttestationStatement) {
		t.Fatalf("expected errors.Is(ErrInvalidAttestationStatement), got %v", err)
	}
}

// --- trailing bytes (parseAuthenticatorData) ---

func testAuthDataWithCred(t *testing.T, flags byte, extra []byte) []byte {
	t.Helper()
	key := testMustECKey(t)
	// testCoseES256 takes raw x/y; pad to 32 bytes.
	xb := key.PublicKey.X.Bytes()
	yb := key.PublicKey.Y.Bytes()
	coseKey := testCoseES256(t, testPad32(xb), testPad32(yb))
	rpIDHash := sha256.Sum256([]byte("example.com"))
	out := append([]byte{}, rpIDHash[:]...)
	out = append(out, flags)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], 1)
	out = append(out, sc[:]...)
	out = append(out, make([]byte, 16)...) // aaguid
	credID := []byte("credential-id-01")
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(credID)))
	out = append(out, l[:]...)
	out = append(out, credID...)
	out = append(out, coseKey...)
	out = append(out, extra...)
	return out
}

func TestParseAuthenticatorDataTrailingBytes(t *testing.T) {
	// Clean authData without extensions flag.
	pad, err := parseAuthenticatorData(testAuthDataWithCred(t, 0x41, nil), true)
	if err != nil {
		t.Fatalf("clean authData rejected: %v", err)
	}
	if string(pad.CredentialID) != "credential-id-01" {
		t.Fatalf("credentialId: got %q", pad.CredentialID)
	}

	// Appended garbage with no extensions flag.
	_, err = parseAuthenticatorData(testAuthDataWithCred(t, 0x41, []byte{0x00}), true)
	if !errors.Is(err, ErrAuthDataTrailingBytes) {
		t.Fatalf("expected ErrAuthDataTrailingBytes, got %v", err)
	}

	// Extensions flag with a valid single extensions map.
	extMap, _ := cbor.Marshal(map[string]string{"appid": "https://example.com"})
	pad, err = parseAuthenticatorData(testAuthDataWithCred(t, 0xC1, extMap), true)
	if err != nil {
		t.Fatalf("authData with valid extensions rejected: %v", err)
	}
	if string(pad.CredentialID) != "credential-id-01" {
		t.Fatalf("credentialId: got %q", pad.CredentialID)
	}

	// Extensions flag with trailing garbage after the extensions map.
	_, err = parseAuthenticatorData(testAuthDataWithCred(t, 0xC1, append(extMap, 0x00)), true)
	if !errors.Is(err, ErrAuthDataTrailingBytes) {
		t.Fatalf("expected ErrAuthDataTrailingBytes, got %v", err)
	}

	// Extensions flag with no extensions bytes at all.
	_, err = parseAuthenticatorData(testAuthDataWithCred(t, 0xC1, nil), true)
	if err == nil {
		t.Fatal("expected error for missing extensions bytes")
	}
}

// --- packed x5c leaf validity (verifyPackedFullAttestation) ---

// testPackedFullStmt builds a packed full-attestation statement signed by a
// dedicated attestation key. sameKey controls whether the leaf certificate
// binds the credential key itself (malformed self-with-x5c) or a distinct
// attestation key (genuine full attestation).
func testPackedFullStmt(t *testing.T, notBefore, notAfter time.Time, sameKey bool) (*attestationStatement, []byte, []byte, []byte) {
	t.Helper()
	attKey := testMustECKey(t)
	credKey := testMustECKey(t)
	if sameKey {
		credKey = attKey
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test Validity"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der := testSelfSignedCertWithTemplate(t, template, &attKey.PublicKey, attKey)
	authData := testFakeAuthData()
	clientData := testClientDataJSON()
	clientDataHash := sha256.Sum256(clientData)
	verifyData := append(append([]byte{}, authData...), clientDataHash[:]...)
	hash := sha256.Sum256(verifyData)
	sig := testSignASN1(t, attKey, hash[:])
	credCOSE := testCoseES256(t, testPad32(credKey.PublicKey.X.Bytes()), testPad32(credKey.PublicKey.Y.Bytes()))
	return &attestationStatement{Alg: AlgES256, Sig: sig, X5C: [][]byte{der}}, authData, clientData, credCOSE
}

func testSelfSignedCertWithTemplate(t *testing.T, template *x509.Certificate, pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("creating test certificate: %v", err)
	}
	return der
}

func TestVerifyPackedFullAttestationValidity(t *testing.T) {
	now := time.Now()

	stmt, authData, clientData, credCOSE := testPackedFullStmt(t, now.Add(-time.Hour), now.Add(time.Hour), false)
	if err := verifyPackedFullAttestation(stmt, authData, clientData, credCOSE); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}

	stmt, authData, clientData, credCOSE = testPackedFullStmt(t, now.Add(-48*time.Hour), now.Add(-time.Hour), false)
	err := verifyPackedFullAttestation(stmt, authData, clientData, credCOSE)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}

	stmt, authData, clientData, credCOSE = testPackedFullStmt(t, now.Add(time.Hour), now.Add(48*time.Hour), false)
	err = verifyPackedFullAttestation(stmt, authData, clientData, credCOSE)
	if err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("expected not-yet-valid error, got %v", err)
	}
}

// TestVerifyPackedFullAttestationSelfWithX5C is the FIDO F-2 case: a "full"
// attestation whose leaf certificate binds the credential key itself (self
// attestation carrying x5c) must be rejected even though the signature
// verifies with x5c[0].
func TestVerifyPackedFullAttestationSelfWithX5C(t *testing.T) {
	now := time.Now()
	stmt, authData, clientData, credCOSE := testPackedFullStmt(t, now.Add(-time.Hour), now.Add(time.Hour), true)
	err := verifyPackedFullAttestation(stmt, authData, clientData, credCOSE)
	if err == nil {
		t.Fatal("expected rejection of self attestation carrying x5c")
	}
	if !errors.Is(err, ErrInvalidAttestationStatement) {
		t.Fatalf("expected errors.Is(ErrInvalidAttestationStatement), got %v", err)
	}
}
