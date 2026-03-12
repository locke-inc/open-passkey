// vecgen generates WebAuthn test vectors for the open-passkey spec/ directory.
//
// It uses Go's standard crypto libraries to create a software authenticator
// that produces real, valid WebAuthn registration and authentication payloads.
// These vectors are then serialized as JSON so every language implementation
// can import and test against them.
//
// Usage: go run main.go -out ../../spec/vectors
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/fxamacker/cbor/v2"
)

// --- Base64url helpers (no padding, URL-safe) ---

func b64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64Decode(s string) []byte {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		log.Fatalf("b64Decode failed: %v", err)
	}
	return data
}

// --- COSE key encoding ---

// coseEC2PublicKey encodes an ECDSA P-256 public key in COSE_Key format (RFC 8152).
func coseEC2PublicKey(pub *ecdsa.PublicKey) []byte {
	// COSE_Key map: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
	// kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256)
	key := map[int]interface{}{
		1:  2,                               // kty: EC2
		3:  -7,                              // alg: ES256
		-1: 1,                               // crv: P-256
		-2: pub.X.FillBytes(make([]byte, 32)), // x coordinate
		-3: pub.Y.FillBytes(make([]byte, 32)), // y coordinate
	}
	data, err := cbor.Marshal(key)
	if err != nil {
		log.Fatalf("coseEC2PublicKey marshal failed: %v", err)
	}
	return data
}

// --- Software authenticator ---

type softAuthenticator struct {
	credentialID  []byte
	privateKey    *ecdsa.PrivateKey
	publicKeyCOSE []byte // cached COSE encoding — computed once for determinism
	signCount     uint32
}

func newSoftAuthenticator() *softAuthenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("key generation failed: %v", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		log.Fatalf("credID generation failed: %v", err)
	}
	return &softAuthenticator{
		credentialID:  credID,
		privateKey:    key,
		publicKeyCOSE: coseEC2PublicKey(&key.PublicKey),
		signCount:     0,
	}
}

// makeAuthenticatorData builds the authenticator data blob per WebAuthn spec.
// Flags: 0x01 = UP (user present), 0x04 = UV (user verified), 0x40 = AT (attested credential data)
func (a *softAuthenticator) makeAuthenticatorData(rpID string, flags byte, includeCredData bool) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 256)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, flags)

	// Sign counter (4 bytes big-endian)
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, a.signCount)
	buf = append(buf, counterBytes...)

	if includeCredData {
		// AAGUID (16 bytes of zeros for "none" attestation)
		buf = append(buf, make([]byte, 16)...)
		// Credential ID length (2 bytes big-endian)
		credIDLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credIDLen, uint16(len(a.credentialID)))
		buf = append(buf, credIDLen...)
		// Credential ID
		buf = append(buf, a.credentialID...)
		// COSE public key (use cached encoding for determinism)
		buf = append(buf, a.publicKeyCOSE...)
	}

	return buf
}

// sign produces an ECDSA signature over authenticatorData || sha256(clientDataJSON)
// and returns it in ASN.1 DER format.
func (a *softAuthenticator) sign(authData, clientDataJSON []byte) []byte {
	clientDataHash := sha256.Sum256(clientDataJSON)
	sigInput := append(authData, clientDataHash[:]...)
	hash := sha256.Sum256(sigInput)

	r, s, err := ecdsa.Sign(rand.Reader, a.privateKey, hash[:])
	if err != nil {
		log.Fatalf("signing failed: %v", err)
	}

	// Encode as DER
	return marshalDER(r, s)
}

// marshalDER produces a minimal ASN.1 DER encoding of an ECDSA signature.
func marshalDER(r, s *big.Int) []byte {
	rBytes := intToDER(r)
	sBytes := intToDER(s)

	seq := []byte{0x30, byte(len(rBytes) + len(sBytes))}
	seq = append(seq, rBytes...)
	seq = append(seq, sBytes...)
	return seq
}

func intToDER(i *big.Int) []byte {
	b := i.Bytes()
	// Pad with 0x00 if high bit is set (DER requires unsigned integers)
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	return append([]byte{0x02, byte(len(b))}, b...)
}

// --- Client data construction ---

func makeClientDataJSON(typ, challenge, origin string) []byte {
	cd := map[string]string{
		"type":      typ,
		"challenge": challenge,
		"origin":    origin,
	}
	data, err := json.Marshal(cd)
	if err != nil {
		log.Fatalf("clientDataJSON marshal failed: %v", err)
	}
	return data
}

func makeClientDataJSONWithTokenBinding(typ, challenge, origin string, tokenBinding map[string]string) []byte {
	cd := map[string]any{
		"type":         typ,
		"challenge":    challenge,
		"origin":       origin,
		"tokenBinding": tokenBinding,
	}
	data, err := json.Marshal(cd)
	if err != nil {
		log.Fatalf("clientDataJSON marshal failed: %v", err)
	}
	return data
}

// --- Attestation object (none format) ---

func makeAttestationObject(authData []byte) []byte {
	obj := map[string]interface{}{
		"fmt":      "none",
		"attStmt":  map[string]interface{}{},
		"authData": authData,
	}
	data, err := cbor.Marshal(obj)
	if err != nil {
		log.Fatalf("attestationObject marshal failed: %v", err)
	}
	return data
}

func makeAttestationObjectWithFmt(authData []byte, fmt string) []byte {
	obj := map[string]interface{}{
		"fmt":      fmt,
		"attStmt":  map[string]interface{}{},
		"authData": authData,
	}
	data, err := cbor.Marshal(obj)
	if err != nil {
		log.Fatalf("attestationObject marshal failed: %v", err)
	}
	return data
}

// makePackedSelfAttestationObject creates a packed attestation object with self-attestation.
// The signature is over authData || SHA256(clientDataJSON), signed by the authenticator's key.
func (a *softAuthenticator) makePackedSelfAttestationObject(authData, clientDataJSON []byte) []byte {
	clientDataHash := sha256.Sum256(clientDataJSON)
	sigInput := append(authData, clientDataHash[:]...)
	hash := sha256.Sum256(sigInput)

	r, s, err := ecdsa.Sign(rand.Reader, a.privateKey, hash[:])
	if err != nil {
		log.Fatalf("packed self-attestation signing failed: %v", err)
	}
	sig := marshalDER(r, s)

	obj := map[string]interface{}{
		"fmt": "packed",
		"attStmt": map[string]interface{}{
			"alg": -7, // ES256
			"sig": sig,
		},
		"authData": authData,
	}
	data, err := cbor.Marshal(obj)
	if err != nil {
		log.Fatalf("packed attestationObject marshal failed: %v", err)
	}
	return data
}

// makePackedFullAttestationObject creates a packed attestation object with x5c (full attestation).
// Uses a self-signed certificate containing the authenticator's public key.
func (a *softAuthenticator) makePackedFullAttestationObject(authData, clientDataJSON []byte) ([]byte, []byte) {
	// Create a self-signed certificate for the authenticator key
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Attestation"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &a.privateKey.PublicKey, a.privateKey)
	if err != nil {
		log.Fatalf("creating attestation certificate: %v", err)
	}

	clientDataHash := sha256.Sum256(clientDataJSON)
	sigInput := append(authData, clientDataHash[:]...)
	hash := sha256.Sum256(sigInput)

	r, s, err := ecdsa.Sign(rand.Reader, a.privateKey, hash[:])
	if err != nil {
		log.Fatalf("packed full attestation signing failed: %v", err)
	}
	sig := marshalDER(r, s)

	obj := map[string]interface{}{
		"fmt": "packed",
		"attStmt": map[string]interface{}{
			"alg": -7, // ES256
			"sig": sig,
			"x5c": [][]byte{certDER},
		},
		"authData": authData,
	}
	data, err := cbor.Marshal(obj)
	if err != nil {
		log.Fatalf("packed full attestationObject marshal failed: %v", err)
	}
	return data, certDER
}

// makePackedSelfAttestationObjectBadSig creates a packed self-attestation with a tampered signature.
func (a *softAuthenticator) makePackedSelfAttestationObjectBadSig(authData, clientDataJSON []byte) []byte {
	clientDataHash := sha256.Sum256(clientDataJSON)
	sigInput := append(authData, clientDataHash[:]...)
	hash := sha256.Sum256(sigInput)

	r, s, err := ecdsa.Sign(rand.Reader, a.privateKey, hash[:])
	if err != nil {
		log.Fatalf("packed self-attestation signing failed: %v", err)
	}
	sig := marshalDER(r, s)
	// Tamper with the signature
	sig[len(sig)-1] ^= 0xFF

	obj := map[string]interface{}{
		"fmt": "packed",
		"attStmt": map[string]interface{}{
			"alg": -7,
			"sig": sig,
		},
		"authData": authData,
	}
	data, err := cbor.Marshal(obj)
	if err != nil {
		log.Fatalf("packed attestationObject marshal failed: %v", err)
	}
	return data
}

// --- Composite ML-DSA-65-ES256 (hybrid PQ) ---
//
// Per draft-ietf-jose-pq-composite-sigs, the composite algorithm ML-DSA-65-ES256
// uses COSE alg -52. The composite public key concatenates the component keys
// (ML-DSA-65 || ES256) and the composite signature concatenates the component
// signatures (ML-DSA-65 || ES256). Both signatures must verify independently.

const (
	algCompositeMLDSA65ES256 = -52 // COSE alg for ML-DSA-65-ES256 composite
	ktyComposite             = 9   // COSE kty for composite keys
)

// coseCompositePublicKey encodes a composite ML-DSA-65-ES256 public key in COSE_Key format.
// The composite public key stores concatenated raw keys in COSE parameter -1.
// Format: ML-DSA-65 public key (1952 bytes) || ECDSA P-256 uncompressed point (65 bytes)
func coseCompositePublicKey(mldsaPub *mldsa65.PublicKey, ecdsaPub *ecdsa.PublicKey) []byte {
	mldsaPubBytes, err := mldsaPub.MarshalBinary()
	if err != nil {
		log.Fatalf("ML-DSA-65 public key marshal failed: %v", err)
	}

	// Uncompressed EC point: 0x04 || x(32) || y(32)
	ecdsaPubBytes := make([]byte, 65)
	ecdsaPubBytes[0] = 0x04
	copy(ecdsaPubBytes[1:33], ecdsaPub.X.FillBytes(make([]byte, 32)))
	copy(ecdsaPubBytes[33:65], ecdsaPub.Y.FillBytes(make([]byte, 32)))

	compositeKey := append(mldsaPubBytes, ecdsaPubBytes...)

	key := map[int]interface{}{
		1:  ktyComposite,             // kty: Composite
		3:  algCompositeMLDSA65ES256, // alg: ML-DSA-65-ES256
		-1: compositeKey,             // composite public key bytes
	}
	data, err := cbor.Marshal(key)
	if err != nil {
		log.Fatalf("coseCompositePublicKey marshal failed: %v", err)
	}
	return data
}

// hybridAuthenticator is a software authenticator that produces composite
// ML-DSA-65-ES256 credentials (dual-signed with both algorithms).
type hybridAuthenticator struct {
	credentialID  []byte
	mldsaPriv     *mldsa65.PrivateKey
	mldsaPub      *mldsa65.PublicKey
	ecdsaPriv     *ecdsa.PrivateKey
	publicKeyCOSE []byte // cached composite COSE key
	signCount     uint32
}

func newHybridAuthenticator() *hybridAuthenticator {
	// Generate ML-DSA-65 key pair
	mldsaPub, mldsaPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("ML-DSA-65 key generation failed: %v", err)
	}

	// Generate ECDSA P-256 key pair
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("ECDSA key generation failed: %v", err)
	}

	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		log.Fatalf("credID generation failed: %v", err)
	}

	return &hybridAuthenticator{
		credentialID:  credID,
		mldsaPriv:     mldsaPriv,
		mldsaPub:      mldsaPub,
		ecdsaPriv:     ecdsaPriv,
		publicKeyCOSE: coseCompositePublicKey(mldsaPub, &ecdsaPriv.PublicKey),
		signCount:     0,
	}
}

// makeAuthenticatorData builds authenticator data identical to the ES256 authenticator.
func (h *hybridAuthenticator) makeAuthenticatorData(rpID string, flags byte, includeCredData bool) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 4096) // larger buffer for composite key
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, flags)

	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, h.signCount)
	buf = append(buf, counterBytes...)

	if includeCredData {
		buf = append(buf, make([]byte, 16)...) // AAGUID
		credIDLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credIDLen, uint16(len(h.credentialID)))
		buf = append(buf, credIDLen...)
		buf = append(buf, h.credentialID...)
		buf = append(buf, h.publicKeyCOSE...)
	}

	return buf
}

// sign produces a composite signature: ML-DSA-65 signature || ES256 DER signature.
// Per the draft, both component signatures are computed over the same verification data:
// authData || SHA256(clientDataJSON).
func (h *hybridAuthenticator) sign(authData, clientDataJSON []byte) []byte {
	clientDataHash := sha256.Sum256(clientDataJSON)
	verifyData := append(authData, clientDataHash[:]...)

	// ML-DSA-65: signs the message directly (no pre-hashing)
	mldsaSig, err := h.mldsaPriv.Sign(rand.Reader, verifyData, nil)
	if err != nil {
		log.Fatalf("ML-DSA-65 signing failed: %v", err)
	}

	// ES256: ECDSA signs SHA-256(verifyData)
	ecdsaHash := sha256.Sum256(verifyData)
	r, s, err := ecdsa.Sign(rand.Reader, h.ecdsaPriv, ecdsaHash[:])
	if err != nil {
		log.Fatalf("ECDSA signing failed: %v", err)
	}
	ecdsaSig := marshalDER(r, s)

	// Composite signature: 4-byte big-endian length of ML-DSA sig, then ML-DSA sig, then ES256 sig
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(mldsaSig)))
	composite := append(lenBytes, mldsaSig...)
	composite = append(composite, ecdsaSig...)

	return composite
}

// --- Test vector types (matching the JSON schema) ---

type TestVector struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Input       map[string]any `json:"input"`
	Expected    Expected       `json:"expected"`
}

type Expected struct {
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
	CredentialID string `json:"credentialId,omitempty"`
	PublicKeyCOSE string `json:"publicKeyCose,omitempty"`
	SignCount    *uint32 `json:"signCount,omitempty"`
	RPIDHash     string `json:"rpIdHash,omitempty"`
}

type VectorFile struct {
	Description string       `json:"description"`
	Vectors     []TestVector `json:"vectors"`
}

// --- Registration vector generation ---

func generateRegistrationVectors() VectorFile {
	rpID := "example.com"
	origin := "https://example.com"
	challenge := b64Encode([]byte("registration-challenge-0123456789"))

	auth := newSoftAuthenticator()

	vectors := VectorFile{
		Description: "WebAuthn registration (navigator.credentials.create) verification test vectors",
		Vectors:     []TestVector{},
	}

	// --- Happy path ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin)
		flags := byte(0x01 | 0x04 | 0x40) // UP + UV + AT
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := makeAttestationObject(authData)

		rpIDHash := sha256.Sum256([]byte(rpID))
		signCount := uint32(0)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "valid_registration_none_attestation",
			Description: "A valid registration ceremony with 'none' attestation, ES256 credential.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success:      true,
				CredentialID: b64Encode(auth.credentialID),
				PublicKeyCOSE: b64Encode(auth.publicKeyCOSE),
				SignCount:    &signCount,
				RPIDHash:     b64Encode(rpIDHash[:]),
			},
		})
	}

	// --- Wrong RP ID ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin)
		flags := byte(0x01 | 0x04 | 0x40)
		authData := auth.makeAuthenticatorData(rpID, flags, true) // authenticator signed for "example.com"
		attestationObject := makeAttestationObject(authData)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_rp_id_mismatch",
			Description: "Registration where the relying party passes a different rpId than what the authenticator signed.",
			Input: map[string]any{
				"rpId":              "evil.com", // mismatch!
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "rp_id_mismatch",
			},
		})
	}

	// --- Wrong challenge ---
	{
		wrongChallenge := b64Encode([]byte("wrong-challenge-value"))
		clientDataJSON := makeClientDataJSON("webauthn.create", wrongChallenge, origin) // client sent wrong challenge
		flags := byte(0x01 | 0x04 | 0x40)
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := makeAttestationObject(authData)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_challenge_mismatch",
			Description: "Registration where the challenge in clientDataJSON does not match the expected challenge.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge, // server expected this
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "challenge_mismatch",
			},
		})
	}

	// --- Wrong origin ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, "https://phishing.com")
		flags := byte(0x01 | 0x04 | 0x40)
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := makeAttestationObject(authData)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_origin_mismatch",
			Description: "Registration where the origin in clientDataJSON does not match the expected origin.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "origin_mismatch",
			},
		})
	}

	// --- Wrong type in clientDataJSON ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin) // should be "webauthn.create"
		flags := byte(0x01 | 0x04 | 0x40)
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := makeAttestationObject(authData)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_type_not_create",
			Description: "Registration where clientDataJSON type is 'webauthn.get' instead of 'webauthn.create'.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "type_mismatch",
			},
		})
	}

	// --- UP flag missing ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin)
		flags := byte(0x40) // AT set, UP cleared
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := makeAttestationObject(authData)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "registration_up_missing",
			Description: "Registration where the User Present (UP) flag is not set in authenticator data.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "user_presence_required",
			},
		})
	}

	// --- UV flag missing (should still pass — UV not required by default) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin)
		flags := byte(0x01 | 0x40) // UP + AT, UV cleared
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := makeAttestationObject(authData)

		rpIDHash := sha256.Sum256([]byte(rpID))
		signCount := uint32(0)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "registration_uv_missing",
			Description: "Registration where the User Verified (UV) flag is not set. Should pass since UV is not required by default.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success:      true,
				CredentialID: b64Encode(auth.credentialID),
				PublicKeyCOSE: b64Encode(auth.publicKeyCOSE),
				SignCount:    &signCount,
				RPIDHash:     b64Encode(rpIDHash[:]),
			},
		})
	}

	// --- Packed attestation with empty attStmt (invalid) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin)
		flags := byte(0x01 | 0x04 | 0x40)
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := makeAttestationObjectWithFmt(authData, "packed")

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "registration_packed_attestation_empty_stmt",
			Description: "Registration with fmt 'packed' but empty attStmt (missing alg and sig).",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "invalid_attestation_statement",
			},
		})
	}

	// --- Packed self-attestation (valid) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin)
		flags := byte(0x01 | 0x04 | 0x40)
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := auth.makePackedSelfAttestationObject(authData, clientDataJSON)

		rpIDHash := sha256.Sum256([]byte(rpID))
		signCount := uint32(0)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "registration_packed_self_attestation",
			Description: "A valid registration with packed self-attestation (no x5c). Signature verified against credential public key.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success:       true,
				CredentialID:  b64Encode(auth.credentialID),
				PublicKeyCOSE: b64Encode(auth.publicKeyCOSE),
				SignCount:     &signCount,
				RPIDHash:      b64Encode(rpIDHash[:]),
			},
		})
	}

	// --- Packed self-attestation with bad signature ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin)
		flags := byte(0x01 | 0x04 | 0x40)
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := auth.makePackedSelfAttestationObjectBadSig(authData, clientDataJSON)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "registration_packed_self_attestation_bad_sig",
			Description: "Registration with packed self-attestation where the signature is tampered.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "signature_invalid",
			},
		})
	}

	// --- Packed full attestation with x5c (valid) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin)
		flags := byte(0x01 | 0x04 | 0x40)
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject, _ := auth.makePackedFullAttestationObject(authData, clientDataJSON)

		rpIDHash := sha256.Sum256([]byte(rpID))
		signCount := uint32(0)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "registration_packed_full_attestation",
			Description: "A valid registration with packed full attestation (x5c present). Signature verified against x5c[0] certificate.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success:       true,
				CredentialID:  b64Encode(auth.credentialID),
				PublicKeyCOSE: b64Encode(auth.publicKeyCOSE),
				SignCount:     &signCount,
				RPIDHash:      b64Encode(rpIDHash[:]),
			},
		})
	}

	// --- Backup state without backup eligible (invalid per §6.3.3) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin)
		flags := byte(0x01 | 0x10 | 0x40) // UP + BS + AT (BE=0, BS=1 is invalid)
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := makeAttestationObject(authData)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "registration_backup_state_without_eligible",
			Description: "Registration where BS=1 but BE=0, which is invalid per spec §6.3.3.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "invalid_backup_state",
			},
		})
	}

	// --- Token binding present (unsupported) ---
	{
		clientDataJSON := makeClientDataJSONWithTokenBinding("webauthn.create", challenge, origin, map[string]string{
			"status": "present",
			"id":     "dGVzdC1iaW5kaW5nLWlk",
		})
		flags := byte(0x01 | 0x04 | 0x40)
		authData := auth.makeAuthenticatorData(rpID, flags, true)
		attestationObject := makeAttestationObject(authData)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "registration_token_binding_present",
			Description: "Registration where clientDataJSON includes tokenBinding with status 'present', which we cannot verify.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"attestationObject": b64Encode(attestationObject),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "token_binding_unsupported",
			},
		})
	}

	return vectors
}

// --- Authentication vector generation ---

func generateAuthenticationVectors() VectorFile {
	rpID := "example.com"
	origin := "https://example.com"
	challenge := b64Encode([]byte("authentication-challenge-0123456"))

	auth := newSoftAuthenticator()
	auth.signCount = 1 // simulate a previously-used credential

	vectors := VectorFile{
		Description: "WebAuthn authentication (navigator.credentials.get) verification test vectors",
		Vectors:     []TestVector{},
	}

	// Store the public key for verification by the test consumer
	storedPublicKey := b64Encode(auth.publicKeyCOSE)

	// --- Happy path ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x04) // UP + UV (no AT flag for authentication)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		signCount := auth.signCount

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "valid_authentication",
			Description: "A valid authentication ceremony with ES256 signature.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":   0, // previous sign count on server
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success:   true,
				SignCount: &signCount,
			},
		})
	}

	// --- Wrong RP ID ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x04)
		authData := auth.makeAuthenticatorData(rpID, flags, false) // signed for "example.com"
		signature := auth.sign(authData, clientDataJSON)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_rp_id_mismatch",
			Description: "Authentication where the relying party passes a different rpId than what the authenticator signed.",
			Input: map[string]any{
				"rpId":              "evil.com", // mismatch!
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":   0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "rp_id_mismatch",
			},
		})
	}

	// --- Wrong challenge ---
	{
		wrongChallenge := b64Encode([]byte("wrong-challenge-value"))
		clientDataJSON := makeClientDataJSON("webauthn.get", wrongChallenge, origin)
		flags := byte(0x01 | 0x04)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_challenge_mismatch",
			Description: "Authentication where the challenge in clientDataJSON does not match the expected challenge.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":   0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "challenge_mismatch",
			},
		})
	}

	// --- Invalid signature (tampered) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x04)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		// Tamper with the signature by flipping bits in the last byte
		tamperedSig := make([]byte, len(signature))
		copy(tamperedSig, signature)
		tamperedSig[len(tamperedSig)-1] ^= 0xFF

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_signature_tampered",
			Description: "Authentication with a valid structure but a tampered/invalid signature.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":   0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(tamperedSig),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "signature_invalid",
			},
		})
	}

	// --- Wrong type in clientDataJSON ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin) // should be "webauthn.get"
		flags := byte(0x01 | 0x04)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_type_not_get",
			Description: "Authentication where clientDataJSON type is 'webauthn.create' instead of 'webauthn.get'.",
			Input: map[string]any{
				"rpId":              rpID,
				"expectedChallenge": challenge,
				"expectedOrigin":    origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":   0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "type_mismatch",
			},
		})
	}

	// --- UP flag missing ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x00) // UP cleared
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "authentication_up_missing",
			Description: "Authentication where the User Present (UP) flag is not set in authenticator data.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "user_presence_required",
			},
		})
	}

	// --- UV flag missing (should still pass — UV not required by default) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01) // UP set, UV cleared
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		signCount := auth.signCount

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "authentication_uv_missing",
			Description: "Authentication where the User Verified (UV) flag is not set. Should pass since UV is not required by default.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success:   true,
				SignCount: &signCount,
			},
		})
	}

	// --- Sign count both zero (should pass per spec) ---
	{
		auth2 := newSoftAuthenticator()
		auth2.signCount = 0
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x04) // UP + UV
		authData := auth2.makeAuthenticatorData(rpID, flags, false)
		signature := auth2.sign(authData, clientDataJSON)

		signCount := uint32(0)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "authentication_sign_count_zero_zero",
			Description: "Authentication where both stored and reported sign counts are zero. Per spec, this is fine (authenticators that don't increment).",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": b64Encode(auth2.publicKeyCOSE),
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth2.credentialID),
					"rawId": b64Encode(auth2.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success:   true,
				SignCount: &signCount,
			},
		})
	}

	// --- Sign count rollback ---
	{
		auth3 := newSoftAuthenticator()
		auth3.signCount = 3 // authenticator reports 3
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x04)
		authData := auth3.makeAuthenticatorData(rpID, flags, false)
		signature := auth3.sign(authData, clientDataJSON)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "authentication_sign_count_rollback",
			Description: "Authentication where stored sign count (5) is greater than reported sign count (3), indicating a possible cloned authenticator.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": b64Encode(auth3.publicKeyCOSE),
				"storedSignCount":     5, // stored is 5, reported is 3
				"credential": map[string]any{
					"id":    b64Encode(auth3.credentialID),
					"rawId": b64Encode(auth3.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "sign_count_rollback",
			},
		})
	}

	// --- Backup eligible flag set (should pass) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x08) // UP + BE
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		signCount := auth.signCount

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "authentication_backup_eligible",
			Description: "Authentication where BE flag (bit 3) is set. Should pass and report backupEligible: true.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success:   true,
				SignCount: &signCount,
			},
		})
	}

	// --- Backup state without eligible (invalid) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x10) // UP + BS (BE=0, BS=1 is invalid)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "authentication_backup_state_without_eligible",
			Description: "Authentication where BS=1 but BE=0, which is invalid per spec §6.3.3.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "invalid_backup_state",
			},
		})
	}

	// --- Token binding "supported" (should pass) ---
	{
		clientDataJSON := makeClientDataJSONWithTokenBinding("webauthn.get", challenge, origin, map[string]string{
			"status": "supported",
		})
		flags := byte(0x01 | 0x04)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		signCount := auth.signCount

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "authentication_token_binding_supported",
			Description: "Authentication where clientDataJSON includes tokenBinding with status 'supported'. This is fine — only 'present' is rejected.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success:   true,
				SignCount: &signCount,
			},
		})
	}

	return vectors
}

// --- Hybrid ML-DSA-65-ES256 authentication vector generation ---

func generateHybridAuthenticationVectors() VectorFile {
	rpID := "example.com"
	origin := "https://example.com"
	challenge := b64Encode([]byte("hybrid-auth-challenge-01234567890"))

	auth := newHybridAuthenticator()
	auth.signCount = 1

	vectors := VectorFile{
		Description: "WebAuthn authentication test vectors for ML-DSA-65-ES256 composite (hybrid PQ) signatures (COSE alg -52)",
		Vectors:     []TestVector{},
	}

	storedPublicKey := b64Encode(auth.publicKeyCOSE)

	// --- Happy path: valid composite signature ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x04) // UP + UV
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		signCount := auth.signCount

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "valid_hybrid_authentication",
			Description: "A valid authentication ceremony with ML-DSA-65-ES256 composite signature (COSE alg -52). Both PQ and classical components verify.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success:   true,
				SignCount: &signCount,
			},
		})
	}

	// --- Wrong RP ID ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x04)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_hybrid_rp_id_mismatch",
			Description: "Hybrid authentication where the relying party passes a different rpId than what the authenticator signed.",
			Input: map[string]any{
				"rpId":                "evil.com",
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "rp_id_mismatch",
			},
		})
	}

	// --- Wrong challenge ---
	{
		wrongChallenge := b64Encode([]byte("wrong-challenge-value"))
		clientDataJSON := makeClientDataJSON("webauthn.get", wrongChallenge, origin)
		flags := byte(0x01 | 0x04)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_hybrid_challenge_mismatch",
			Description: "Hybrid authentication where the challenge in clientDataJSON does not match the expected challenge.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "challenge_mismatch",
			},
		})
	}

	// --- Tampered composite signature (flip bits in ML-DSA component) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x04)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		// Tamper with the ML-DSA portion (byte 10 inside the ML-DSA sig, after the 4-byte length prefix)
		tamperedSig := make([]byte, len(signature))
		copy(tamperedSig, signature)
		tamperedSig[10] ^= 0xFF

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_hybrid_signature_tampered_mldsa",
			Description: "Hybrid authentication with a tampered ML-DSA-65 component. The ES256 component is valid but the PQ component is corrupted.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(tamperedSig),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "signature_invalid",
			},
		})
	}

	// --- Tampered composite signature (flip bits in ES256 component) ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.get", challenge, origin)
		flags := byte(0x01 | 0x04)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		// Tamper with the ES256 portion (last byte of the composite signature)
		tamperedSig := make([]byte, len(signature))
		copy(tamperedSig, signature)
		tamperedSig[len(tamperedSig)-1] ^= 0xFF

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_hybrid_signature_tampered_ecdsa",
			Description: "Hybrid authentication with a tampered ES256 component. The ML-DSA-65 component is valid but the classical component is corrupted.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(tamperedSig),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "signature_invalid",
			},
		})
	}

	// --- Wrong type in clientDataJSON ---
	{
		clientDataJSON := makeClientDataJSON("webauthn.create", challenge, origin) // wrong type
		flags := byte(0x01 | 0x04)
		authData := auth.makeAuthenticatorData(rpID, flags, false)
		signature := auth.sign(authData, clientDataJSON)

		vectors.Vectors = append(vectors.Vectors, TestVector{
			Name:        "invalid_hybrid_type_not_get",
			Description: "Hybrid authentication where clientDataJSON type is 'webauthn.create' instead of 'webauthn.get'.",
			Input: map[string]any{
				"rpId":                rpID,
				"expectedChallenge":   challenge,
				"expectedOrigin":      origin,
				"storedPublicKeyCose": storedPublicKey,
				"storedSignCount":     0,
				"credential": map[string]any{
					"id":    b64Encode(auth.credentialID),
					"rawId": b64Encode(auth.credentialID),
					"type":  "public-key",
					"response": map[string]any{
						"clientDataJSON":    b64Encode(clientDataJSON),
						"authenticatorData": b64Encode(authData),
						"signature":         b64Encode(signature),
					},
				},
			},
			Expected: Expected{
				Success: false,
				Error:   "type_mismatch",
			},
		})
	}

	return vectors
}

func main() {
	outDir := flag.String("out", "../../spec/vectors", "Output directory for test vector JSON files")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	regVectors := generateRegistrationVectors()
	authVectors := generateAuthenticationVectors()
	hybridVectors := generateHybridAuthenticationVectors()

	for _, pair := range []struct {
		name string
		data VectorFile
	}{
		{"registration.json", regVectors},
		{"authentication.json", authVectors},
		{"hybrid_authentication.json", hybridVectors},
	} {
		path := filepath.Join(*outDir, pair.name)
		content, err := json.MarshalIndent(pair.data, "", "  ")
		if err != nil {
			log.Fatalf("failed to marshal %s: %v", pair.name, err)
		}
		if err := os.WriteFile(path, content, 0644); err != nil {
			log.Fatalf("failed to write %s: %v", path, err)
		}
		fmt.Printf("wrote %s (%d vectors)\n", path, len(pair.data.Vectors))
	}
}
