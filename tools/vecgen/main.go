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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"

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

	for _, pair := range []struct {
		name string
		data VectorFile
	}{
		{"registration.json", regVectors},
		{"authentication.json", authVectors},
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
