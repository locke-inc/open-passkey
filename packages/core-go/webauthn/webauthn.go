// Package webauthn implements the core WebAuthn/FIDO2 protocol logic for
// verifying registration and authentication ceremonies.
//
// This is the "Core Protocol" layer — it contains no HTTP handling, no
// framework bindings, and no session management. It operates purely on
// parsed WebAuthn structures and returns verification results.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// Sentinel errors returned by verification functions.
// Error names match the "error" field in spec/vectors/ JSON.
var (
	ErrTypeMismatch      = errors.New("type_mismatch")
	ErrChallengeMismatch = errors.New("challenge_mismatch")
	ErrOriginMismatch    = errors.New("origin_mismatch")
	ErrRPIDMismatch      = errors.New("rp_id_mismatch")
	ErrSignatureInvalid  = errors.New("signature_invalid")
	ErrAuthDataTooShort  = errors.New("authenticator_data_too_short")
	ErrNoCredentialData  = errors.New("no_attested_credential_data")
	ErrUnsupportedAlg    = errors.New("unsupported_cose_algorithm")
)

// --- Public input/output types ---

type RegistrationInput struct {
	RPID              string
	ExpectedChallenge string // base64url-encoded
	ExpectedOrigin    string
	ClientDataJSON    string // base64url-encoded
	AttestationObject string // base64url-encoded
}

type RegistrationResult struct {
	CredentialID []byte
	PublicKeyCOSE []byte
	SignCount    uint32
	RPIDHash     []byte
}

type AuthenticationInput struct {
	RPID                string
	ExpectedChallenge   string // base64url-encoded
	ExpectedOrigin      string
	StoredPublicKeyCOSE []byte
	StoredSignCount     uint32
	ClientDataJSON      string // base64url-encoded
	AuthenticatorData   string // base64url-encoded
	Signature           string // base64url-encoded
}

type AuthenticationResult struct {
	SignCount uint32
}

// --- clientDataJSON parsing ---

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func verifyClientData(clientDataJSONB64, expectedType, expectedChallenge, expectedOrigin string) ([]byte, error) {
	raw, err := b64Decode(clientDataJSONB64)
	if err != nil {
		return nil, fmt.Errorf("decoding clientDataJSON: %w", err)
	}

	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, fmt.Errorf("parsing clientDataJSON: %w", err)
	}

	if cd.Type != expectedType {
		return nil, ErrTypeMismatch
	}
	if cd.Challenge != expectedChallenge {
		return nil, ErrChallengeMismatch
	}
	if cd.Origin != expectedOrigin {
		return nil, ErrOriginMismatch
	}

	return raw, nil
}

// --- Authenticator data parsing ---

// minAuthDataLen is rpIdHash(32) + flags(1) + signCount(4)
const minAuthDataLen = 37

type parsedAuthData struct {
	RPIDHash       []byte
	Flags          byte
	SignCount      uint32
	CredentialID   []byte
	CredentialKey  []byte // raw COSE key bytes
}

func parseAuthenticatorData(authData []byte, expectCredData bool) (*parsedAuthData, error) {
	if len(authData) < minAuthDataLen {
		return nil, ErrAuthDataTooShort
	}

	pad := &parsedAuthData{
		RPIDHash:  authData[:32],
		Flags:     authData[32],
		SignCount: binary.BigEndian.Uint32(authData[33:37]),
	}

	hasAttestedCredData := pad.Flags&0x40 != 0

	if expectCredData {
		if !hasAttestedCredData {
			return nil, ErrNoCredentialData
		}
		// Parse attested credential data starting at byte 37
		rest := authData[37:]
		// AAGUID: 16 bytes
		if len(rest) < 18 { // 16 (aaguid) + 2 (credID length)
			return nil, ErrAuthDataTooShort
		}
		credIDLen := binary.BigEndian.Uint16(rest[16:18])
		rest = rest[18:]
		if len(rest) < int(credIDLen) {
			return nil, ErrAuthDataTooShort
		}
		pad.CredentialID = rest[:credIDLen]
		pad.CredentialKey = rest[credIDLen:]
	}

	return pad, nil
}

func verifyRPIDHash(authDataRPIDHash []byte, rpID string) error {
	expected := sha256.Sum256([]byte(rpID))
	if len(authDataRPIDHash) != 32 {
		return ErrRPIDMismatch
	}
	for i := 0; i < 32; i++ {
		if authDataRPIDHash[i] != expected[i] {
			return ErrRPIDMismatch
		}
	}
	return nil
}

// --- Attestation object ---

type attestationObject struct {
	AuthData []byte `cbor:"authData"`
}

func decodeAttestationObject(attObjB64 string) ([]byte, error) {
	raw, err := b64Decode(attObjB64)
	if err != nil {
		return nil, fmt.Errorf("decoding attestationObject: %w", err)
	}
	var obj attestationObject
	if err := cbor.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("CBOR decoding attestationObject: %w", err)
	}
	return obj.AuthData, nil
}

// --- COSE key decoding (ES256 / P-256 only) ---

type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

func decodeCOSEPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	var key coseKey
	if err := cbor.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("CBOR decoding COSE key: %w", err)
	}
	// kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256)
	if key.Kty != 2 || key.Alg != -7 || key.Crv != 1 {
		return nil, ErrUnsupportedAlg
	}
	if len(key.X) != 32 || len(key.Y) != 32 {
		return nil, fmt.Errorf("invalid EC2 key coordinate length")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(key.X),
		Y:     new(big.Int).SetBytes(key.Y),
	}, nil
}

// --- Signature verification ---

func verifySignature(pubKey *ecdsa.PublicKey, authData, clientDataJSON []byte, signatureBytes []byte) error {
	clientDataHash := sha256.Sum256(clientDataJSON)
	verifyData := append(authData, clientDataHash[:]...)
	hash := sha256.Sum256(verifyData)

	if !ecdsa.VerifyASN1(pubKey, hash[:], signatureBytes) {
		return ErrSignatureInvalid
	}
	return nil
}

// --- Public API ---

func VerifyRegistration(input RegistrationInput) (*RegistrationResult, error) {
	_, err := verifyClientData(input.ClientDataJSON, "webauthn.create", input.ExpectedChallenge, input.ExpectedOrigin)
	if err != nil {
		return nil, err
	}

	authData, err := decodeAttestationObject(input.AttestationObject)
	if err != nil {
		return nil, err
	}

	pad, err := parseAuthenticatorData(authData, true)
	if err != nil {
		return nil, err
	}

	if err := verifyRPIDHash(pad.RPIDHash, input.RPID); err != nil {
		return nil, err
	}

	return &RegistrationResult{
		CredentialID:  pad.CredentialID,
		PublicKeyCOSE: pad.CredentialKey,
		SignCount:     pad.SignCount,
		RPIDHash:      pad.RPIDHash,
	}, nil
}

func VerifyAuthentication(input AuthenticationInput) (*AuthenticationResult, error) {
	clientDataJSONRaw, err := verifyClientData(input.ClientDataJSON, "webauthn.get", input.ExpectedChallenge, input.ExpectedOrigin)
	if err != nil {
		return nil, err
	}

	authDataRaw, err := b64Decode(input.AuthenticatorData)
	if err != nil {
		return nil, fmt.Errorf("decoding authenticatorData: %w", err)
	}

	pad, err := parseAuthenticatorData(authDataRaw, false)
	if err != nil {
		return nil, err
	}

	if err := verifyRPIDHash(pad.RPIDHash, input.RPID); err != nil {
		return nil, err
	}

	pubKey, err := decodeCOSEPublicKey(input.StoredPublicKeyCOSE)
	if err != nil {
		return nil, err
	}

	sigBytes, err := b64Decode(input.Signature)
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	if err := verifySignature(pubKey, authDataRaw, clientDataJSONRaw, sigBytes); err != nil {
		return nil, err
	}

	return &AuthenticationResult{
		SignCount: pad.SignCount,
	}, nil
}

// --- Helpers ---

func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
