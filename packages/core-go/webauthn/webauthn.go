// Package webauthn implements the core WebAuthn/FIDO2 protocol logic for
// verifying registration and authentication ceremonies.
//
// This is the "Core Protocol" layer — it contains no HTTP handling, no
// framework bindings, and no session management. It operates purely on
// parsed WebAuthn structures and returns verification results.
//
// Supported algorithms:
//   - ES256 (ECDSA P-256, COSE alg -7) — classical, widely supported
//   - ML-DSA-65 (FIPS 204 / Dilithium3, COSE alg -49) — post-quantum
//   - ML-DSA-65-ES256 (composite, COSE alg -52) — hybrid PQ, draft-ietf-jose-pq-composite-sigs
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/fxamacker/cbor/v2"
)

// cborDecMode rejects CBOR maps with duplicate keys (defense-in-depth).
var cborDecMode, _ = cbor.DecOptions{
	DupMapKey: cbor.DupMapKeyEnforcedAPF,
}.DecMode()

// COSE algorithm identifiers.
const (
	AlgES256              = -7  // ECDSA w/ SHA-256 on P-256
	AlgMLDSA65            = -49 // ML-DSA-65 (Dilithium3, FIPS 204)
	AlgCompositeMLDSA65ES256 = -52 // ML-DSA-65-ES256 composite (draft-ietf-jose-pq-composite-sigs)
)

// COSE key type identifiers.
const (
	KtyEC2       = 2 // Elliptic Curve (two coordinates)
	KtyMLDSA     = 8 // ML-DSA (Module-Lattice Digital Signature)
	KtyComposite = 9 // Composite key (draft-ietf-jose-pq-composite-sigs)
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
	ErrSignCountRollback            = errors.New("sign_count_rollback")
	ErrUserPresenceRequired         = errors.New("user_presence_required")
	ErrUserVerificationRequired     = errors.New("user_verification_required")
	ErrUnsupportedAttestationFormat = errors.New("unsupported_attestation_format")
	ErrTokenBindingUnsupported      = errors.New("token_binding_unsupported")
)

// --- Public input/output types ---

type RegistrationInput struct {
	RPID                    string
	ExpectedChallenge       string // base64url-encoded
	ExpectedOrigin          string
	ClientDataJSON          string // base64url-encoded
	AttestationObject       string // base64url-encoded
	RequireUserVerification bool   // If true, UV flag (bit 2) must be set. Default false.
}

type RegistrationResult struct {
	CredentialID  []byte
	PublicKeyCOSE []byte
	SignCount     uint32
	RPIDHash      []byte
	Flags         byte
}

type AuthenticationInput struct {
	RPID                    string
	ExpectedChallenge       string // base64url-encoded
	ExpectedOrigin          string
	StoredPublicKeyCOSE     []byte
	StoredSignCount         uint32
	ClientDataJSON          string // base64url-encoded
	AuthenticatorData       string // base64url-encoded
	Signature               string // base64url-encoded
	RequireUserVerification bool   // If true, UV flag (bit 2) must be set. Default false.
}

type AuthenticationResult struct {
	SignCount uint32
	Flags     byte
}

// --- clientDataJSON parsing ---

type tokenBindingData struct {
	Status string `json:"status"`
}

type clientData struct {
	Type         string            `json:"type"`
	Challenge    string            `json:"challenge"`
	Origin       string            `json:"origin"`
	TokenBinding *tokenBindingData `json:"tokenBinding,omitempty"`
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
	if cd.TokenBinding != nil && cd.TokenBinding.Status == "present" {
		return nil, ErrTokenBindingUnsupported
	}

	return raw, nil
}

// --- Authenticator data parsing ---

// minAuthDataLen is rpIdHash(32) + flags(1) + signCount(4)
const minAuthDataLen = 37

type parsedAuthData struct {
	RPIDHash      []byte
	Flags         byte
	SignCount     uint32
	CredentialID  []byte
	CredentialKey []byte // raw COSE key bytes
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
	if subtle.ConstantTimeCompare(authDataRPIDHash, expected[:]) != 1 {
		return ErrRPIDMismatch
	}
	return nil
}

// --- Attestation object ---

type attestationObject struct {
	Fmt      string `cbor:"fmt"`
	AuthData []byte `cbor:"authData"`
}

func decodeAttestationObject(attObjB64 string) ([]byte, error) {
	raw, err := b64Decode(attObjB64)
	if err != nil {
		return nil, fmt.Errorf("decoding attestationObject: %w", err)
	}
	var obj attestationObject
	if err := cborDecMode.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("CBOR decoding attestationObject: %w", err)
	}
	if obj.Fmt != "none" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAttestationFormat, obj.Fmt)
	}
	return obj.AuthData, nil
}

// --- COSE key decoding (multi-algorithm) ---

// coseKeyHeader is decoded first to determine the algorithm, then dispatched.
type coseKeyHeader struct {
	Kty int `cbor:"1,keyasint"`
	Alg int `cbor:"3,keyasint"`
}

// coseEC2Key holds the EC2-specific fields for ES256 / P-256.
type coseEC2Key struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// coseMLDSAKey holds the ML-DSA-specific fields.
// The public key is stored in COSE parameter -1 (analogous to crv for EC).
type coseMLDSAKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Pub []byte `cbor:"-1,keyasint"` // raw ML-DSA public key bytes
}

// identifyCOSEAlgorithm returns the COSE algorithm ID from a raw COSE key.
func identifyCOSEAlgorithm(data []byte) (int, error) {
	var header coseKeyHeader
	if err := cborDecMode.Unmarshal(data, &header); err != nil {
		return 0, fmt.Errorf("CBOR decoding COSE key header: %w", err)
	}
	return header.Alg, nil
}

func decodeES256PublicKey(data []byte) (*ecdsa.PublicKey, error) {
	var key coseEC2Key
	if err := cborDecMode.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("CBOR decoding COSE EC2 key: %w", err)
	}
	if key.Kty != KtyEC2 || key.Alg != AlgES256 || key.Crv != 1 {
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

func decodeMLDSA65PublicKey(data []byte) (*mldsa65.PublicKey, error) {
	var key coseMLDSAKey
	if err := cborDecMode.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("CBOR decoding COSE ML-DSA key: %w", err)
	}
	if key.Kty != KtyMLDSA || key.Alg != AlgMLDSA65 {
		return nil, ErrUnsupportedAlg
	}

	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(key.Pub); err != nil {
		return nil, fmt.Errorf("decoding ML-DSA-65 public key: %w", err)
	}
	return &pk, nil
}

// --- Composite ML-DSA-65-ES256 key decoding ---

// coseCompositeKey holds the composite key fields.
// The raw composite public key is stored in COSE parameter -1:
// ML-DSA-65 public key (1952 bytes) || ECDSA P-256 uncompressed point (65 bytes)
type coseCompositeKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Pub []byte `cbor:"-1,keyasint"` // concatenated component public keys
}

// compositePublicKey holds the decoded component keys for ML-DSA-65-ES256.
type compositePublicKey struct {
	MLDSA65 *mldsa65.PublicKey
	ECDSA   *ecdsa.PublicKey
}

// ML-DSA-65 public key size per FIPS 204.
const mldsaPubKeySize = 1952

// Uncompressed EC P-256 point: 0x04 || x(32) || y(32).
const ecdsaUncompressedSize = 65

func decodeCompositePublicKey(data []byte) (*compositePublicKey, error) {
	var key coseCompositeKey
	if err := cborDecMode.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("CBOR decoding COSE composite key: %w", err)
	}
	if key.Kty != KtyComposite || key.Alg != AlgCompositeMLDSA65ES256 {
		return nil, ErrUnsupportedAlg
	}

	expectedLen := mldsaPubKeySize + ecdsaUncompressedSize
	if len(key.Pub) != expectedLen {
		return nil, fmt.Errorf("composite public key wrong length: got %d, want %d", len(key.Pub), expectedLen)
	}

	// Split into ML-DSA-65 and ECDSA components
	mldsaPubBytes := key.Pub[:mldsaPubKeySize]
	ecdsaPubBytes := key.Pub[mldsaPubKeySize:]

	// Decode ML-DSA-65 component
	var mldsaPub mldsa65.PublicKey
	if err := mldsaPub.UnmarshalBinary(mldsaPubBytes); err != nil {
		return nil, fmt.Errorf("decoding ML-DSA-65 component: %w", err)
	}

	// Decode ECDSA P-256 component (uncompressed point)
	if ecdsaPubBytes[0] != 0x04 {
		return nil, fmt.Errorf("ECDSA component not uncompressed point")
	}
	ecdsaPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(ecdsaPubBytes[1:33]),
		Y:     new(big.Int).SetBytes(ecdsaPubBytes[33:65]),
	}

	return &compositePublicKey{MLDSA65: &mldsaPub, ECDSA: ecdsaPub}, nil
}

// --- Signature verification (multi-algorithm) ---

func verifySignatureES256(pubKey *ecdsa.PublicKey, authData, clientDataJSON, signatureBytes []byte) error {
	clientDataHash := sha256.Sum256(clientDataJSON)
	verifyData := append(authData, clientDataHash[:]...)
	hash := sha256.Sum256(verifyData)

	if !ecdsa.VerifyASN1(pubKey, hash[:], signatureBytes) {
		return ErrSignatureInvalid
	}
	return nil
}

func verifySignatureMLDSA65(pubKey *mldsa65.PublicKey, authData, clientDataJSON, signatureBytes []byte) error {
	clientDataHash := sha256.Sum256(clientDataJSON)
	verifyData := append(authData, clientDataHash[:]...)

	if !mldsa65.Verify(pubKey, verifyData, nil, signatureBytes) {
		return ErrSignatureInvalid
	}
	return nil
}

// verifySignatureComposite verifies an ML-DSA-65-ES256 composite signature.
// The composite signature format is: 4-byte big-endian ML-DSA sig length || ML-DSA sig || ES256 DER sig.
// Both components must verify independently for the composite to be valid.
func verifySignatureComposite(pubKey *compositePublicKey, authData, clientDataJSON, signatureBytes []byte) error {
	if len(signatureBytes) < 4 {
		return ErrSignatureInvalid
	}

	mldsaSigLen := binary.BigEndian.Uint32(signatureBytes[:4])
	if uint64(mldsaSigLen)+4 > uint64(len(signatureBytes)) {
		return ErrSignatureInvalid
	}

	mldsaSig := signatureBytes[4 : 4+mldsaSigLen]
	ecdsaSig := signatureBytes[4+mldsaSigLen:]

	// Both components sign over the same verification data
	if err := verifySignatureMLDSA65(pubKey.MLDSA65, authData, clientDataJSON, mldsaSig); err != nil {
		return err
	}
	if err := verifySignatureES256(pubKey.ECDSA, authData, clientDataJSON, ecdsaSig); err != nil {
		return err
	}

	return nil
}

// verifySignature dispatches to the correct algorithm based on the COSE key.
func verifySignature(coseKeyData, authData, clientDataJSON, signatureBytes []byte) error {
	alg, err := identifyCOSEAlgorithm(coseKeyData)
	if err != nil {
		return err
	}

	switch alg {
	case AlgES256:
		pubKey, err := decodeES256PublicKey(coseKeyData)
		if err != nil {
			return err
		}
		return verifySignatureES256(pubKey, authData, clientDataJSON, signatureBytes)

	case AlgMLDSA65:
		pubKey, err := decodeMLDSA65PublicKey(coseKeyData)
		if err != nil {
			return err
		}
		return verifySignatureMLDSA65(pubKey, authData, clientDataJSON, signatureBytes)

	case AlgCompositeMLDSA65ES256:
		pubKey, err := decodeCompositePublicKey(coseKeyData)
		if err != nil {
			return err
		}
		return verifySignatureComposite(pubKey, authData, clientDataJSON, signatureBytes)

	default:
		return ErrUnsupportedAlg
	}
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

	if pad.Flags&0x01 == 0 {
		return nil, ErrUserPresenceRequired
	}
	if input.RequireUserVerification && pad.Flags&0x04 == 0 {
		return nil, ErrUserVerificationRequired
	}

	return &RegistrationResult{
		CredentialID:  pad.CredentialID,
		PublicKeyCOSE: pad.CredentialKey,
		SignCount:     pad.SignCount,
		RPIDHash:      pad.RPIDHash,
		Flags:         pad.Flags,
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

	if pad.Flags&0x01 == 0 {
		return nil, ErrUserPresenceRequired
	}
	if input.RequireUserVerification && pad.Flags&0x04 == 0 {
		return nil, ErrUserVerificationRequired
	}

	sigBytes, err := b64Decode(input.Signature)
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	if err := verifySignature(input.StoredPublicKeyCOSE, authDataRaw, clientDataJSONRaw, sigBytes); err != nil {
		return nil, err
	}

	// Sign count rollback detection per WebAuthn spec §7.2 step 21.
	// If both stored and reported counts are non-zero, the new count must be greater.
	if input.StoredSignCount > 0 && pad.SignCount <= input.StoredSignCount {
		return nil, ErrSignCountRollback
	}

	return &AuthenticationResult{
		SignCount: pad.SignCount,
		Flags:     pad.Flags,
	}, nil
}

// --- Helpers ---

func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
