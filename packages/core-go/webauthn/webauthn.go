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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/fxamacker/cbor/v2"
)

// cborDecMode rejects CBOR maps with duplicate keys (defense-in-depth).
var cborDecMode, _ = cbor.DecOptions{
	DupMapKey: cbor.DupMapKeyEnforcedAPF,
}.DecMode()

// COSE algorithm identifiers.
const (
	AlgES256                 = -7  // ECDSA w/ SHA-256 on P-256
	AlgMLDSA65               = -49 // ML-DSA-65 (Dilithium3, FIPS 204)
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
	ErrTypeMismatch                 = errors.New("type_mismatch")
	ErrChallengeMismatch            = errors.New("challenge_mismatch")
	ErrOriginMismatch               = errors.New("origin_mismatch")
	ErrRPIDMismatch                 = errors.New("rp_id_mismatch")
	ErrSignatureInvalid             = errors.New("signature_invalid")
	ErrAuthDataTooShort             = errors.New("authenticator_data_too_short")
	ErrNoCredentialData             = errors.New("no_attested_credential_data")
	ErrUnsupportedAlg               = errors.New("unsupported_cose_algorithm")
	ErrSignCountRollback            = errors.New("sign_count_rollback")
	ErrUserPresenceRequired         = errors.New("user_presence_required")
	ErrUserVerificationRequired     = errors.New("user_verification_required")
	ErrUnsupportedAttestationFormat = errors.New("unsupported_attestation_format")
	ErrTokenBindingUnsupported      = errors.New("token_binding_unsupported")
	ErrInvalidBackupState           = errors.New("invalid_backup_state")
	ErrInvalidAttestationStatement  = errors.New("invalid_attestation_statement")
	ErrAuthDataTrailingBytes        = errors.New("authenticator_data_trailing_bytes")
)

// --- Public input/output types ---

type RegistrationInput struct {
	RPID                    string
	ExpectedChallenge       string // base64url-encoded
	ExpectedOrigin          string
	AdditionalOrigins       []string // additional accepted origins (e.g. multiple ports in dev)
	ClientDataJSON          string   // base64url-encoded
	AttestationObject       string   // base64url-encoded
	RequireUserVerification bool     // If true, UV flag (bit 2) must be set. Default false.
}

type RegistrationResult struct {
	CredentialID      []byte
	PublicKeyCOSE     []byte
	SignCount         uint32
	RPIDHash          []byte
	Flags             byte
	BackupEligible    bool     // BE flag (bit 3): credential can be backed up/synced
	BackupState       bool     // BS flag (bit 4): credential is currently backed up
	AttestationFormat string   // "none", "packed", "tpm", or "android-key"
	AttestationX5C    [][]byte // x5c certificate chain (nil for "none" and self-attestation)
}

type AuthenticationInput struct {
	RPID                    string
	ExpectedChallenge       string // base64url-encoded
	ExpectedOrigin          string
	AdditionalOrigins       []string // additional accepted origins (e.g. multiple ports in dev)
	StoredPublicKeyCOSE     []byte
	StoredSignCount         uint32
	ClientDataJSON          string // base64url-encoded
	AuthenticatorData       string // base64url-encoded
	Signature               string // base64url-encoded
	RequireUserVerification bool   // If true, UV flag (bit 2) must be set. Default false.

	// TODO: Add configurable SignCountPolicy (strict/relaxed/disabled).
	// Currently strict (line ~655): rejects if new <= stored. Synced passkeys (iCloud Keychain,
	// Google Password Manager) may lag sign count across devices temporarily.
	// Relaxed mode (accept >=) is needed for launch; revert to strict after confirming
	// iOS and Android reliably sync sign counts across devices.
}

type AuthenticationResult struct {
	SignCount      uint32
	Flags          byte
	BackupEligible bool
	BackupState    bool
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

func verifyClientData(clientDataJSONB64, expectedType, expectedChallenge, expectedOrigin string, additionalOrigins []string) ([]byte, error) {
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
	if !originMatches(cd.Origin, expectedOrigin, additionalOrigins) {
		return nil, ErrOriginMismatch
	}
	// tokenBinding, when present, must be an object whose status is one of
	// "present", "supported", or "not-supported" (WebAuthn §5.8.1). Absent
	// (or null) is fine. "present" means the client used token binding,
	// which we do not support, so the ceremony is rejected.
	if cd.TokenBinding != nil {
		switch cd.TokenBinding.Status {
		case "present":
			return nil, ErrTokenBindingUnsupported
		case "supported", "not-supported":
			// Accepted: no token binding was negotiated.
		default:
			return nil, fmt.Errorf("%w: invalid status %q", ErrTokenBindingUnsupported, cd.TokenBinding.Status)
		}
	}

	return raw, nil
}

func originMatches(actual, primary string, additional []string) bool {
	if actual == primary {
		return true
	}
	for _, o := range additional {
		if actual == o {
			return true
		}
	}
	return false
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
		rest = rest[credIDLen:]

		// The credential public key is exactly one CBOR item. Slice it
		// precisely so trailing bytes cannot hide inside CredentialKey.
		keyLen, err := cborItemLen(rest)
		if err != nil {
			return nil, fmt.Errorf("CBOR decoding credential public key: %w", err)
		}
		pad.CredentialKey = rest[:keyLen]
		rest = rest[keyLen:]

		// Any bytes after the credential key must be the extensions map
		// (flag 0x80) consuming the remainder exactly; otherwise they are
		// trailing garbage and the authData is rejected.
		if pad.Flags&0x80 != 0 {
			extLen, err := cborItemLen(rest)
			if err != nil {
				return nil, fmt.Errorf("CBOR decoding authData extensions: %w", err)
			}
			var extMap map[string]any
			if err := cborDecMode.Unmarshal(rest[:extLen], &extMap); err != nil {
				return nil, fmt.Errorf("CBOR decoding authData extensions: %w", err)
			}
			if extLen != len(rest) {
				return nil, ErrAuthDataTrailingBytes
			}
		} else if len(rest) > 0 {
			return nil, ErrAuthDataTrailingBytes
		}
	}

	return pad, nil
}

// cborItemLen returns the encoded length of the first well-formed CBOR data
// item in buf, or an error if buf holds no complete item.
func cborItemLen(buf []byte) (int, error) {
	end, err := cborItemEnd(buf, 0)
	if err != nil {
		return 0, err
	}
	return end, nil
}

// cborArgLen reads the argument of the initial byte at off and returns the
// offset of the content that follows plus the argument value. indefinite
// reports an indefinite-length head (content ends at a 0xff break byte).
func cborArgLen(buf []byte, off int) (content int, arg uint64, indefinite bool, err error) {
	if off >= len(buf) {
		return 0, 0, false, fmt.Errorf("truncated CBOR head")
	}
	ai := buf[off] & 0x1f
	switch {
	case ai < 24:
		return off + 1, uint64(ai), false, nil
	case ai == 24:
		if off+2 > len(buf) {
			return 0, 0, false, fmt.Errorf("truncated CBOR head")
		}
		return off + 2, uint64(buf[off+1]), false, nil
	case ai == 25:
		if off+3 > len(buf) {
			return 0, 0, false, fmt.Errorf("truncated CBOR head")
		}
		return off + 3, uint64(binary.BigEndian.Uint16(buf[off+1:])), false, nil
	case ai == 26:
		if off+5 > len(buf) {
			return 0, 0, false, fmt.Errorf("truncated CBOR head")
		}
		return off + 5, uint64(binary.BigEndian.Uint32(buf[off+1:])), false, nil
	case ai == 27:
		if off+9 > len(buf) {
			return 0, 0, false, fmt.Errorf("truncated CBOR head")
		}
		return off + 9, binary.BigEndian.Uint64(buf[off+1:]), false, nil
	case ai == 31:
		return off + 1, 0, true, nil
	default:
		return 0, 0, false, fmt.Errorf("reserved CBOR additional information %d", ai)
	}
}

// cborItemEnd returns the offset just past the CBOR item starting at off.
func cborItemEnd(buf []byte, off int) (int, error) {
	if off >= len(buf) {
		return 0, fmt.Errorf("truncated CBOR item")
	}
	if buf[off] == 0xff {
		return 0, fmt.Errorf("unexpected CBOR break byte")
	}
	mt := buf[off] >> 5
	content, arg, indefinite, err := cborArgLen(buf, off)
	if err != nil {
		return 0, err
	}
	switch mt {
	case 0, 1: // unsigned / negative integer (never indefinite)
		if indefinite {
			return 0, fmt.Errorf("indefinite CBOR integer")
		}
		return content, nil
	case 2, 3: // byte / text string
		if indefinite {
			for {
				if content >= len(buf) {
					return 0, fmt.Errorf("truncated indefinite CBOR string")
				}
				if buf[content] == 0xff {
					return content + 1, nil
				}
				chunkEnd, err := cborItemEnd(buf, content)
				if err != nil {
					return 0, err
				}
				content = chunkEnd
			}
		}
		if arg > uint64(len(buf)-content) {
			return 0, fmt.Errorf("truncated CBOR string content")
		}
		return content + int(arg), nil
	case 4: // array
		if indefinite {
			for {
				if content >= len(buf) {
					return 0, fmt.Errorf("truncated indefinite CBOR array")
				}
				if buf[content] == 0xff {
					return content + 1, nil
				}
				next, err := cborItemEnd(buf, content)
				if err != nil {
					return 0, err
				}
				content = next
			}
		}
		for i := uint64(0); i < arg; i++ {
			next, err := cborItemEnd(buf, content)
			if err != nil {
				return 0, err
			}
			content = next
		}
		return content, nil
	case 5: // map
		if indefinite {
			for {
				if content >= len(buf) {
					return 0, fmt.Errorf("truncated indefinite CBOR map")
				}
				if buf[content] == 0xff {
					return content + 1, nil
				}
				for k := 0; k < 2; k++ {
					next, err := cborItemEnd(buf, content)
					if err != nil {
						return 0, err
					}
					content = next
				}
			}
		}
		for i := uint64(0); i < arg; i++ {
			for k := 0; k < 2; k++ {
				next, err := cborItemEnd(buf, content)
				if err != nil {
					return 0, err
				}
				content = next
			}
		}
		return content, nil
	case 6: // tag: one enclosed item
		return cborItemEnd(buf, content)
	default: // simple / float: argument bytes are the content
		return content, nil
	}
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

type attestationStatement struct {
	Alg      int
	Sig      []byte
	X5C      [][]byte // nil for self-attestation
	Ver      string   // "tpm" only
	CertInfo []byte   // "tpm" only
	PubArea  []byte   // "tpm" only
}

type decodedAttestation struct {
	Fmt      string
	AuthData []byte
	AttStmt  *attestationStatement // nil for "none"
}

type attestationObject struct {
	Fmt      string          `cbor:"fmt"`
	AuthData []byte          `cbor:"authData"`
	AttStmt  cbor.RawMessage `cbor:"attStmt"`
}

func decodeAttestationObject(attObjB64 string) (*decodedAttestation, error) {
	raw, err := b64Decode(attObjB64)
	if err != nil {
		return nil, fmt.Errorf("decoding attestationObject: %w", err)
	}
	var obj attestationObject
	if err := cborDecMode.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("CBOR decoding attestationObject: %w", err)
	}
	switch obj.Fmt {
	case "none":
		// "none" attestation carries no statement; a non-empty attStmt is
		// malformed and must be rejected (WebAuthn §8.1).
		if len(obj.AttStmt) > 0 {
			var stmtMap map[string]cbor.RawMessage
			if err := cborDecMode.Unmarshal(obj.AttStmt, &stmtMap); err != nil {
				return nil, fmt.Errorf("%w: malformed none attStmt", ErrInvalidAttestationStatement)
			}
			if len(stmtMap) > 0 {
				return nil, fmt.Errorf("%w: none attestation with non-empty attStmt", ErrInvalidAttestationStatement)
			}
		}
		return &decodedAttestation{Fmt: "none", AuthData: obj.AuthData}, nil
	case "packed":
		stmt, err := decodePackedAttStmt(obj.AttStmt)
		if err != nil {
			return nil, err
		}
		return &decodedAttestation{Fmt: "packed", AuthData: obj.AuthData, AttStmt: stmt}, nil
	case "tpm":
		stmt, err := decodeTPMAttStmt(obj.AttStmt)
		if err != nil {
			return nil, err
		}
		return &decodedAttestation{Fmt: "tpm", AuthData: obj.AuthData, AttStmt: stmt}, nil
	case "android-key":
		stmt, err := decodeAndroidKeyAttStmt(obj.AttStmt)
		if err != nil {
			return nil, err
		}
		return &decodedAttestation{Fmt: "android-key", AuthData: obj.AuthData, AttStmt: stmt}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAttestationFormat, obj.Fmt)
	}
}

func decodePackedAttStmt(raw cbor.RawMessage) (*attestationStatement, error) {
	var m map[string]cbor.RawMessage
	if err := cborDecMode.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%w: decoding attStmt", ErrInvalidAttestationStatement)
	}

	algRaw, ok := m["alg"]
	if !ok {
		return nil, fmt.Errorf("%w: missing alg", ErrInvalidAttestationStatement)
	}
	var alg int
	if err := cborDecMode.Unmarshal(algRaw, &alg); err != nil {
		return nil, fmt.Errorf("%w: decoding alg", ErrInvalidAttestationStatement)
	}

	sigRaw, ok := m["sig"]
	if !ok {
		return nil, fmt.Errorf("%w: missing sig", ErrInvalidAttestationStatement)
	}
	var sig []byte
	if err := cborDecMode.Unmarshal(sigRaw, &sig); err != nil {
		return nil, fmt.Errorf("%w: decoding sig", ErrInvalidAttestationStatement)
	}

	stmt := &attestationStatement{Alg: alg, Sig: sig}

	if x5cRaw, ok := m["x5c"]; ok {
		var x5c [][]byte
		if err := cborDecMode.Unmarshal(x5cRaw, &x5c); err != nil {
			return nil, fmt.Errorf("%w: decoding x5c", ErrInvalidAttestationStatement)
		}
		stmt.X5C = x5c
	}

	return stmt, nil
}

// decodeCommonAttStmt decodes the alg/sig/x5c fields shared by the
// x5c-based attestation formats ("packed", "tpm", "android-key").
func decodeCommonAttStmt(raw cbor.RawMessage) (*attestationStatement, map[string]cbor.RawMessage, error) {
	var m map[string]cbor.RawMessage
	if err := cborDecMode.Unmarshal(raw, &m); err != nil {
		return nil, nil, fmt.Errorf("%w: decoding attStmt", ErrInvalidAttestationStatement)
	}

	algRaw, ok := m["alg"]
	if !ok {
		return nil, nil, fmt.Errorf("%w: missing alg", ErrInvalidAttestationStatement)
	}
	var alg int
	if err := cborDecMode.Unmarshal(algRaw, &alg); err != nil {
		return nil, nil, fmt.Errorf("%w: decoding alg", ErrInvalidAttestationStatement)
	}

	sigRaw, ok := m["sig"]
	if !ok {
		return nil, nil, fmt.Errorf("%w: missing sig", ErrInvalidAttestationStatement)
	}
	var sig []byte
	if err := cborDecMode.Unmarshal(sigRaw, &sig); err != nil {
		return nil, nil, fmt.Errorf("%w: decoding sig", ErrInvalidAttestationStatement)
	}

	stmt := &attestationStatement{Alg: alg, Sig: sig}

	if x5cRaw, ok := m["x5c"]; ok {
		var x5c [][]byte
		if err := cborDecMode.Unmarshal(x5cRaw, &x5c); err != nil {
			return nil, nil, fmt.Errorf("%w: decoding x5c", ErrInvalidAttestationStatement)
		}
		stmt.X5C = x5c
	}

	return stmt, m, nil
}

func decodeByteField(m map[string]cbor.RawMessage, name string) ([]byte, error) {
	fieldRaw, ok := m[name]
	if !ok {
		return nil, fmt.Errorf("%w: missing %s", ErrInvalidAttestationStatement, name)
	}
	var field []byte
	if err := cborDecMode.Unmarshal(fieldRaw, &field); err != nil {
		return nil, fmt.Errorf("%w: decoding %s", ErrInvalidAttestationStatement, name)
	}
	return field, nil
}

// decodeTPMAttStmt decodes a TPM attestation statement (WebAuthn §8.3):
// ver, alg, x5c, sig, certInfo, pubArea.
func decodeTPMAttStmt(raw cbor.RawMessage) (*attestationStatement, error) {
	stmt, m, err := decodeCommonAttStmt(raw)
	if err != nil {
		return nil, err
	}

	verRaw, ok := m["ver"]
	if !ok {
		return nil, fmt.Errorf("%w: missing ver", ErrInvalidAttestationStatement)
	}
	var ver string
	if err := cborDecMode.Unmarshal(verRaw, &ver); err != nil {
		return nil, fmt.Errorf("%w: decoding ver", ErrInvalidAttestationStatement)
	}
	stmt.Ver = ver

	if stmt.CertInfo, err = decodeByteField(m, "certInfo"); err != nil {
		return nil, err
	}
	if stmt.PubArea, err = decodeByteField(m, "pubArea"); err != nil {
		return nil, err
	}
	return stmt, nil
}

// decodeAndroidKeyAttStmt decodes an android-key attestation statement
// (WebAuthn §8.4): alg, sig, x5c.
func decodeAndroidKeyAttStmt(raw cbor.RawMessage) (*attestationStatement, error) {
	stmt, _, err := decodeCommonAttStmt(raw)
	if err != nil {
		return nil, err
	}
	return stmt, nil
}

// verifyPackedAttestation verifies a packed attestation statement per WebAuthn §8.2.
func verifyPackedAttestation(att *decodedAttestation, clientDataJSONRaw, credentialKey []byte) error {
	if att.AttStmt.X5C != nil {
		// Full attestation: verify with x5c[0] certificate
		return verifyPackedFullAttestation(att.AttStmt, att.AuthData, clientDataJSONRaw, credentialKey)
	}
	// Self-attestation: verify with credential public key
	return verifySignature(credentialKey, att.AuthData, clientDataJSONRaw, att.AttStmt.Sig)
}

func verifyPackedFullAttestation(stmt *attestationStatement, authData, clientDataJSONRaw, credentialKey []byte) error {
	if len(stmt.X5C) == 0 {
		return fmt.Errorf("%w: x5c is empty", ErrInvalidAttestationStatement)
	}
	cert, err := x509.ParseCertificate(stmt.X5C[0])
	if err != nil {
		return fmt.Errorf("parsing attestation certificate: %w", err)
	}

	// The leaf certificate must be currently valid: reject expired or
	// not-yet-valid attestation certificates.
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: attestation certificate not yet valid", ErrInvalidAttestationStatement)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: attestation certificate expired", ErrInvalidAttestationStatement)
	}

	clientDataHash := sha256.Sum256(clientDataJSONRaw)
	verifyData := append(authData, clientDataHash[:]...)
	hash := sha256.Sum256(verifyData)

	switch stmt.Alg {
	case AlgES256:
		ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrSignatureInvalid
		}
		// A "full" attestation whose leaf key is the credential key itself
		// is a self attestation carrying x5c — malformed, reject. Genuine
		// self attestation carries no x5c; genuine full attestation is
		// signed by a dedicated attestation key.
		if credKey, err := decodeES256PublicKey(credentialKey); err == nil {
			if ecKey.Curve == credKey.Curve &&
				ecKey.X.Cmp(credKey.X) == 0 && ecKey.Y.Cmp(credKey.Y) == 0 {
				return fmt.Errorf("%w: attestation certificate key matches credential key", ErrInvalidAttestationStatement)
			}
		}
		if !ecdsa.VerifyASN1(ecKey, hash[:], stmt.Sig) {
			return ErrSignatureInvalid
		}
	default:
		return fmt.Errorf("%w: attestation alg %d", ErrUnsupportedAlg, stmt.Alg)
	}
	return nil
}

// --- TPM attestation (WebAuthn §8.3) ---
//
// Same-documented policy as packed: the AIK certificate (x5c[0]) is used as
// the trust anchor for the signature only — no chain-to-root validation.
// Per spec, sig covers certInfo (which binds attToBeSigned via extraData).

const (
	tpmGeneratedValue  = 0xFF544347 // magic for TPMS_ATTEST
	tpmStAttestCertify = 0x8017     // type for certify attestation
	tpmAlgECC          = 0x0023     // TPMT_PUBLIC type for ECC keys
)

// tpmNameHash returns the hash constructor for a TPM nameAlg identifier.
func tpmNameHash(nameAlg uint16) (func() hash.Hash, error) {
	switch nameAlg {
	case 0x0004:
		return sha1.New, nil
	case 0x000B:
		return sha256.New, nil
	case 0x000C:
		return sha512.New384, nil
	case 0x000D:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("%w: unsupported tpm nameAlg 0x%x", ErrInvalidAttestationStatement, nameAlg)
	}
}

func tpmU16be(buf []byte, offset int) uint16 {
	return binary.BigEndian.Uint16(buf[offset : offset+2])
}

// readTPM2B reads a TPM2B sized buffer (u16 length prefix + bytes).
func readTPM2B(buf []byte, offset int, context string) ([]byte, int, error) {
	if offset+2 > len(buf) {
		return nil, 0, fmt.Errorf("%w: malformed tpm %s", ErrInvalidAttestationStatement, context)
	}
	length := int(tpmU16be(buf, offset))
	if offset+2+length > len(buf) {
		return nil, 0, fmt.Errorf("%w: malformed tpm %s", ErrInvalidAttestationStatement, context)
	}
	return buf[offset+2 : offset+2+length], offset + 2 + length, nil
}

type tpmPubAreaInfo struct {
	nameAlg uint16
	x, y    []byte
}

// parseTPMPubArea parses a TPM2B_PUBLIC (pubArea) holding an ECC key:
// type(2) || nameAlg(2) || objectAttributes(4) || authPolicy(TPM2B) ||
// parameters (symmetric(2) || scheme(2) || curveID(2) || kdf(2)) ||
// unique (x TPM2B || y TPM2B).
func parseTPMPubArea(pubArea []byte) (*tpmPubAreaInfo, error) {
	if len(pubArea) < 2+2+4+2+8+2+2 {
		return nil, fmt.Errorf("%w: malformed tpm pubArea", ErrInvalidAttestationStatement)
	}
	offset := 0
	typ := tpmU16be(pubArea, offset)
	offset += 2
	if typ != tpmAlgECC {
		return nil, fmt.Errorf("%w: unsupported tpm pubArea type 0x%x", ErrInvalidAttestationStatement, typ)
	}
	nameAlg := tpmU16be(pubArea, offset)
	offset += 2
	if _, err := tpmNameHash(nameAlg); err != nil {
		return nil, err
	}
	offset += 4 // objectAttributes
	var authPolicy []byte
	var err error
	if authPolicy, offset, err = readTPM2B(pubArea, offset, "pubArea authPolicy"); err != nil {
		return nil, err
	}
	_ = authPolicy
	if offset+8 > len(pubArea) {
		return nil, fmt.Errorf("%w: malformed tpm pubArea parameters", ErrInvalidAttestationStatement)
	}
	offset += 8 // symmetric, scheme, curveID, kdf
	var x, y []byte
	if x, offset, err = readTPM2B(pubArea, offset, "pubArea x"); err != nil {
		return nil, err
	}
	if y, _, err = readTPM2B(pubArea, offset, "pubArea y"); err != nil {
		return nil, err
	}
	return &tpmPubAreaInfo{nameAlg: nameAlg, x: x, y: y}, nil
}

// computeTPMName returns the TPM name of pubArea: nameAlg(2 BE) || Hash_nameAlg(pubArea).
func computeTPMName(pubArea []byte, nameAlg uint16) ([]byte, error) {
	newHash, err := tpmNameHash(nameAlg)
	if err != nil {
		return nil, err
	}
	h := newHash()
	h.Write(pubArea)
	digest := h.Sum(nil)
	name := make([]byte, 2+len(digest))
	binary.BigEndian.PutUint16(name, nameAlg)
	copy(name[2:], digest)
	return name, nil
}

type tpmCertInfo struct {
	extraData []byte
	name      []byte
}

// parseTPMCertInfo parses a TPMS_ATTEST (certInfo): magic(4) || type(2) ||
// qualifiedSigner(TPM2B) || extraData(TPM2B) || clockInfo(17) ||
// firmwareVersion(8) || attested (certify: name TPM2B || qualifiedName TPM2B).
func parseTPMCertInfo(certInfo []byte) (*tpmCertInfo, error) {
	if len(certInfo) < 4+2+2+2+17+8+2+2 {
		return nil, fmt.Errorf("%w: malformed tpm certInfo", ErrInvalidAttestationStatement)
	}
	offset := 0
	magic := binary.BigEndian.Uint32(certInfo[offset:])
	offset += 4
	if magic != tpmGeneratedValue {
		return nil, fmt.Errorf("%w: tpm certInfo bad magic", ErrInvalidAttestationStatement)
	}
	typ := tpmU16be(certInfo, offset)
	offset += 2
	if typ != tpmStAttestCertify {
		return nil, fmt.Errorf("%w: tpm certInfo bad type", ErrInvalidAttestationStatement)
	}
	var err error
	var extraData, name []byte
	if _, offset, err = readTPM2B(certInfo, offset, "certInfo qualifiedSigner"); err != nil {
		return nil, err
	}
	if extraData, offset, err = readTPM2B(certInfo, offset, "certInfo extraData"); err != nil {
		return nil, err
	}
	if offset+17+8+2 > len(certInfo) {
		return nil, fmt.Errorf("%w: malformed tpm certInfo", ErrInvalidAttestationStatement)
	}
	offset += 17 // clockInfo
	offset += 8  // firmwareVersion
	if name, offset, err = readTPM2B(certInfo, offset, "certInfo name"); err != nil {
		return nil, err
	}
	if offset+2 > len(certInfo) {
		return nil, fmt.Errorf("%w: malformed tpm certInfo qualifiedName", ErrInvalidAttestationStatement)
	}
	return &tpmCertInfo{extraData: extraData, name: name}, nil
}

// verifyTPMAttestation verifies a TPM attestation statement per WebAuthn §8.3.
func verifyTPMAttestation(att *decodedAttestation, clientDataJSONRaw, credentialKey []byte) error {
	stmt := att.AttStmt
	if stmt.Ver != "2.0" {
		return fmt.Errorf("%w: tpm ver must be \"2.0\"", ErrInvalidAttestationStatement)
	}
	if len(stmt.Sig) == 0 || len(stmt.X5C) == 0 || len(stmt.CertInfo) == 0 || len(stmt.PubArea) == 0 {
		return fmt.Errorf("%w: tpm statement missing sig, x5c, certInfo, or pubArea", ErrInvalidAttestationStatement)
	}

	pubArea, err := parseTPMPubArea(stmt.PubArea)
	if err != nil {
		return err
	}
	expectedName, err := computeTPMName(stmt.PubArea, pubArea.nameAlg)
	if err != nil {
		return err
	}
	certInfo, err := parseTPMCertInfo(stmt.CertInfo)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(certInfo.name, expectedName) != 1 {
		return fmt.Errorf("%w: tpm certInfo name mismatch", ErrInvalidAttestationStatement)
	}

	clientDataHash := sha256.Sum256(clientDataJSONRaw)
	attToBeSigned := make([]byte, 0, len(att.AuthData)+len(clientDataHash))
	attToBeSigned = append(attToBeSigned, att.AuthData...)
	attToBeSigned = append(attToBeSigned, clientDataHash[:]...)
	// Per TPM Library (TPMS_ATTEST) + WebAuthn §8.3, extraData is a TPM2B
	// (max 64 bytes) holding the digest of attToBeSigned under the nameAlg
	// hash, not attToBeSigned itself.
	nameHash, err := tpmNameHash(pubArea.nameAlg)
	if err != nil {
		return err
	}
	h := nameHash()
	h.Write(attToBeSigned)
	expectedExtra := h.Sum(nil)
	if subtle.ConstantTimeCompare(certInfo.extraData, expectedExtra) != 1 {
		return fmt.Errorf("%w: tpm certInfo extraData mismatch", ErrInvalidAttestationStatement)
	}

	// The ECC point in pubArea must equal the credential key from authData.
	credKey, err := decodeES256PublicKey(credentialKey)
	if err != nil {
		return err
	}
	if credKey.X.Cmp(new(big.Int).SetBytes(pubArea.x)) != 0 ||
		credKey.Y.Cmp(new(big.Int).SetBytes(pubArea.y)) != 0 {
		return fmt.Errorf("%w: tpm pubArea point differs from credential key", ErrInvalidAttestationStatement)
	}

	if stmt.Alg != AlgES256 {
		return fmt.Errorf("%w: attestation alg %d", ErrUnsupportedAlg, stmt.Alg)
	}
	cert, err := x509.ParseCertificate(stmt.X5C[0])
	if err != nil {
		return fmt.Errorf("parsing AIK certificate: %w", err)
	}
	ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrSignatureInvalid
	}
	certInfoHash := sha256.Sum256(stmt.CertInfo)
	if !ecdsa.VerifyASN1(ecKey, certInfoHash[:], stmt.Sig) {
		return ErrSignatureInvalid
	}
	return nil
}

// --- Android Key attestation (WebAuthn §8.4) ---
//
// Same-documented policy as packed: the leaf certificate (x5c[0]) is used as
// the trust anchor for the signature only — no chain-to-root validation.
// Policy: accept TEE and StrongBox security levels, reject SoftwareOnly.

// Keymaster security levels: 0 = SoftwareOnly, 1 = TEE, 2 = StrongBox.
const (
	androidSecurityLevelSoftware  = 0
	androidSecurityLevelTEE       = 1
	androidSecurityLevelStrongBox = 2
)

// androidKeyDescription mirrors the ASN.1 KeyDescription SEQUENCE; only the
// leading fields are decoded, the authorization lists stay opaque.
type androidKeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TEEEnforced              asn1.RawValue
}

// derTlv is one DER tag-length-value element.
type derTlv struct {
	tag   byte
	value []byte
}

func readDERElement(buf []byte, offset int) (derTlv, int, error) {
	if offset+2 > len(buf) {
		return derTlv{}, 0, fmt.Errorf("%w: malformed certificate DER", ErrInvalidAttestationStatement)
	}
	tag := buf[offset]
	length := int(buf[offset+1])
	headerLen := 2
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || offset+2+count > len(buf) {
			return derTlv{}, 0, fmt.Errorf("%w: malformed certificate DER", ErrInvalidAttestationStatement)
		}
		length = 0
		for i := 0; i < count; i++ {
			length = length*256 + int(buf[offset+2+i])
		}
		headerLen += count
	}
	if offset+headerLen+length > len(buf) {
		return derTlv{}, 0, fmt.Errorf("%w: malformed certificate DER", ErrInvalidAttestationStatement)
	}
	return derTlv{tag: tag, value: buf[offset+headerLen : offset+headerLen+length]}, offset + headerLen + length, nil
}

func readDERChildren(buf []byte) ([]derTlv, error) {
	var out []derTlv
	offset := 0
	for offset < len(buf) {
		el, next, err := readDERElement(buf, offset)
		if err != nil {
			return nil, err
		}
		out = append(out, el)
		offset = next
	}
	return out, nil
}

// androidOIDContents holds the DER contents of OID 1.3.6.1.4.1.11129.2.1.17.
var androidOIDContents = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11}

// parseAndroidKeyDescription walks the leaf certificate DER to the KeyDescription
// extension (OID 1.3.6.1.4.1.11129.2.1.17) and returns the parsed KeyDescription:
//
//	KeyDescription ::= SEQUENCE { attestationVersion INTEGER,
//	  attestationSecurityLevel ENUMERATED, keymasterVersion INTEGER,
//	  keymasterSecurityLevel ENUMERATED, attestationChallenge OCTET STRING,
//	  uniqueId OCTET STRING, softwareEnforced AuthorizationList,
//	  teeEnforced AuthorizationList }
func parseAndroidKeyDescription(certDER []byte) (*androidKeyDescription, error) {
	cert, _, err := readDERElement(certDER, 0)
	if err != nil {
		return nil, err
	}
	if cert.tag != 0x30 {
		return nil, fmt.Errorf("%w: malformed certificate DER", ErrInvalidAttestationStatement)
	}
	certKids, err := readDERChildren(cert.value)
	if err != nil {
		return nil, err
	}
	if len(certKids) < 1 || certKids[0].tag != 0x30 {
		return nil, fmt.Errorf("%w: malformed certificate DER", ErrInvalidAttestationStatement)
	}
	tbsKids, err := readDERChildren(certKids[0].value)
	if err != nil {
		return nil, err
	}
	var extensions *derTlv
	for i := range tbsKids {
		if tbsKids[i].tag == 0xa3 {
			extensions = &tbsKids[i]
			break
		}
	}
	if extensions == nil {
		return nil, fmt.Errorf("%w: android-key leaf certificate has no extensions", ErrInvalidAttestationStatement)
	}
	wrapperKids, err := readDERChildren(extensions.value)
	if err != nil {
		return nil, err
	}
	if len(wrapperKids) < 1 || wrapperKids[0].tag != 0x30 {
		return nil, fmt.Errorf("%w: malformed certificate extensions", ErrInvalidAttestationStatement)
	}
	extList, err := readDERChildren(wrapperKids[0].value)
	if err != nil {
		return nil, err
	}
	for _, ext := range extList {
		if ext.tag != 0x30 {
			continue
		}
		parts, err := readDERChildren(ext.value)
		if err != nil {
			return nil, err
		}
		if len(parts) < 2 || parts[0].tag != 0x06 {
			continue
		}
		if subtle.ConstantTimeCompare(parts[0].value, androidOIDContents) != 1 {
			continue
		}
		var extValue []byte
		for _, p := range parts {
			if p.tag == 0x04 {
				extValue = p.value
				break
			}
		}
		if extValue == nil {
			return nil, fmt.Errorf("%w: malformed android-key extension value", ErrInvalidAttestationStatement)
		}
		var kd androidKeyDescription
		if _, err := asn1.Unmarshal(extValue, &kd); err != nil {
			return nil, fmt.Errorf("%w: malformed android KeyDescription", ErrInvalidAttestationStatement)
		}
		return &kd, nil
	}
	return nil, fmt.Errorf("%w: android-key extension 1.3.6.1.4.1.11129.2.1.17 missing", ErrInvalidAttestationStatement)
}

// androidSecurityLevel returns the KeyDescription attestationSecurityLevel
// from the leaf certificate DER.
func androidSecurityLevel(certDER []byte) (int, error) {
	kd, err := parseAndroidKeyDescription(certDER)
	if err != nil {
		return 0, err
	}
	return int(kd.AttestationSecurityLevel), nil
}

// verifyAndroidKeyAttestation verifies an android-key attestation statement
// per WebAuthn §8.4.
func verifyAndroidKeyAttestation(att *decodedAttestation, clientDataJSONRaw []byte) error {
	stmt := att.AttStmt
	if len(stmt.Sig) == 0 || len(stmt.X5C) == 0 {
		return fmt.Errorf("%w: android-key statement missing sig or x5c", ErrInvalidAttestationStatement)
	}

	kd, err := parseAndroidKeyDescription(stmt.X5C[0])
	if err != nil {
		return err
	}
	level := int(kd.AttestationSecurityLevel)
	if level == androidSecurityLevelSoftware {
		return fmt.Errorf("%w: android-key software-only attestation rejected", ErrInvalidAttestationStatement)
	}
	if level != androidSecurityLevelTEE && level != androidSecurityLevelStrongBox {
		return fmt.Errorf("%w: android-key unrecognized security level %d", ErrInvalidAttestationStatement, level)
	}

	// WebAuthn §8.4: attestationChallenge must equal the clientDataHash.
	clientDataHash := sha256.Sum256(clientDataJSONRaw)
	if subtle.ConstantTimeCompare(kd.AttestationChallenge, clientDataHash[:]) != 1 {
		return fmt.Errorf("%w: android-key attestationChallenge mismatch", ErrInvalidAttestationStatement)
	}

	if stmt.Alg != AlgES256 {
		return fmt.Errorf("%w: attestation alg %d", ErrUnsupportedAlg, stmt.Alg)
	}
	cert, err := x509.ParseCertificate(stmt.X5C[0])
	if err != nil {
		return fmt.Errorf("parsing android-key leaf certificate: %w", err)
	}
	ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrSignatureInvalid
	}
	verifyData := make([]byte, 0, len(att.AuthData)+len(clientDataHash))
	verifyData = append(verifyData, att.AuthData...)
	verifyData = append(verifyData, clientDataHash[:]...)
	hash := sha256.Sum256(verifyData)
	if !ecdsa.VerifyASN1(ecKey, hash[:], stmt.Sig) {
		return ErrSignatureInvalid
	}
	return nil
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
	clientDataJSONRaw, err := verifyClientData(input.ClientDataJSON, "webauthn.create", input.ExpectedChallenge, input.ExpectedOrigin, input.AdditionalOrigins)
	if err != nil {
		return nil, err
	}

	att, err := decodeAttestationObject(input.AttestationObject)
	if err != nil {
		return nil, err
	}

	pad, err := parseAuthenticatorData(att.AuthData, true)
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

	// BS must be 0 if BE is 0 (§6.3.3)
	if pad.Flags&0x08 == 0 && pad.Flags&0x10 != 0 {
		return nil, ErrInvalidBackupState
	}

	// Verify the attestation statement ("none" carries nothing to verify).
	// Same-documented policy for every x5c format: signatures verify with
	// x5c[0]; no chain-to-root validation.
	switch att.Fmt {
	case "packed":
		if err := verifyPackedAttestation(att, clientDataJSONRaw, pad.CredentialKey); err != nil {
			return nil, err
		}
	case "tpm":
		if err := verifyTPMAttestation(att, clientDataJSONRaw, pad.CredentialKey); err != nil {
			return nil, err
		}
	case "android-key":
		if err := verifyAndroidKeyAttestation(att, clientDataJSONRaw); err != nil {
			return nil, err
		}
	}

	result := &RegistrationResult{
		CredentialID:      pad.CredentialID,
		PublicKeyCOSE:     pad.CredentialKey,
		SignCount:         pad.SignCount,
		RPIDHash:          pad.RPIDHash,
		Flags:             pad.Flags,
		BackupEligible:    pad.Flags&0x08 != 0,
		BackupState:       pad.Flags&0x10 != 0,
		AttestationFormat: att.Fmt,
	}
	if att.AttStmt != nil && att.AttStmt.X5C != nil {
		result.AttestationX5C = att.AttStmt.X5C
	}
	return result, nil
}

func VerifyAuthentication(input AuthenticationInput) (*AuthenticationResult, error) {
	clientDataJSONRaw, err := verifyClientData(input.ClientDataJSON, "webauthn.get", input.ExpectedChallenge, input.ExpectedOrigin, input.AdditionalOrigins)
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

	// BS must be 0 if BE is 0 (§6.3.3)
	if pad.Flags&0x08 == 0 && pad.Flags&0x10 != 0 {
		return nil, ErrInvalidBackupState
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
		SignCount:      pad.SignCount,
		Flags:          pad.Flags,
		BackupEligible: pad.Flags&0x08 != 0,
		BackupState:    pad.Flags&0x10 != 0,
	}, nil
}

// --- Helpers ---

func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
