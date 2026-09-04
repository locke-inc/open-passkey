package webauthn

// Synthetic fixtures for the TPM (§8.3) and android-key (§8.4) attestation
// formats: hand-built certInfo/pubArea structures plus self-signed P-256
// AIK/leaf certificates. These tests call the verify functions directly.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func testMustECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating P-256 key: %v", err)
	}
	return key
}

func testPad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// testFakeAuthData returns rpIdHash(32) || flags(1) || signCount(4).
func testFakeAuthData() []byte {
	rpIDHash := sha256.Sum256([]byte("example.com"))
	out := make([]byte, 0, 37)
	out = append(out, rpIDHash[:]...)
	out = append(out, 0x41) // UP + AT
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], 1)
	out = append(out, sc[:]...)
	return out
}

func testClientDataJSON() []byte {
	return []byte(`{"type":"webauthn.create","challenge":"c","origin":"https://example.com"}`)
}

// testTPM2B encodes a TPM2B sized buffer (u16 length prefix + bytes).
func testTPM2B(content []byte) []byte {
	out := make([]byte, 2+len(content))
	binary.BigEndian.PutUint16(out, uint16(len(content)))
	copy(out[2:], content)
	return out
}

// testBuildPubArea encodes a TPM2B_PUBLIC holding an ECC P-256 key.
func testBuildPubArea(x, y []byte) []byte {
	head := make([]byte, 2+2+4)
	binary.BigEndian.PutUint16(head[0:], 0x0023) // TPM_ALG_ECC
	binary.BigEndian.PutUint16(head[2:], 0x000B) // nameAlg sha256
	// objectAttributes left zero.
	out := append([]byte{}, head...)
	out = append(out, testTPM2B(nil)...)  // authPolicy
	out = append(out, make([]byte, 8)...) // symmetric, scheme, curveID, kdf
	out = append(out, testTPM2B(x)...)
	out = append(out, testTPM2B(y)...)
	return out
}

// testBuildCertInfo encodes a TPMS_ATTEST (certify) structure.
func testBuildCertInfo(magic uint32, typ uint16, extraData, name []byte) []byte {
	var out []byte
	var magicB [4]byte
	binary.BigEndian.PutUint32(magicB[:], magic)
	out = append(out, magicB[:]...)
	var typeB [2]byte
	binary.BigEndian.PutUint16(typeB[:], typ)
	out = append(out, typeB[:]...)
	out = append(out, testTPM2B(nil)...) // qualifiedSigner
	out = append(out, testTPM2B(extraData)...)
	out = append(out, make([]byte, 17)...) // clockInfo
	out = append(out, make([]byte, 8)...)  // firmwareVersion
	out = append(out, testTPM2B(name)...)
	out = append(out, testTPM2B(nil)...) // qualifiedName
	return out
}

// testSelfSignedCert creates a self-signed P-256 certificate DER.
func testSelfSignedCert(t *testing.T, pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey, extraExtensions []pkix.Extension) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "Test"},
		NotBefore:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:        time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: extraExtensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("creating test certificate: %v", err)
	}
	return der
}

func testSignASN1(t *testing.T, priv *ecdsa.PrivateKey, hash []byte) []byte {
	t.Helper()
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return sig
}

func testCoseES256(t *testing.T, x, y []byte) []byte {
	t.Helper()
	raw, err := cbor.Marshal(coseEC2Key{Kty: KtyEC2, Alg: AlgES256, Crv: 1, X: x, Y: y})
	if err != nil {
		t.Fatalf("marshaling COSE key: %v", err)
	}
	return raw
}

// --- TPM fixtures ---

type testTPMFixture struct {
	att            *decodedAttestation
	clientDataJSON []byte
	coseKey        []byte
	certInfo       []byte
	extraData      []byte
	name           []byte
	authData       []byte
	clientDataHash [32]byte
	aik            *ecdsa.PrivateKey
}

func testBuildTPMFixture(t *testing.T) *testTPMFixture {
	t.Helper()
	cred := testMustECKey(t)
	aik := testMustECKey(t)
	x := testPad32(cred.PublicKey.X.Bytes())
	y := testPad32(cred.PublicKey.Y.Bytes())

	authData := testFakeAuthData()
	clientDataJSON := testClientDataJSON()
	clientDataHash := sha256.Sum256(clientDataJSON)

	pubArea := testBuildPubArea(x, y)
	// TPM name computed independently of computeTPMName.
	nameHash, err := tpmNameHash(0x000B)
	if err != nil {
		t.Fatalf("name hash: %v", err)
	}
	h := nameHash()
	h.Write(pubArea)
	name := append([]byte{0x00, 0x0B}, h.Sum(nil)...)

	// extraData is the nameAlg hash of attToBeSigned (the fixed behavior).
	attToBeSigned := append(append([]byte{}, authData...), clientDataHash[:]...)
	extraSum := sha256.Sum256(attToBeSigned)
	extraData := extraSum[:]

	certInfo := testBuildCertInfo(tpmGeneratedValue, tpmStAttestCertify, extraData, name)
	aikDER := testSelfSignedCert(t, &aik.PublicKey, aik, nil)
	certInfoHash := sha256.Sum256(certInfo)
	sig := testSignASN1(t, aik, certInfoHash[:])

	return &testTPMFixture{
		att: &decodedAttestation{
			AuthData: authData,
			AttStmt: &attestationStatement{
				Alg:      AlgES256,
				Sig:      sig,
				X5C:      [][]byte{aikDER},
				Ver:      "2.0",
				CertInfo: certInfo,
				PubArea:  pubArea,
			},
		},
		clientDataJSON: clientDataJSON,
		coseKey:        testCoseES256(t, x, y),
		certInfo:       certInfo,
		extraData:      extraData,
		name:           name,
		authData:       authData,
		clientDataHash: clientDataHash,
		aik:            aik,
	}
}

func testRequireInvalidAttestation(t *testing.T, err error, msgPart string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected invalid_attestation_statement error, got nil")
	}
	if !errors.Is(err, ErrInvalidAttestationStatement) {
		t.Fatalf("expected invalid_attestation_statement, got: %v", err)
	}
	if !strings.Contains(err.Error(), msgPart) {
		t.Fatalf("expected error containing %q, got: %v", msgPart, err)
	}
}

func TestVerifyTPMValid(t *testing.T) {
	f := testBuildTPMFixture(t)
	if err := verifyTPMAttestation(f.att, f.clientDataJSON, f.coseKey); err != nil {
		t.Fatalf("valid TPM statement rejected: %v", err)
	}
}

func TestVerifyTPMTamperedSig(t *testing.T) {
	f := testBuildTPMFixture(t)
	badSig := append([]byte{}, f.att.AttStmt.Sig...)
	badSig[len(badSig)-1] ^= 0x01
	f.att.AttStmt.Sig = badSig
	err := verifyTPMAttestation(f.att, f.clientDataJSON, f.coseKey)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected signature_invalid, got: %v", err)
	}
}

func TestVerifyTPMBadMagic(t *testing.T) {
	f := testBuildTPMFixture(t)
	f.att.AttStmt.CertInfo = testBuildCertInfo(0x00000000, tpmStAttestCertify, f.extraData, f.name)
	testRequireInvalidAttestation(t, verifyTPMAttestation(f.att, f.clientDataJSON, f.coseKey), "bad magic")
}

func TestVerifyTPMNameMismatch(t *testing.T) {
	f := testBuildTPMFixture(t)
	badName := append([]byte{}, f.name...)
	badName[len(badName)-1] ^= 0x01
	f.att.AttStmt.CertInfo = testBuildCertInfo(tpmGeneratedValue, tpmStAttestCertify, f.extraData, badName)
	testRequireInvalidAttestation(t, verifyTPMAttestation(f.att, f.clientDataJSON, f.coseKey), "name mismatch")
}

func TestVerifyTPMExtraDataMismatch(t *testing.T) {
	f := testBuildTPMFixture(t)
	badExtra := sha256.Sum256([]byte("wrong"))
	f.att.AttStmt.CertInfo = testBuildCertInfo(tpmGeneratedValue, tpmStAttestCertify, badExtra[:], f.name)
	testRequireInvalidAttestation(t, verifyTPMAttestation(f.att, f.clientDataJSON, f.coseKey), "extraData mismatch")
}

func TestVerifyTPMRawAttToBeSignedRejected(t *testing.T) {
	// Guards the original bug: extraData holding attToBeSigned verbatim.
	f := testBuildTPMFixture(t)
	raw := append(append([]byte{}, f.authData...), f.clientDataHash[:]...)
	f.att.AttStmt.CertInfo = testBuildCertInfo(tpmGeneratedValue, tpmStAttestCertify, raw, f.name)
	testRequireInvalidAttestation(t, verifyTPMAttestation(f.att, f.clientDataJSON, f.coseKey), "extraData mismatch")
}

// --- android-key fixtures ---

var testAndroidOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

func testAndroidKeyDescriptionDER(t *testing.T, securityLevel int, challenge []byte) []byte {
	t.Helper()
	emptyList := asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: []byte{}}
	der, err := asn1.Marshal(androidKeyDescription{
		AttestationVersion:       3,
		AttestationSecurityLevel: asn1.Enumerated(securityLevel),
		KeymasterVersion:         4,
		KeymasterSecurityLevel:   asn1.Enumerated(androidSecurityLevelTEE),
		AttestationChallenge:     challenge,
		UniqueID:                 []byte{},
		SoftwareEnforced:         emptyList,
		TEEEnforced:              emptyList,
	})
	if err != nil {
		t.Fatalf("marshaling KeyDescription: %v", err)
	}
	return der
}

type testAndroidFixture struct {
	att            *decodedAttestation
	clientDataJSON []byte
}

func testBuildAndroidFixture(t *testing.T, securityLevel int, challenge []byte) *testAndroidFixture {
	t.Helper()
	leaf := testMustECKey(t)
	authData := testFakeAuthData()
	clientDataJSON := testClientDataJSON()
	clientDataHash := sha256.Sum256(clientDataJSON)
	if challenge == nil {
		challenge = clientDataHash[:]
	}
	kdDER := testAndroidKeyDescriptionDER(t, securityLevel, challenge)
	leafDER := testSelfSignedCert(t, &leaf.PublicKey, leaf, []pkix.Extension{
		{Id: testAndroidOID, Value: kdDER},
	})
	verifyData := append(append([]byte{}, authData...), clientDataHash[:]...)
	verifyHash := sha256.Sum256(verifyData)
	sig := testSignASN1(t, leaf, verifyHash[:])
	return &testAndroidFixture{
		att: &decodedAttestation{
			AuthData: authData,
			AttStmt: &attestationStatement{
				Alg: AlgES256,
				Sig: sig,
				X5C: [][]byte{leafDER},
			},
		},
		clientDataJSON: clientDataJSON,
	}
}

func TestVerifyAndroidKeyValidTEE(t *testing.T) {
	f := testBuildAndroidFixture(t, androidSecurityLevelTEE, nil)
	if err := verifyAndroidKeyAttestation(f.att, f.clientDataJSON); err != nil {
		t.Fatalf("valid android-key statement rejected: %v", err)
	}
}

func TestVerifyAndroidKeyValidStrongBox(t *testing.T) {
	f := testBuildAndroidFixture(t, androidSecurityLevelStrongBox, nil)
	if err := verifyAndroidKeyAttestation(f.att, f.clientDataJSON); err != nil {
		t.Fatalf("valid android-key statement rejected: %v", err)
	}
}

func TestVerifyAndroidKeyTamperedSig(t *testing.T) {
	f := testBuildAndroidFixture(t, androidSecurityLevelTEE, nil)
	badSig := append([]byte{}, f.att.AttStmt.Sig...)
	badSig[0] ^= 0x01
	f.att.AttStmt.Sig = badSig
	err := verifyAndroidKeyAttestation(f.att, f.clientDataJSON)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected signature_invalid, got: %v", err)
	}
}

func TestVerifyAndroidKeySoftwareOnlyRejected(t *testing.T) {
	f := testBuildAndroidFixture(t, androidSecurityLevelSoftware, nil)
	testRequireInvalidAttestation(t, verifyAndroidKeyAttestation(f.att, f.clientDataJSON), "software-only")
}

func TestVerifyAndroidKeyChallengeMismatch(t *testing.T) {
	wrong := sha256.Sum256([]byte("other"))
	f := testBuildAndroidFixture(t, androidSecurityLevelTEE, wrong[:])
	testRequireInvalidAttestation(t, verifyAndroidKeyAttestation(f.att, f.clientDataJSON), "attestationChallenge mismatch")
}
