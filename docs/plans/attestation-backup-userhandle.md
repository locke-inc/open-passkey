# Plan: Packed Attestation, Backup Flags, userHandle Verification

## Overview

Three additions to close the remaining gaps before using open-passkey in the Locke password manager:

1. **Packed attestation format** — verify self-attestation and full (x5c) attestation
2. **Backup flags (BE/BS)** — expose and optionally enforce backup eligibility/state
3. **userHandle verification** — cross-check credential owner in discoverable flow

Items are ordered by implementation dependency.

---

## 1. Backup Flags (BE/BS)

**Severity:** Low effort, high value for policy enforcement.

**Problem:** The authenticator data flags byte already contains BE (bit 3) and BS (bit 4), and `parseAuthenticatorData` already extracts the full flags byte. But neither language exposes these as named fields, and there's no enforcement.

### Changes

**Add named fields to result types — Go:**

```go
type RegistrationResult struct {
    // ...existing fields...
    Flags         byte
    BackupEligible bool // BE flag (bit 3): credential can be backed up/synced
    BackupState    bool // BS flag (bit 4): credential is currently backed up
}

type AuthenticationResult struct {
    SignCount      uint32
    Flags          byte
    BackupEligible bool
    BackupState    bool
}
```

**Same in TypeScript:**

```typescript
export interface RegistrationResult {
  // ...existing fields...
  flags: number;
  backupEligible: boolean;
  backupState: boolean;
}
```

**Populate after flag checks in both `VerifyRegistration` and `VerifyAuthentication`:**

```go
BackupEligible: pad.Flags&0x08 != 0,
BackupState:    pad.Flags&0x10 != 0,
```

**Spec conformance check — BS MUST be 0 if BE is 0 (§6.3.3):**

```go
ErrInvalidBackupState = errors.New("invalid_backup_state")

// After UP/UV checks:
if pad.Flags&0x08 == 0 && pad.Flags&0x10 != 0 {
    return nil, ErrInvalidBackupState  // BS=1 with BE=0 is invalid per spec
}
```

**No enforcement options yet.** Callers inspect `BackupEligible`/`BackupState` in the result and make their own policy decisions. Adding `RequireSingleDevice` or `RequireBackupEligible` input fields is simple but premature — the Locke use case should drive which policies we need.

### Test vectors

| Vector | Flags | Expected |
|--------|-------|----------|
| `registration_backup_state_without_eligible` | 0x51 (UP+AT+BS, BE=0) | Fail: `invalid_backup_state` |
| `authentication_backup_eligible` | 0x09 (UP+BE) | Pass, `backupEligible: true` |

### Files changed

| File | Change |
|------|--------|
| `core-go/webauthn/webauthn.go` | Add error, add fields to results, add BS/BE check, populate fields |
| `core-ts/src/errors.ts` | Add `InvalidBackupStateError` |
| `core-ts/src/types.ts` | Add `backupEligible`, `backupState` to results |
| `core-ts/src/registration.ts` | Add BS/BE check, populate fields |
| `core-ts/src/authentication.ts` | Add BS/BE check, populate fields |
| `tools/vecgen/main.go` | Add 2 vectors |
| Tests in both languages | Automatically pick up new vectors |

---

## 2. Packed Attestation

**Severity:** Medium effort, required for hardware authenticator verification.

**Problem:** The library rejects all non-`"none"` attestation formats. Most hardware authenticators (YubiKey, etc.) produce `fmt: "packed"`. Two sub-formats exist:

- **Self-attestation** (no `x5c`): `attStmt` contains `alg` and `sig`. Signature is verified using the credential public key from `authData`. This proves the authenticator produced the credential but doesn't identify the authenticator model.
- **Full attestation** (`x5c` present): `attStmt` contains `alg`, `sig`, and `x5c` (certificate chain). Signature is verified using `x5c[0]`. The caller can validate the certificate chain against a trust store to identify the authenticator model.

### Architecture change

Currently `decodeAttestationObject` returns only `authData`. It needs to return the full attestation object so `VerifyRegistration` can dispatch based on format.

**Go — new return type:**

```go
type decodedAttestation struct {
    Fmt      string
    AuthData []byte
    AttStmt  attestationStatement // nil for "none"
}

type attestationStatement struct {
    Alg  int
    Sig  []byte
    X5C  [][]byte // nil for self-attestation
}
```

**Go — updated `decodeAttestationObject`:**

```go
type attestationObject struct {
    Fmt      string         `cbor:"fmt"`
    AuthData []byte         `cbor:"authData"`
    AttStmt  cbor.RawMessage `cbor:"attStmt"`
}

func decodeAttestationObject(attObjB64 string) (*decodedAttestation, error) {
    // ... decode CBOR ...
    switch obj.Fmt {
    case "none":
        return &decodedAttestation{Fmt: "none", AuthData: obj.AuthData}, nil
    case "packed":
        stmt, err := decodePackedAttStmt(obj.AttStmt)
        if err != nil { return nil, err }
        return &decodedAttestation{Fmt: "packed", AuthData: obj.AuthData, AttStmt: stmt}, nil
    default:
        return nil, fmt.Errorf("%w: %s", ErrUnsupportedAttestationFormat, obj.Fmt)
    }
}
```

**Go — packed attestation verification (called from VerifyRegistration):**

Per WebAuthn spec §8.2, the packed signature is over `authData || SHA256(clientDataJSON)`:

```go
func verifyPackedAttestation(att *decodedAttestation, clientDataJSONRaw []byte, credentialKey []byte) error {
    clientDataHash := sha256.Sum256(clientDataJSONRaw)
    verifyData := append(att.AuthData, clientDataHash[:]...)

    if att.AttStmt.X5C != nil {
        // Full attestation: verify with x5c[0] certificate
        return verifyPackedFullAttestation(att.AttStmt, verifyData)
    }
    // Self-attestation: verify with credential public key
    return verifySignature(credentialKey, att.AuthData, clientDataJSONRaw, att.AttStmt.Sig)
}
```

Wait — the signature format differs between assertion and attestation for packed. For packed self-attestation, the signature is over `authData || clientDataHash`, same as assertion. But we need to use the raw signature bytes (not the composite format). The existing `verifySignature` dispatches based on COSE alg from the credential key, which works.

Actually, looking more carefully: `verifySignatureES256` already computes `authData || clientDataHash` internally from the raw `authData` and `clientDataJSON` params. We can reuse it directly.

**For full attestation (x5c):**

```go
func verifyPackedFullAttestation(stmt *attestationStatement, verifyData []byte) error {
    if len(stmt.X5C) == 0 {
        return fmt.Errorf("packed attestation: x5c is empty")
    }
    // Parse x5c[0] as X.509 certificate
    cert, err := x509.ParseCertificate(stmt.X5C[0])
    if err != nil {
        return fmt.Errorf("parsing attestation certificate: %w", err)
    }
    // Verify signature using certificate's public key
    hash := sha256.Sum256(verifyData)
    switch stmt.Alg {
    case AlgES256:
        ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
        if !ok { return ErrSignatureInvalid }
        if !ecdsa.VerifyASN1(ecKey, hash[:], stmt.Sig) {
            return ErrSignatureInvalid
        }
    default:
        return fmt.Errorf("%w: attestation alg %d", ErrUnsupportedAlg, stmt.Alg)
    }
    return nil
}
```

We do NOT validate the certificate chain or trust anchors — that's the caller's responsibility. We expose `x5c` in the result so the caller can do trust evaluation.

**New fields in RegistrationResult:**

```go
type RegistrationResult struct {
    // ...existing fields...
    AttestationFormat string   // "none" or "packed"
    AttestationX5C   [][]byte // x5c certificate chain (nil for "none" and self-attestation)
}
```

### TypeScript changes

Same pattern. `cbor-x` decodes `attStmt` as a plain object with `alg`, `sig`, and optional `x5c` fields.

```typescript
const attObj = decode(attObjBytes);
switch (attObj.fmt) {
  case "none":
    break;
  case "packed":
    verifyPackedAttestation(attObj.attStmt, authData, clientDataHash, parsed.credentialKey!);
    break;
  default:
    throw new UnsupportedAttestationFormatError(attObj.fmt);
}
```

For full attestation, Node's `crypto.X509Certificate` class (Node 15+) can parse the certificate.

### vecgen changes

Need a new helper on `softAuthenticator` to produce packed self-attestation objects:

```go
func (a *softAuthenticator) makePackedAttestationObject(authData, clientDataJSON []byte) []byte {
    clientDataHash := sha256.Sum256(clientDataJSON)
    sigInput := append(authData, clientDataHash[:]...)
    hash := sha256.Sum256(sigInput)
    r, s, _ := ecdsa.Sign(rand.Reader, a.privateKey, hash[:])
    sig := marshalDER(r, s)

    obj := map[string]interface{}{
        "fmt": "packed",
        "attStmt": map[string]interface{}{
            "alg": -7, // ES256
            "sig": sig,
        },
        "authData": authData,
    }
    data, _ := cbor.Marshal(obj)
    return data
}
```

### Test vectors

| Vector | Format | attStmt | Expected |
|--------|--------|---------|----------|
| `registration_packed_self_attestation` | `"packed"` | `{alg: -7, sig: <valid>}` | Pass |
| `registration_packed_self_attestation_bad_sig` | `"packed"` | `{alg: -7, sig: <tampered>}` | Fail: `signature_invalid` |
| `registration_packed_attestation` (existing) | `"packed"` | `{}` (empty) | Fail: `invalid_attestation_statement` |

The existing `registration_packed_attestation` vector has an empty `attStmt`, which should now fail with a more specific error (`invalid_attestation_statement` instead of `unsupported_attestation_format`). Need to update the expected error.

### Files changed

| File | Change |
|------|--------|
| `core-go/webauthn/webauthn.go` | New types, refactor `decodeAttestationObject`, add `verifyPackedAttestation`, add x5c to results |
| `core-ts/src/registration.ts` | Add packed attestation dispatch, packed verification |
| `core-ts/src/errors.ts` | Add `InvalidAttestationStatementError` |
| `core-ts/src/types.ts` | Add `attestationFormat`, `attestationX5C` to `RegistrationResult` |
| `tools/vecgen/main.go` | Add packed self-attestation helper, 2 new vectors, update existing packed vector |
| Tests in both languages | Pick up new vectors |

---

## 3. userHandle Verification

**Severity:** Low effort, security fix for discoverable flow.

**Problem:** In the discoverable credential flow, the authenticator returns a `userHandle` (the `user.id` set during registration). The server should verify that this matches the `UserID` of the stored credential. Currently, `FinishAuthentication` looks up the credential by ID but never checks that the credential's owner matches the authenticator's claimed `userHandle`.

This is a confused-deputy risk: if an attacker can somehow present a valid credential but claim a different user, the server would accept it.

### Changes

**server-go — `FinishAuthentication` request struct:**

Add `UserHandle` field:

```go
var req struct {
    UserID     string `json:"userId"`
    Credential struct {
        // ...existing fields...
        Response struct {
            ClientDataJSON    string `json:"clientDataJSON"`
            AuthenticatorData string `json:"authenticatorData"`
            Signature         string `json:"signature"`
            UserHandle        string `json:"userHandle,omitempty"` // base64url-encoded user.id from authenticator
        } `json:"response"`
    } `json:"credential"`
}
```

**Verification logic — after credential lookup:**

```go
// For discoverable flow, verify userHandle matches credential owner
if req.Credential.Response.UserHandle != "" {
    userHandleBytes, err := base64.RawURLEncoding.DecodeString(req.Credential.Response.UserHandle)
    if err != nil {
        writeError(w, http.StatusBadRequest, "invalid userHandle encoding")
        return
    }
    if string(userHandleBytes) != stored.UserID {
        writeError(w, http.StatusBadRequest, "userHandle does not match credential owner")
        return
    }
}
```

For the non-discoverable flow, `userHandle` may be empty (the client already knows who the user is), so we only check when it's provided.

**Angular — PasskeyService:**

Extract `userHandle` from the authenticator response and send it:

```typescript
// In getCredential(), after navigator.credentials.get():
const userHandle = credential.response.userHandle
  ? btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
  : undefined;

const body: FinishAuthenticationRequest = {
    userId: userId ?? "",
    credential: {
        // ...existing fields...
        response: {
            // ...existing fields...
            userHandle,
        },
    },
};
```

**Types update:**

```typescript
// passkey.types.ts
export interface FinishAuthenticationRequest {
    userId: string;
    credential: {
        // ...
        response: {
            clientDataJSON: string;
            authenticatorData: string;
            signature: string;
            userHandle?: string;
        };
    };
}
```

### Test additions

**server-go tests:**

| Test | Description |
|------|-------------|
| `TestFinishAuthentication_UserHandleMismatch` | Provide a valid credential but wrong userHandle → 400 |
| `TestFinishAuthentication_UserHandleMatch` | Provide matching userHandle → success |
| `TestFinishAuthentication_NoUserHandle` | Omit userHandle → success (non-discoverable flow) |

**Angular tests:**

| Test | Description |
|------|-------------|
| `should send userHandle in discoverable flow` | Verify service extracts and sends userHandle |

### Files changed

| File | Change |
|------|--------|
| `server-go/passkey.go` | Add `UserHandle` to request, add verification after credential lookup |
| `server-go/passkey_test.go` | Add 3 tests |
| `angular/src/lib/passkey.types.ts` | Add `userHandle` to finish auth request |
| `angular/src/lib/passkey.service.ts` | Extract `userHandle` from authenticator response |
| `angular/src/lib/passkey.service.spec.ts` | Add userHandle test |

---

## Implementation Order

```
Step 1: Backup Flags (BE/BS)      (core-go, core-ts, vecgen)  — no dependencies
Step 2: Packed Attestation         (core-go, core-ts, vecgen)  — no dependencies
Step 3: userHandle Verification    (server-go, angular)        — no dependencies
```

All three are independent. Steps 1 and 2 touch core verification and need vector generation. Step 3 is server/client only.

---

## Summary

| Step | What | Files | Breaking |
|------|------|-------|----------|
| 1 | BE/BS flags | core-go, core-ts, vecgen | Non-breaking — additive fields + spec conformance check |
| 2 | Packed attestation | core-go, core-ts, vecgen | **Breaking** — existing `registration_packed_attestation` vector changes expected error |
| 3 | userHandle verification | server-go, angular | Non-breaking — only enforced when userHandle is present |
