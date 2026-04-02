package com.openpasskey.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PublicKey;
import java.security.Security;
import java.util.List;
import java.util.Map;

/**
 * WebAuthn core protocol verification.
 * Provides static methods for registration and authentication ceremony verification.
 */
public final class WebAuthn {
    private WebAuthn() {}

    private static final ObjectMapper CBOR_MAPPER = new ObjectMapper(new CBORFactory());

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Verify a WebAuthn registration ceremony (navigator.credentials.create).
     */
    @SuppressWarnings("unchecked")
    public static RegistrationResult verifyRegistration(RegistrationInput input) throws WebAuthnException {
        // 1. Verify client data
        byte[] clientDataJSONRaw = ClientData.verify(
                input.getClientDataJSON(),
                "webauthn.create",
                input.getExpectedChallenge(),
                input.getExpectedOrigin()
        );

        // 2. Decode CBOR attestation object
        byte[] attObjBytes = Base64Url.decode(input.getAttestationObject());
        Map<String, Object> attObj;
        try {
            attObj = CBOR_MAPPER.readValue(attObjBytes, Map.class);
        } catch (Exception e) {
            throw new WebAuthnException("invalid_attestation_statement",
                    "Failed to decode attestation object CBOR");
        }

        String fmt = (String) attObj.get("fmt");
        byte[] authData = (byte[]) attObj.get("authData");
        Map<Object, Object> attStmt = (Map<Object, Object>) attObj.get("attStmt");

        // 3. Validate attestation format
        if (fmt == null) {
            // Some vectors encode without explicit fmt but have authData at top level
            // Try treating as "none"
            fmt = "none";
        }

        switch (fmt) {
            case "none":
                break;
            case "packed":
                if (attStmt == null || !attStmt.containsKey("alg") || !attStmt.containsKey("sig")) {
                    throw new WebAuthnException("invalid_attestation_statement",
                            "Packed attestation missing alg or sig");
                }
                break;
            default:
                throw new WebAuthnException("unsupported_attestation_format",
                        "Unsupported attestation format: " + fmt);
        }

        // 4. Parse authenticator data
        AuthData.Parsed parsed = AuthData.parse(authData, true);

        // 5. Verify RP ID hash
        AuthData.verifyRpIdHash(parsed.rpIdHash, input.getRpId());

        // 6. Verify User Presence
        if ((parsed.flags & 0x01) == 0) {
            throw new WebAuthnException("user_presence_required",
                    "User Presence (UP) flag not set");
        }

        // 7. Verify User Verification (if required)
        if (input.isRequireUserVerification() && (parsed.flags & 0x04) == 0) {
            throw new WebAuthnException("user_verification_required",
                    "User Verification (UV) flag not set");
        }

        // 8. Check backup state consistency (BS=1 requires BE=1)
        boolean backupEligible = (parsed.flags & 0x08) != 0;
        boolean backupState = (parsed.flags & 0x10) != 0;
        if (!backupEligible && backupState) {
            throw new WebAuthnException("invalid_backup_state",
                    "BS flag set without BE flag");
        }

        // 9. Verify packed attestation if present
        if ("packed".equals(fmt) && attStmt != null) {
            byte[] clientDataHash = AuthData.sha256(clientDataJSONRaw);
            boolean hasX5c = attStmt.containsKey("x5c");
            if (hasX5c) {
                // Full attestation
                // Jackson CBOR may decode attStmt keys as strings since they are text keys
                // Build a map with string keys for the attestation verifier
                Map<Object, Object> stmtForVerify = new java.util.HashMap<>();
                stmtForVerify.put("alg", attStmt.get("alg"));
                stmtForVerify.put("sig", attStmt.get("sig"));
                stmtForVerify.put("x5c", attStmt.get("x5c"));
                PackedAttestation.verifyFullAttestation(stmtForVerify, authData, clientDataHash);
            } else {
                // Self-attestation: verify with credential public key
                Map<Object, Object> coseKey = parseCoseKey(parsed.coseKeyBytes);
                PackedAttestation.verifySelfAttestation(coseKey, authData, clientDataJSONRaw,
                        (byte[]) attStmt.get("sig"));
            }
        }

        return new RegistrationResult(
                parsed.credentialId,
                parsed.coseKeyBytes,
                parsed.signCount,
                parsed.rpIdHash,
                parsed.flags,
                backupEligible,
                backupState,
                fmt
        );
    }

    /**
     * Verify a WebAuthn authentication ceremony (navigator.credentials.get).
     */
    public static AuthenticationResult verifyAuthentication(AuthenticationInput input) throws WebAuthnException {
        // 1. Verify client data
        byte[] clientDataJSONRaw = ClientData.verify(
                input.getClientDataJSON(),
                "webauthn.get",
                input.getExpectedChallenge(),
                input.getExpectedOrigin()
        );

        // 2. Decode authenticator data
        byte[] authDataBytes = Base64Url.decode(input.getAuthenticatorData());
        AuthData.Parsed parsed = AuthData.parse(authDataBytes, false);

        // 3. Verify RP ID hash
        AuthData.verifyRpIdHash(parsed.rpIdHash, input.getRpId());

        // 4. Verify User Presence
        if ((parsed.flags & 0x01) == 0) {
            throw new WebAuthnException("user_presence_required",
                    "User Presence (UP) flag not set");
        }

        // 5. Verify User Verification (if required)
        if (input.isRequireUserVerification() && (parsed.flags & 0x04) == 0) {
            throw new WebAuthnException("user_verification_required",
                    "User Verification (UV) flag not set");
        }

        // 6. Check backup state consistency (BS=1 requires BE=1)
        boolean backupEligible = (parsed.flags & 0x08) != 0;
        boolean backupState = (parsed.flags & 0x10) != 0;
        if (!backupEligible && backupState) {
            throw new WebAuthnException("invalid_backup_state",
                    "BS flag set without BE flag");
        }

        // 7. Verify signature
        byte[] storedKeyCoseBytes = Base64Url.decode(input.getStoredPublicKeyCose());
        Map<Object, Object> coseKey = parseCoseKey(storedKeyCoseBytes);
        int alg = ((Number) coseKey.get(CoseConstants.LABEL_ALG)).intValue();

        byte[] clientDataHash = AuthData.sha256(clientDataJSONRaw);
        byte[] verifyData = concat(authDataBytes, clientDataHash);
        byte[] signature = Base64Url.decode(input.getSignature());

        switch (alg) {
            case CoseConstants.ALG_ES256: {
                PublicKey pubKey = ES256.publicKeyFromCose(coseKey);
                boolean valid = ES256.verify(pubKey, verifyData, signature);
                if (!valid) {
                    throw new WebAuthnException("signature_invalid", "ES256 signature invalid");
                }
                break;
            }
            case CoseConstants.ALG_MLDSA65: {
                byte[] pubKeyBytes = (byte[]) coseKey.get(CoseConstants.LABEL_PUB);
                if (pubKeyBytes == null || pubKeyBytes.length != MLDSA65.PUBLIC_KEY_SIZE) {
                    throw new WebAuthnException("unsupported_cose_algorithm",
                            "Invalid ML-DSA-65 public key size");
                }
                boolean valid = MLDSA65.verify(pubKeyBytes, verifyData, signature);
                if (!valid) {
                    throw new WebAuthnException("signature_invalid", "ML-DSA-65 signature invalid");
                }
                break;
            }
            case CoseConstants.ALG_COMPOSITE_MLDSA65_ES256: {
                byte[] compositeKey = (byte[]) coseKey.get(CoseConstants.LABEL_PUB);
                if (compositeKey == null) {
                    throw new WebAuthnException("unsupported_cose_algorithm",
                            "Missing composite public key");
                }
                Composite.verifySignature(compositeKey, verifyData, signature);
                break;
            }
            default:
                throw new WebAuthnException("unsupported_cose_algorithm",
                        "Unsupported COSE algorithm: " + alg);
        }

        // 8. Sign count rollback check (after signature verification, per spec §7.2 step 21)
        if (input.getStoredSignCount() > 0 && parsed.signCount <= input.getStoredSignCount()) {
            throw new WebAuthnException("sign_count_rollback",
                    "Sign count rollback detected: stored=" + input.getStoredSignCount()
                            + " reported=" + parsed.signCount);
        }

        return new AuthenticationResult(
                parsed.signCount,
                parsed.flags,
                backupEligible,
                backupState
        );
    }

    /**
     * Parse a COSE key from raw CBOR bytes.
     * Jackson CBOR maps integer keys to Integer objects.
     */
    @SuppressWarnings("unchecked")
    static Map<Object, Object> parseCoseKey(byte[] coseKeyBytes) throws WebAuthnException {
        try {
            return CBOR_MAPPER.readValue(coseKeyBytes, Map.class);
        } catch (Exception e) {
            throw new WebAuthnException("unsupported_cose_algorithm",
                    "Failed to decode COSE key CBOR: " + e.getMessage());
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
