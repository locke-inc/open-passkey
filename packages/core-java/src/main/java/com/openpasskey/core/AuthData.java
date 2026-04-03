package com.openpasskey.core;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Authenticator data parsing and RP ID hash verification.
 */
public final class AuthData {
    private AuthData() {}

    /** Parsed authenticator data fields. */
    public static class Parsed {
        public final byte[] rpIdHash;     // 32 bytes
        public final int flags;           // 1 byte
        public final int signCount;       // 4 bytes big-endian
        public final byte[] credentialId; // variable length (only if AT flag set)
        public final byte[] coseKeyBytes; // remaining bytes (only if AT flag set)

        public Parsed(byte[] rpIdHash, int flags, int signCount,
                      byte[] credentialId, byte[] coseKeyBytes) {
            this.rpIdHash = rpIdHash;
            this.flags = flags;
            this.signCount = signCount;
            this.credentialId = credentialId;
            this.coseKeyBytes = coseKeyBytes;
        }
    }

    /**
     * Parse authenticator data bytes.
     * @param authData raw authenticator data
     * @param expectAttestedCredential if true, expect AT flag and parse credential data
     */
    public static Parsed parse(byte[] authData, boolean expectAttestedCredential) throws WebAuthnException {
        if (authData.length < 37) {
            throw new WebAuthnException("invalid_authenticator_data", "Authenticator data too short");
        }

        byte[] rpIdHash = Arrays.copyOfRange(authData, 0, 32);
        int flags = authData[32] & 0xFF;
        int signCount = ByteBuffer.wrap(authData, 33, 4).getInt();

        byte[] credentialId = null;
        byte[] coseKeyBytes = null;

        if ((flags & 0x40) != 0) {
            // AT flag set: parse attested credential data
            if (authData.length < 55) {
                throw new WebAuthnException("invalid_authenticator_data",
                        "Authenticator data too short for attested credential");
            }
            // Skip AAGUID (16 bytes at offset 37)
            int credIdLen = ((authData[53] & 0xFF) << 8) | (authData[54] & 0xFF);
            int credIdEnd = 55 + credIdLen;
            if (authData.length < credIdEnd) {
                throw new WebAuthnException("invalid_authenticator_data",
                        "Authenticator data too short for credential ID");
            }
            credentialId = Arrays.copyOfRange(authData, 55, credIdEnd);
            coseKeyBytes = Arrays.copyOfRange(authData, credIdEnd, authData.length);
        }

        return new Parsed(rpIdHash, flags, signCount, credentialId, coseKeyBytes);
    }

    /**
     * Verify that rpIdHash matches SHA-256(rpId).
     */
    public static void verifyRpIdHash(byte[] rpIdHash, String rpId) throws WebAuthnException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] expected = md.digest(rpId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (!MessageDigest.isEqual(rpIdHash, expected)) {
                throw new WebAuthnException("rp_id_mismatch",
                        "RP ID hash does not match expected value");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Compute SHA-256 hash of the given data.
     */
    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
