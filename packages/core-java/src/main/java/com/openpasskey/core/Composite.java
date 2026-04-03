package com.openpasskey.core;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * ML-DSA-65-ES256 composite (hybrid PQ) signature verification.
 * COSE alg -52, per draft-ietf-jose-pq-composite-sigs.
 */
public final class Composite {
    private Composite() {}

    /**
     * Split the composite public key: ML-DSA-65 (1952 bytes) || ECDSA uncompressed (65 bytes).
     */
    public static void verifySignature(byte[] compositePublicKey, byte[] verifyData, byte[] signature)
            throws WebAuthnException {
        if (compositePublicKey.length != MLDSA65.PUBLIC_KEY_SIZE + 65) {
            throw new WebAuthnException("unsupported_cose_algorithm",
                    "Composite public key has invalid length: " + compositePublicKey.length);
        }

        // Split public key
        byte[] mldsaPubKey = Arrays.copyOfRange(compositePublicKey, 0, MLDSA65.PUBLIC_KEY_SIZE);
        byte[] ecdsaUncompressed = Arrays.copyOfRange(compositePublicKey, MLDSA65.PUBLIC_KEY_SIZE,
                compositePublicKey.length);

        // Split signature: 4-byte big-endian ML-DSA sig length || ML-DSA sig || ES256 DER sig
        if (signature.length < 4) {
            throw new WebAuthnException("signature_invalid", "Composite signature too short");
        }
        int mldsaSigLen = ByteBuffer.wrap(signature, 0, 4).getInt();
        if (mldsaSigLen < 0 || 4 + mldsaSigLen > signature.length) {
            throw new WebAuthnException("signature_invalid",
                    "Invalid ML-DSA signature length in composite");
        }
        byte[] mldsaSig = Arrays.copyOfRange(signature, 4, 4 + mldsaSigLen);
        byte[] ecdsaSig = Arrays.copyOfRange(signature, 4 + mldsaSigLen, signature.length);

        // Verify ML-DSA-65 component
        boolean mldsaValid = MLDSA65.verify(mldsaPubKey, verifyData, mldsaSig);
        if (!mldsaValid) {
            throw new WebAuthnException("signature_invalid", "ML-DSA-65 component verification failed");
        }

        // Verify ES256 component
        PublicKey ecPubKey = ES256.publicKeyFromUncompressed(ecdsaUncompressed);
        boolean ecdsaValid = ES256.verify(ecPubKey, verifyData, ecdsaSig);
        if (!ecdsaValid) {
            throw new WebAuthnException("signature_invalid", "ES256 component verification failed");
        }
    }
}
