package com.openpasskey.core;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

/**
 * ML-DSA-65 (Dilithium3, FIPS 204) signature verification.
 */
public final class MLDSA65 {
    private MLDSA65() {}

    public static final int PUBLIC_KEY_SIZE = 1952;

    /**
     * Verify an ML-DSA-65 signature.
     * ML-DSA signs the message directly (no additional hashing).
     *
     * @param publicKeyBytes raw ML-DSA-65 public key (1952 bytes)
     * @param verifyData     authData || SHA256(clientDataJSON)
     * @param signature      ML-DSA-65 signature
     * @return true if the signature is valid
     */
    public static boolean verify(byte[] publicKeyBytes, byte[] verifyData, byte[] signature)
            throws WebAuthnException {
        try {
            MLDSAPublicKeyParameters pubKeyParams = new MLDSAPublicKeyParameters(
                    MLDSAParameters.ml_dsa_65, publicKeyBytes);

            MLDSASigner signer = new MLDSASigner();
            signer.init(false, pubKeyParams);
            signer.update(verifyData, 0, verifyData.length);
            return signer.verifySignature(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
