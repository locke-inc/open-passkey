package com.openpasskey.core;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * Packed attestation statement verification.
 */
public final class PackedAttestation {
    private PackedAttestation() {}

    /**
     * Verify packed self-attestation (no x5c) using the credential public key.
     */
    public static void verifySelfAttestation(Map<Object, Object> coseKey, byte[] authData,
                                             byte[] clientDataJSONRaw, byte[] sig)
            throws WebAuthnException {
        int alg = ((Number) coseKey.get(CoseConstants.LABEL_ALG)).intValue();
        if (alg != CoseConstants.ALG_ES256) {
            throw new WebAuthnException("unsupported_cose_algorithm",
                    "Self-attestation only supported for ES256");
        }

        byte[] clientDataHash = AuthData.sha256(clientDataJSONRaw);
        byte[] verifyData = concat(authData, clientDataHash);

        PublicKey pubKey = ES256.publicKeyFromCose(coseKey);
        boolean valid = ES256.verify(pubKey, verifyData, sig);
        if (!valid) {
            throw new WebAuthnException("signature_invalid",
                    "Packed self-attestation signature invalid");
        }
    }

    /**
     * Verify packed full attestation (x5c present) using the certificate.
     */
    @SuppressWarnings("unchecked")
    public static void verifyFullAttestation(Map<Object, Object> attStmt, byte[] authData,
                                             byte[] clientDataHash)
            throws WebAuthnException {
        try {
            int alg = ((Number) attStmt.get("alg")).intValue();
            byte[] sig = (byte[]) attStmt.get("sig");
            List<byte[]> x5c = (List<byte[]>) attStmt.get("x5c");

            if (x5c == null || x5c.isEmpty()) {
                throw new WebAuthnException("invalid_attestation_statement", "x5c is empty");
            }

            byte[] certDer = x5c.get(0);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(certDer));

            byte[] verifyData = concat(authData, clientDataHash);

            if (alg == CoseConstants.ALG_ES256) {
                Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
                verifier.initVerify(cert.getPublicKey());
                verifier.update(verifyData);
                if (!verifier.verify(sig)) {
                    throw new WebAuthnException("signature_invalid",
                            "Packed full attestation signature invalid");
                }
            } else {
                throw new WebAuthnException("unsupported_cose_algorithm",
                        "Unsupported attestation algorithm: " + alg);
            }
        } catch (WebAuthnException e) {
            throw e;
        } catch (Exception e) {
            throw new WebAuthnException("invalid_attestation_statement",
                    "Failed to verify packed attestation: " + e.getMessage());
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
