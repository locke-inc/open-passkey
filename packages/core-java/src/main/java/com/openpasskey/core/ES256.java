package com.openpasskey.core;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Map;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

/**
 * ES256 (ECDSA P-256 with SHA-256) signature verification.
 */
public final class ES256 {
    private ES256() {}

    /**
     * Build an ECPublicKey from a COSE key map.
     */
    public static PublicKey publicKeyFromCose(Map<Object, Object> coseKey) throws WebAuthnException {
        try {
            byte[] x = (byte[]) coseKey.get(-2);
            byte[] y = (byte[]) coseKey.get(-3);
            if (x == null || y == null) {
                throw new WebAuthnException("unsupported_cose_algorithm",
                        "Missing x or y coordinate in ES256 COSE key");
            }

            ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("P-256");
            EllipticCurve curve = new EllipticCurve(
                    new java.security.spec.ECFieldFp(bcSpec.getCurve().getField().getCharacteristic()),
                    bcSpec.getCurve().getA().toBigInteger(),
                    bcSpec.getCurve().getB().toBigInteger()
            );
            ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            ECParameterSpec spec = new ECParameterSpec(
                    curve,
                    new ECPoint(
                            bcSpec.getG().getAffineXCoord().toBigInteger(),
                            bcSpec.getG().getAffineYCoord().toBigInteger()
                    ),
                    bcSpec.getN(),
                    bcSpec.getH().intValue()
            );

            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            return kf.generatePublic(new ECPublicKeySpec(point, spec));
        } catch (WebAuthnException e) {
            throw e;
        } catch (Exception e) {
            throw new WebAuthnException("unsupported_cose_algorithm",
                    "Failed to construct ES256 public key: " + e.getMessage());
        }
    }

    /**
     * Build an ECPublicKey from raw uncompressed point (65 bytes: 0x04 || x || y).
     */
    public static PublicKey publicKeyFromUncompressed(byte[] uncompressed) throws WebAuthnException {
        if (uncompressed.length != 65 || uncompressed[0] != 0x04) {
            throw new WebAuthnException("unsupported_cose_algorithm",
                    "Invalid uncompressed EC point");
        }
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        System.arraycopy(uncompressed, 1, x, 0, 32);
        System.arraycopy(uncompressed, 33, y, 0, 32);

        Map<Object, Object> fakeMap = new java.util.HashMap<>();
        fakeMap.put(-2, x);
        fakeMap.put(-3, y);
        return publicKeyFromCose(fakeMap);
    }

    /**
     * Verify an ES256 signature.
     * @param publicKey the EC public key
     * @param verifyData authData || SHA256(clientDataJSON)
     * @param signature DER-encoded ECDSA signature
     */
    public static boolean verify(PublicKey publicKey, byte[] verifyData, byte[] signature)
            throws WebAuthnException {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
            sig.initVerify(publicKey);
            sig.update(verifyData);
            return sig.verify(signature);
        } catch (Exception e) {
            // Signature verification failure (e.g. malformed DER) counts as invalid
            return false;
        }
    }
}
