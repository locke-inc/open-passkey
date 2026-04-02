package com.openpasskey.core;

/**
 * COSE algorithm and key type constants used in WebAuthn.
 */
public final class CoseConstants {
    private CoseConstants() {}

    // Key types
    public static final int KTY_EC2 = 2;
    public static final int KTY_MLDSA = 8;
    public static final int KTY_COMPOSITE = 9;

    // Algorithms
    public static final int ALG_ES256 = -7;
    public static final int ALG_MLDSA65 = -49;
    public static final int ALG_COMPOSITE_MLDSA65_ES256 = -52;

    // COSE key map labels
    public static final int LABEL_KTY = 1;
    public static final int LABEL_ALG = 3;
    public static final int LABEL_EC_X = -2;
    public static final int LABEL_EC_Y = -3;
    public static final int LABEL_PUB = -1;
}
