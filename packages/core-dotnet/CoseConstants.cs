namespace OpenPasskey.Core;

public static class CoseConstants
{
    // Algorithm identifiers
    public const int AlgES256 = -7;
    public const int AlgMLDSA65 = -49;
    public const int AlgCompositeMLDSA65ES256 = -52;

    // Key type identifiers
    public const int KtyEC2 = 2;
    public const int KtyMLDSA = 8;
    public const int KtyComposite = 9;

    // ML-DSA-65 public key size (FIPS 204)
    public const int MLDSA65PubKeySize = 1952;

    // Uncompressed EC P-256 point: 0x04 || x(32) || y(32)
    public const int ECDSAUncompressedSize = 65;
}
