using PeterO.Cbor;

namespace OpenPasskey.Core;

internal static class Composite
{
    public static void Verify(byte[] coseKeyBytes, byte[] verifyData, byte[] signatureBytes)
    {
        CBORObject coseKey = CBORObject.DecodeFromBytes(coseKeyBytes);
        int kty = coseKey[CBORObject.FromObject(1)].AsInt32();
        int alg = coseKey[CBORObject.FromObject(3)].AsInt32();

        if (kty != CoseConstants.KtyComposite || alg != CoseConstants.AlgCompositeMLDSA65ES256)
            throw new WebAuthnException("unsupported_cose_algorithm");

        byte[] compositeKey = coseKey[CBORObject.FromObject(-1)].GetByteString();

        int expectedKeyLen = CoseConstants.MLDSA65PubKeySize + CoseConstants.ECDSAUncompressedSize;
        if (compositeKey.Length != expectedKeyLen)
            throw new WebAuthnException("unsupported_cose_algorithm",
                $"composite public key wrong length: got {compositeKey.Length}, want {expectedKeyLen}");

        // Split composite key: ML-DSA-65 (1952 bytes) || ECDSA uncompressed point (65 bytes)
        byte[] mldsaPubKey = new byte[CoseConstants.MLDSA65PubKeySize];
        Array.Copy(compositeKey, 0, mldsaPubKey, 0, CoseConstants.MLDSA65PubKeySize);

        byte[] ecdsaPubPoint = new byte[CoseConstants.ECDSAUncompressedSize];
        Array.Copy(compositeKey, CoseConstants.MLDSA65PubKeySize, ecdsaPubPoint, 0, CoseConstants.ECDSAUncompressedSize);

        // Split composite signature: 4-byte big-endian ML-DSA sig length || ML-DSA sig || ES256 DER sig
        if (signatureBytes.Length < 4)
            throw new WebAuthnException("signature_invalid");

        uint mldsaSigLen = (uint)(
            (signatureBytes[0] << 24) |
            (signatureBytes[1] << 16) |
            (signatureBytes[2] << 8) |
            signatureBytes[3]
        );

        if (signatureBytes.Length < 4 + mldsaSigLen)
            throw new WebAuthnException("signature_invalid");

        byte[] mldsaSig = new byte[mldsaSigLen];
        Array.Copy(signatureBytes, 4, mldsaSig, 0, (int)mldsaSigLen);

        int ecdsaSigOffset = 4 + (int)mldsaSigLen;
        byte[] ecdsaSig = new byte[signatureBytes.Length - ecdsaSigOffset];
        Array.Copy(signatureBytes, ecdsaSigOffset, ecdsaSig, 0, ecdsaSig.Length);

        // Both components verify over the same data
        // ML-DSA-65 first
        MLDSA65.VerifyWithRawKey(mldsaPubKey, verifyData, mldsaSig);

        // ES256 second (using raw uncompressed point)
        ES256.VerifyWithUncompressedPoint(ecdsaPubPoint, verifyData, ecdsaSig);
    }
}
