using System.Security.Cryptography;
using PeterO.Cbor;

namespace OpenPasskey.Core;

internal static class ES256
{
    public static void Verify(byte[] coseKeyBytes, byte[] verifyData, byte[] signature)
    {
        CBORObject coseKey = CBORObject.DecodeFromBytes(coseKeyBytes);
        int kty = coseKey[CBORObject.FromObject(1)].AsInt32();
        int alg = coseKey[CBORObject.FromObject(3)].AsInt32();

        if (kty != CoseConstants.KtyEC2 || alg != CoseConstants.AlgES256)
            throw new WebAuthnException("unsupported_cose_algorithm");

        byte[] x = coseKey[CBORObject.FromObject(-2)].GetByteString();
        byte[] y = coseKey[CBORObject.FromObject(-3)].GetByteString();

        VerifyWithXY(x, y, verifyData, signature);
    }

    public static void VerifyWithXY(byte[] x, byte[] y, byte[] verifyData, byte[] signature)
    {
        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y }
        };

        using ECDsa ecdsa = ECDsa.Create(ecParams);
        bool valid = ecdsa.VerifyData(verifyData, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        if (!valid)
            throw new WebAuthnException("signature_invalid");
    }

    /// <summary>
    /// Verify using a raw uncompressed EC point (65 bytes: 0x04 || x || y).
    /// </summary>
    public static void VerifyWithUncompressedPoint(byte[] ecPoint, byte[] verifyData, byte[] signature)
    {
        if (ecPoint.Length != CoseConstants.ECDSAUncompressedSize || ecPoint[0] != 0x04)
            throw new WebAuthnException("unsupported_cose_algorithm", "invalid EC point");

        byte[] x = new byte[32];
        byte[] y = new byte[32];
        Array.Copy(ecPoint, 1, x, 0, 32);
        Array.Copy(ecPoint, 33, y, 0, 32);

        VerifyWithXY(x, y, verifyData, signature);
    }
}
