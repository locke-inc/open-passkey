using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PeterO.Cbor;

namespace OpenPasskey.Core;

internal static class PackedAttestation
{
    public static void VerifySelfAttestation(byte[] coseKeyBytes, byte[] authData, byte[] clientDataJSONRaw, byte[] sig)
    {
        byte[] clientDataHash = SHA256.HashData(clientDataJSONRaw);
        byte[] verifyData = new byte[authData.Length + clientDataHash.Length];
        Array.Copy(authData, 0, verifyData, 0, authData.Length);
        Array.Copy(clientDataHash, 0, verifyData, authData.Length, clientDataHash.Length);

        CBORObject coseKey = CBORObject.DecodeFromBytes(coseKeyBytes);
        int kty = coseKey[CBORObject.FromObject(1)].AsInt32();
        int alg = coseKey[CBORObject.FromObject(3)].AsInt32();

        if (kty != CoseConstants.KtyEC2 || alg != CoseConstants.AlgES256)
            throw new WebAuthnException("unsupported_cose_algorithm");

        byte[] x = coseKey[CBORObject.FromObject(-2)].GetByteString();
        byte[] y = coseKey[CBORObject.FromObject(-3)].GetByteString();

        ES256.VerifyWithXY(x, y, verifyData, sig);
    }

    public static void VerifyFullAttestation(int alg, byte[] sig, byte[] x5cDer, byte[] authData, byte[] clientDataHash)
    {
        if (alg != CoseConstants.AlgES256)
            throw new WebAuthnException("unsupported_cose_algorithm", $"attestation alg {alg}");

        byte[] verifyData = new byte[authData.Length + clientDataHash.Length];
        Array.Copy(authData, 0, verifyData, 0, authData.Length);
        Array.Copy(clientDataHash, 0, verifyData, authData.Length, clientDataHash.Length);

        using var cert = new X509Certificate2(x5cDer);
        using ECDsa? ecdsa = cert.GetECDsaPublicKey();

        if (ecdsa == null)
            throw new WebAuthnException("invalid_attestation_statement", "certificate does not contain an ECDSA public key");

        bool valid = ecdsa.VerifyData(verifyData, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        if (!valid)
            throw new WebAuthnException("signature_invalid");
    }
}
