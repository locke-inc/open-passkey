using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using PeterO.Cbor;

namespace OpenPasskey.Core;

internal static class MLDSA65
{
    public static void Verify(byte[] coseKeyBytes, byte[] verifyData, byte[] signature)
    {
        CBORObject coseKey = CBORObject.DecodeFromBytes(coseKeyBytes);
        int kty = coseKey[CBORObject.FromObject(1)].AsInt32();
        int alg = coseKey[CBORObject.FromObject(3)].AsInt32();

        if (kty != CoseConstants.KtyMLDSA || alg != CoseConstants.AlgMLDSA65)
            throw new WebAuthnException("unsupported_cose_algorithm");

        byte[] pub = coseKey[CBORObject.FromObject(-1)].GetByteString();

        VerifyWithRawKey(pub, verifyData, signature);
    }

    public static void VerifyWithRawKey(byte[] rawPubKeyBytes, byte[] verifyData, byte[] signature)
    {
        var pubKeyParams = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, rawPubKeyBytes);
        var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, false);
        signer.Init(false, pubKeyParams);
        signer.BlockUpdate(verifyData, 0, verifyData.Length);
        bool valid = signer.VerifySignature(signature);

        if (!valid)
            throw new WebAuthnException("signature_invalid");
    }
}
