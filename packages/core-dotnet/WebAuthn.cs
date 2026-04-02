using System.Security.Cryptography;
using PeterO.Cbor;

namespace OpenPasskey.Core;

public static class WebAuthn
{
    public static RegistrationResult VerifyRegistration(RegistrationInput input)
    {
        byte[] clientDataJSONRaw = ClientData.Verify(
            input.ClientDataJSON,
            "webauthn.create",
            input.ExpectedChallenge,
            input.ExpectedOrigin
        );

        // Decode CBOR attestation object
        byte[] attObjBytes = Base64Url.Decode(input.AttestationObject);
        CBORObject attObj = CBORObject.DecodeFromBytes(attObjBytes);

        string fmt = attObj["fmt"].AsString();
        byte[] authData = attObj["authData"].GetByteString();

        int? attStmtAlg = null;
        byte[]? attStmtSig = null;
        byte[]? attStmtX5c = null;

        switch (fmt)
        {
            case "none":
                break;
            case "packed":
            {
                CBORObject stmtObj = attObj["attStmt"];
                if (stmtObj == null || stmtObj.Type != CBORType.Map || stmtObj.Count == 0)
                {
                    throw new WebAuthnException("invalid_attestation_statement", "missing alg or sig");
                }
                CBORObject? algObj = stmtObj[CBORObject.FromObject("alg")];
                CBORObject? sigObj = stmtObj[CBORObject.FromObject("sig")];
                if (algObj == null || sigObj == null)
                {
                    throw new WebAuthnException("invalid_attestation_statement", "missing alg or sig");
                }
                attStmtAlg = algObj.AsInt32();
                attStmtSig = sigObj.GetByteString();
                CBORObject? x5cObj = stmtObj[CBORObject.FromObject("x5c")];
                if (x5cObj != null && x5cObj.Type == CBORType.Array && x5cObj.Count > 0)
                {
                    attStmtX5c = x5cObj[0].GetByteString();
                }
                break;
            }
            default:
                throw new WebAuthnException("unsupported_attestation_format", $"unsupported attestation format: {fmt}");
        }

        var parsed = AuthData.Parse(authData, true);

        AuthData.VerifyRpIdHash(parsed.RpIdHash, input.RpId);

        // UP flag
        if ((parsed.Flags & 0x01) == 0)
            throw new WebAuthnException("user_presence_required");

        // UV flag
        if (input.RequireUserVerification && (parsed.Flags & 0x04) == 0)
            throw new WebAuthnException("user_verification_required");

        // BS must be 0 if BE is 0
        if ((parsed.Flags & 0x08) == 0 && (parsed.Flags & 0x10) != 0)
            throw new WebAuthnException("invalid_backup_state");

        // Verify packed attestation
        if (fmt == "packed" && attStmtSig != null)
        {
            byte[] clientDataHash = SHA256.HashData(clientDataJSONRaw);
            if (attStmtX5c != null)
            {
                // Full attestation
                PackedAttestation.VerifyFullAttestation(attStmtAlg!.Value, attStmtSig, attStmtX5c, authData, clientDataHash);
            }
            else
            {
                // Self-attestation
                PackedAttestation.VerifySelfAttestation(parsed.CredentialKey!, authData, clientDataJSONRaw, attStmtSig);
            }
        }

        return new RegistrationResult
        {
            CredentialId = parsed.CredentialId!,
            PublicKeyCose = parsed.CredentialKey!,
            SignCount = parsed.SignCount,
            RpIdHash = parsed.RpIdHash,
            Flags = parsed.Flags,
            BackupEligible = (parsed.Flags & 0x08) != 0,
            BackupState = (parsed.Flags & 0x10) != 0,
            AttestationFormat = fmt
        };
    }

    public static AuthenticationResult VerifyAuthentication(AuthenticationInput input)
    {
        byte[] clientDataJSONRaw = ClientData.Verify(
            input.ClientDataJSON,
            "webauthn.get",
            input.ExpectedChallenge,
            input.ExpectedOrigin
        );

        byte[] authDataRaw = Base64Url.Decode(input.AuthenticatorData);
        var parsed = AuthData.Parse(authDataRaw, false);

        AuthData.VerifyRpIdHash(parsed.RpIdHash, input.RpId);

        // UP flag
        if ((parsed.Flags & 0x01) == 0)
            throw new WebAuthnException("user_presence_required");

        // UV flag
        if (input.RequireUserVerification && (parsed.Flags & 0x04) == 0)
            throw new WebAuthnException("user_verification_required");

        // BS must be 0 if BE is 0
        if ((parsed.Flags & 0x08) == 0 && (parsed.Flags & 0x10) != 0)
            throw new WebAuthnException("invalid_backup_state");

        byte[] clientDataHash = SHA256.HashData(clientDataJSONRaw);
        byte[] sigBytes = Base64Url.Decode(input.Signature);

        // Build verify data: authData || SHA256(clientDataJSON)
        byte[] verifyData = new byte[authDataRaw.Length + clientDataHash.Length];
        Array.Copy(authDataRaw, 0, verifyData, 0, authDataRaw.Length);
        Array.Copy(clientDataHash, 0, verifyData, authDataRaw.Length, clientDataHash.Length);

        // Identify algorithm from stored COSE key
        CBORObject coseKey = CBORObject.DecodeFromBytes(input.StoredPublicKeyCose);
        int alg = coseKey[CBORObject.FromObject(3)].AsInt32();

        switch (alg)
        {
            case CoseConstants.AlgES256:
                ES256.Verify(input.StoredPublicKeyCose, verifyData, sigBytes);
                break;
            case CoseConstants.AlgMLDSA65:
                MLDSA65.Verify(input.StoredPublicKeyCose, verifyData, sigBytes);
                break;
            case CoseConstants.AlgCompositeMLDSA65ES256:
                Composite.Verify(input.StoredPublicKeyCose, verifyData, sigBytes);
                break;
            default:
                throw new WebAuthnException("unsupported_cose_algorithm");
        }

        // Sign count rollback detection
        if (input.StoredSignCount > 0 && parsed.SignCount <= input.StoredSignCount)
            throw new WebAuthnException("sign_count_rollback");

        return new AuthenticationResult
        {
            SignCount = parsed.SignCount,
            Flags = parsed.Flags,
            BackupEligible = (parsed.Flags & 0x08) != 0,
            BackupState = (parsed.Flags & 0x10) != 0
        };
    }
}
