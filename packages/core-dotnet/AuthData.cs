using System.Security.Cryptography;
using System.Text;

namespace OpenPasskey.Core;

internal class ParsedAuthData
{
    public required byte[] RpIdHash { get; set; }
    public required byte Flags { get; set; }
    public required uint SignCount { get; set; }
    public byte[]? CredentialId { get; set; }
    public byte[]? CredentialKey { get; set; }
}

internal static class AuthData
{
    private const int MinAuthDataLen = 37;

    public static ParsedAuthData Parse(byte[] authData, bool expectCredData)
    {
        if (authData.Length < MinAuthDataLen)
            throw new Exception("authenticator_data_too_short");

        byte[] rpIdHash = new byte[32];
        Array.Copy(authData, 0, rpIdHash, 0, 32);

        byte flags = authData[32];

        uint signCount = (uint)(
            (authData[33] << 24) |
            (authData[34] << 16) |
            (authData[35] << 8) |
            authData[36]
        );

        var result = new ParsedAuthData
        {
            RpIdHash = rpIdHash,
            Flags = flags,
            SignCount = signCount
        };

        if (expectCredData)
        {
            if ((flags & 0x40) == 0)
                throw new Exception("no_attested_credential_data");

            if (authData.Length < 55)
                throw new Exception("authenticator_data_too_short");

            int offset = 37;
            // AAGUID: 16 bytes
            offset += 16;
            // Credential ID length: 2 bytes big-endian
            int credIdLen = (authData[offset] << 8) | authData[offset + 1];
            offset += 2;

            if (authData.Length < offset + credIdLen)
                throw new Exception("authenticator_data_too_short");

            result.CredentialId = new byte[credIdLen];
            Array.Copy(authData, offset, result.CredentialId, 0, credIdLen);
            offset += credIdLen;

            result.CredentialKey = new byte[authData.Length - offset];
            Array.Copy(authData, offset, result.CredentialKey, 0, authData.Length - offset);
        }

        return result;
    }

    public static void VerifyRpIdHash(byte[] authDataRpIdHash, string rpId)
    {
        byte[] expected = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        if (!CryptographicOperations.FixedTimeEquals(authDataRpIdHash, expected))
            throw new WebAuthnException("rp_id_mismatch");
    }
}
