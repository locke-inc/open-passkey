namespace OpenPasskey.Core;

public class AuthenticationInput
{
    public required string RpId { get; set; }
    public required string ExpectedChallenge { get; set; }
    public required string ExpectedOrigin { get; set; }
    public required byte[] StoredPublicKeyCose { get; set; }
    public required uint StoredSignCount { get; set; }
    public required string ClientDataJSON { get; set; }
    public required string AuthenticatorData { get; set; }
    public required string Signature { get; set; }
    public bool RequireUserVerification { get; set; }
}
