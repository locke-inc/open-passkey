namespace OpenPasskey.Core;

public class RegistrationInput
{
    public required string RpId { get; set; }
    public required string ExpectedChallenge { get; set; }
    public required string ExpectedOrigin { get; set; }
    public required string ClientDataJSON { get; set; }
    public required string AttestationObject { get; set; }
    public bool RequireUserVerification { get; set; }
}
