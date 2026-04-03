namespace OpenPasskey.AspNet;

/// <summary>
/// Configuration for the passkey endpoints.
/// </summary>
public class PasskeyConfig
{
    public string RpId { get; set; } = "";
    public string RpDisplayName { get; set; } = "";
    public string Origin { get; set; } = "";
    public IChallengeStore ChallengeStore { get; set; } = new MemoryChallengeStore();
    public ICredentialStore CredentialStore { get; set; } = new MemoryCredentialStore();
    public int ChallengeLength { get; set; } = 32;
    public int ChallengeTimeoutSeconds { get; set; } = 300;

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(RpId))
            throw new ArgumentException("RpId is required");
        if (string.IsNullOrWhiteSpace(Origin))
            throw new ArgumentException("Origin is required");
        if (RpId.Contains("://") || RpId.Contains('/'))
            throw new ArgumentException($"RpId must be a bare domain (got '{RpId}')");
        if (!Origin.StartsWith("https://") && !Origin.StartsWith("http://"))
            throw new ArgumentException($"Origin must start with https:// or http:// (got '{Origin}')");
    }
}
