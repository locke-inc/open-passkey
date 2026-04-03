namespace OpenPasskey.Core;

public class RegistrationResult
{
    public required byte[] CredentialId { get; set; }
    public required byte[] PublicKeyCose { get; set; }
    public required uint SignCount { get; set; }
    public required byte[] RpIdHash { get; set; }
    public required byte Flags { get; set; }
    public required bool BackupEligible { get; set; }
    public required bool BackupState { get; set; }
    public required string AttestationFormat { get; set; }
}
