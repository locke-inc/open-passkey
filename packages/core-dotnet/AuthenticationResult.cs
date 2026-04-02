namespace OpenPasskey.Core;

public class AuthenticationResult
{
    public required uint SignCount { get; set; }
    public required byte Flags { get; set; }
    public required bool BackupEligible { get; set; }
    public required bool BackupState { get; set; }
}
