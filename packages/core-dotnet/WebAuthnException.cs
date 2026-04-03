namespace OpenPasskey.Core;

public class WebAuthnException : Exception
{
    public string Code { get; }

    public WebAuthnException(string code, string? message = null)
        : base(message ?? code)
    {
        Code = code;
    }
}
