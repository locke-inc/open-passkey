using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace OpenPasskey.Core;

internal static class ClientData
{
    public static byte[] Verify(string clientDataJSONB64, string expectedType, string expectedChallenge, string expectedOrigin, IReadOnlyList<string>? additionalOrigins = null)
    {
        byte[] raw = Base64Url.Decode(clientDataJSONB64);
        string text = Encoding.UTF8.GetString(raw);
        using JsonDocument doc = JsonDocument.Parse(text);
        JsonElement root = doc.RootElement;

        string type = root.GetProperty("type").GetString()!;
        string challenge = root.GetProperty("challenge").GetString()!;
        string origin = root.GetProperty("origin").GetString()!;

        if (type != expectedType)
            throw new WebAuthnException("type_mismatch");
        if (challenge != expectedChallenge)
            throw new WebAuthnException("challenge_mismatch");
        if (origin != expectedOrigin && (additionalOrigins == null || !additionalOrigins.Contains(origin)))
            throw new WebAuthnException("origin_mismatch");

        if (root.TryGetProperty("tokenBinding", out JsonElement tb))
        {
            if (tb.TryGetProperty("status", out JsonElement status) && status.GetString() == "present")
                throw new WebAuthnException("token_binding_unsupported");
        }

        return raw;
    }
}
