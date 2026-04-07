using System.Security.Cryptography;
using System.Text;

namespace OpenPasskey.AspNet;

public class SessionConfig
{
    public string Secret { get; set; } = "";
    public int DurationSeconds { get; set; } = 86400; // 24h
    public int ClockSkewGraceMs { get; set; } = 10_000; // 10s
    public string CookieName { get; set; } = "op_session";
    public string CookiePath { get; set; } = "/";
    public bool Secure { get; set; } = true;
    public string SameSite { get; set; } = "Lax";
    public string? Domain { get; set; }
}

/// <summary>Internal only — never serialized to HTTP responses.</summary>
public record SessionTokenData(string UserId, long ExpiresAt);

public static class SessionHelper
{
    private const int MinSecretLength = 32;

    public static void Validate(SessionConfig config)
    {
        if (string.IsNullOrEmpty(config.Secret) || config.Secret.Length < MinSecretLength)
            throw new ArgumentException($"session secret must be at least {MinSecretLength} characters");
    }

    private static string Sign(string payload, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        return Convert.ToBase64String(sig).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string CreateToken(string userId, SessionConfig config)
    {
        var expiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (long)config.DurationSeconds * 1000;
        var payload = $"{userId}:{expiresAt}";
        var signature = Sign(payload, config.Secret);
        return $"{payload}:{signature}";
    }

    public static SessionTokenData ValidateToken(string token, SessionConfig config)
    {
        var lastColon = token.LastIndexOf(':');
        if (lastColon == -1) throw new ArgumentException("invalid session token");

        var secondLastColon = token.LastIndexOf(':', lastColon - 1);
        if (secondLastColon == -1) throw new ArgumentException("invalid session token");

        var userId = token[..secondLastColon];
        var expiresAtStr = token[(secondLastColon + 1)..lastColon];
        var providedSig = token[(lastColon + 1)..];

        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(expiresAtStr) || string.IsNullOrEmpty(providedSig))
            throw new ArgumentException("invalid session token");

        if (!long.TryParse(expiresAtStr, out var expiresAt))
            throw new ArgumentException("invalid session token");

        var payload = $"{userId}:{expiresAtStr}";
        var expectedSig = Sign(payload, config.Secret);

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(providedSig),
                Encoding.UTF8.GetBytes(expectedSig)))
            throw new ArgumentException("invalid session token");

        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (nowMs > expiresAt + config.ClockSkewGraceMs)
            throw new ArgumentException("session expired");

        return new SessionTokenData(userId, expiresAt);
    }

    public static string BuildSetCookieHeader(string token, SessionConfig config)
    {
        var parts = new List<string>
        {
            $"{config.CookieName}={token}",
            "HttpOnly",
            $"Path={config.CookiePath}",
            $"Max-Age={config.DurationSeconds}",
            $"SameSite={config.SameSite}"
        };
        if (config.Secure) parts.Add("Secure");
        if (!string.IsNullOrEmpty(config.Domain)) parts.Add($"Domain={config.Domain}");
        return string.Join("; ", parts);
    }

    public static string BuildClearCookieHeader(SessionConfig config)
    {
        var parts = new List<string>
        {
            $"{config.CookieName}=",
            "HttpOnly",
            $"Path={config.CookiePath}",
            "Max-Age=0",
            $"SameSite={config.SameSite}"
        };
        if (config.Secure) parts.Add("Secure");
        if (!string.IsNullOrEmpty(config.Domain)) parts.Add($"Domain={config.Domain}");
        return string.Join("; ", parts);
    }

    public static string? ParseCookieToken(string? cookieHeader, SessionConfig config)
    {
        if (string.IsNullOrEmpty(cookieHeader)) return null;
        var prefix = $"{config.CookieName}=";
        foreach (var cookie in cookieHeader.Split(';'))
        {
            var trimmed = cookie.Trim();
            if (trimmed.StartsWith(prefix))
            {
                var value = trimmed[prefix.Length..];
                return string.IsNullOrEmpty(value) ? null : value;
            }
        }
        return null;
    }
}
