using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OpenPasskey.Core;

namespace OpenPasskey.AspNet;

/// <summary>
/// Core passkey service that orchestrates challenge management and WebAuthn verification.
/// </summary>
public class PasskeyService
{
    private readonly PasskeyConfig _config;
    private readonly ILogger<PasskeyService>? _logger;

    public PasskeyService(PasskeyConfig config, ILogger<PasskeyService>? logger = null)
    {
        config.Validate();
        _config = config;
        _logger = logger;
    }

    private string GenerateChallenge()
    {
        var buf = RandomNumberGenerator.GetBytes(_config.ChallengeLength);
        return Base64UrlEncode(buf);
    }

    private static string Base64UrlEncode(byte[] data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Convert.FromBase64String(s);
    }

    public object BeginRegistration(string userId, string username)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(username))
            throw new PasskeyException("userId and username are required");

        var challenge = GenerateChallenge();
        var prfSalt = RandomNumberGenerator.GetBytes(32);

        var challengeData = JsonSerializer.Serialize(new { challenge, prfSalt = Base64UrlEncode(prfSalt) });
        _config.ChallengeStore.Store(userId, challengeData, _config.ChallengeTimeoutSeconds);

        return new
        {
            challenge,
            rp = new { id = _config.RpId, name = _config.RpDisplayName },
            user = new { id = Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(userId)), name = username, displayName = username },
            pubKeyCredParams = new object[]
            {
                new { type = "public-key", alg = -52 },
                new { type = "public-key", alg = -49 },
                new { type = "public-key", alg = -7 },
            },
            authenticatorSelection = new { residentKey = "preferred", userVerification = "preferred" },
            timeout = _config.ChallengeTimeoutSeconds * 1000,
            attestation = "none",
            extensions = new { prf = new { eval = new { first = Base64UrlEncode(prfSalt) } } },
        };
    }

    public object FinishRegistration(string userId, JsonElement credential, bool? prfSupported)
    {
        var challengeDataStr = _config.ChallengeStore.Consume(userId);
        using var doc = JsonDocument.Parse(challengeDataStr);
        var storedChallenge = doc.RootElement.GetProperty("challenge").GetString()!;
        var storedPrfSalt = doc.RootElement.GetProperty("prfSalt").GetString()!;

        var response = credential.GetProperty("response");

        var result = WebAuthn.VerifyRegistration(new RegistrationInput
        {
            RpId = _config.RpId,
            ExpectedChallenge = storedChallenge,
            ExpectedOrigin = _config.Origin,
            ClientDataJson = response.GetProperty("clientDataJSON").GetString()!,
            AttestationObject = response.GetProperty("attestationObject").GetString()!,
        });

        bool prfEnabled = prfSupported == true;
        var cred = new StoredCredential
        {
            CredentialId = result.CredentialId,
            PublicKeyCose = result.PublicKeyCose,
            SignCount = result.SignCount,
            UserId = userId,
            PrfSalt = prfEnabled ? Base64UrlDecode(storedPrfSalt) : null,
            PrfSupported = prfEnabled,
        };
        _config.CredentialStore.Store(cred);

        return new { credentialId = Base64UrlEncode(result.CredentialId), registered = true, prfSupported = prfEnabled };
    }

    public object BeginAuthentication(string? userId)
    {
        var challenge = GenerateChallenge();
        var challengeKey = !string.IsNullOrWhiteSpace(userId) ? userId : challenge;
        _config.ChallengeStore.Store(challengeKey, challenge, _config.ChallengeTimeoutSeconds);

        var options = new Dictionary<string, object>
        {
            ["challenge"] = challenge,
            ["rpId"] = _config.RpId,
            ["timeout"] = _config.ChallengeTimeoutSeconds * 1000,
            ["userVerification"] = "preferred",
        };

        if (!string.IsNullOrWhiteSpace(userId))
        {
            var allowCredentials = new List<object>();
            var evalByCredential = new Dictionary<string, object>();
            bool hasPrf = false;

            var creds = _config.CredentialStore.GetByUser(userId);
            foreach (var c in creds)
            {
                var credIdEncoded = Base64UrlEncode(c.CredentialId);
                allowCredentials.Add(new { type = "public-key", id = credIdEncoded });
                if (c.PrfSupported && c.PrfSalt != null)
                {
                    evalByCredential[credIdEncoded] = new { first = Base64UrlEncode(c.PrfSalt) };
                    hasPrf = true;
                }
            }
            options["allowCredentials"] = allowCredentials;
            if (hasPrf)
                options["extensions"] = new { prf = new { evalByCredential } };
        }

        return options;
    }

    public object FinishAuthentication(string userId, JsonElement credential)
    {
        var challenge = _config.ChallengeStore.Consume(userId);

        var credId = credential.GetProperty("id").GetString()!;
        var credIdBytes = Base64UrlDecode(credId);
        var stored = _config.CredentialStore.Get(credIdBytes);

        var response = credential.GetProperty("response");
        if (response.TryGetProperty("userHandle", out var uh) && uh.GetString() is string userHandle && userHandle.Length > 0)
        {
            var decoded = System.Text.Encoding.UTF8.GetString(Base64UrlDecode(userHandle));
            if (decoded != stored.UserId)
                throw new PasskeyException("userHandle does not match credential owner");
        }

        var result = WebAuthn.VerifyAuthentication(new AuthenticationInput
        {
            RpId = _config.RpId,
            ExpectedChallenge = challenge,
            ExpectedOrigin = _config.Origin,
            StoredPublicKeyCose = stored.PublicKeyCose,
            StoredSignCount = stored.SignCount,
            ClientDataJson = response.GetProperty("clientDataJSON").GetString()!,
            AuthenticatorData = response.GetProperty("authenticatorData").GetString()!,
            Signature = response.GetProperty("signature").GetString()!,
        });

        stored.SignCount = result.SignCount;
        _config.CredentialStore.Update(stored);

        var resp = new Dictionary<string, object>
        {
            ["userId"] = stored.UserId,
            ["authenticated"] = true,
        };
        if (stored.PrfSupported) resp["prfSupported"] = true;
        return resp;
    }
}
