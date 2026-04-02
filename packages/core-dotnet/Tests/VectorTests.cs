using System.Text.Json;
using Xunit;

namespace OpenPasskey.Core.Tests;

public class VectorTests
{
    private static readonly string VectorsDir = Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..", "spec", "vectors"));

    private static JsonElement LoadVectorFile(string filename)
    {
        string path = Path.Combine(VectorsDir, filename);
        string json = File.ReadAllText(path);
        return JsonDocument.Parse(json).RootElement;
    }

    public static IEnumerable<object[]> RegistrationVectors()
    {
        var doc = LoadVectorFile("registration.json");
        foreach (var vec in doc.GetProperty("vectors").EnumerateArray())
        {
            yield return new object[]
            {
                vec.GetProperty("name").GetString()!,
                vec.GetProperty("input"),
                vec.GetProperty("expected")
            };
        }
    }

    public static IEnumerable<object[]> AuthenticationVectors()
    {
        var doc = LoadVectorFile("authentication.json");
        foreach (var vec in doc.GetProperty("vectors").EnumerateArray())
        {
            yield return new object[]
            {
                vec.GetProperty("name").GetString()!,
                vec.GetProperty("input"),
                vec.GetProperty("expected")
            };
        }
    }

    public static IEnumerable<object[]> HybridAuthenticationVectors()
    {
        var doc = LoadVectorFile("hybrid_authentication.json");
        foreach (var vec in doc.GetProperty("vectors").EnumerateArray())
        {
            yield return new object[]
            {
                vec.GetProperty("name").GetString()!,
                vec.GetProperty("input"),
                vec.GetProperty("expected")
            };
        }
    }

    [Theory]
    [MemberData(nameof(RegistrationVectors))]
    public void TestRegistration(string name, JsonElement input, JsonElement expected)
    {
        var credential = input.GetProperty("credential");
        var response = credential.GetProperty("response");

        bool shouldSucceed = expected.GetProperty("success").GetBoolean();

        if (shouldSucceed)
        {
            var result = WebAuthn.VerifyRegistration(new RegistrationInput
            {
                RpId = input.GetProperty("rpId").GetString()!,
                ExpectedChallenge = input.GetProperty("expectedChallenge").GetString()!,
                ExpectedOrigin = input.GetProperty("expectedOrigin").GetString()!,
                ClientDataJSON = response.GetProperty("clientDataJSON").GetString()!,
                AttestationObject = response.GetProperty("attestationObject").GetString()!
            });

            if (expected.TryGetProperty("credentialId", out var credId))
            {
                Assert.Equal(credId.GetString(), Base64Url.Encode(result.CredentialId));
            }
            if (expected.TryGetProperty("publicKeyCose", out var pubKey))
            {
                Assert.Equal(pubKey.GetString(), Base64Url.Encode(result.PublicKeyCose));
            }
            if (expected.TryGetProperty("signCount", out var sc))
            {
                Assert.Equal((uint)sc.GetInt32(), result.SignCount);
            }
            if (expected.TryGetProperty("rpIdHash", out var rih))
            {
                Assert.Equal(rih.GetString(), Base64Url.Encode(result.RpIdHash));
            }
        }
        else
        {
            var ex = Assert.Throws<WebAuthnException>(() =>
            {
                WebAuthn.VerifyRegistration(new RegistrationInput
                {
                    RpId = input.GetProperty("rpId").GetString()!,
                    ExpectedChallenge = input.GetProperty("expectedChallenge").GetString()!,
                    ExpectedOrigin = input.GetProperty("expectedOrigin").GetString()!,
                    ClientDataJSON = response.GetProperty("clientDataJSON").GetString()!,
                    AttestationObject = response.GetProperty("attestationObject").GetString()!
                });
            });

            string expectedError = expected.GetProperty("error").GetString()!;
            Assert.Equal(expectedError, ex.Code);
        }
    }

    [Theory]
    [MemberData(nameof(AuthenticationVectors))]
    public void TestAuthentication(string name, JsonElement input, JsonElement expected)
    {
        RunAuthenticationTest(input, expected);
    }

    [Theory]
    [MemberData(nameof(HybridAuthenticationVectors))]
    public void TestHybridAuthentication(string name, JsonElement input, JsonElement expected)
    {
        RunAuthenticationTest(input, expected);
    }

    private static void RunAuthenticationTest(JsonElement input, JsonElement expected)
    {
        var credential = input.GetProperty("credential");
        var response = credential.GetProperty("response");

        byte[] storedPubKey = Base64Url.Decode(input.GetProperty("storedPublicKeyCose").GetString()!);
        uint storedSignCount = (uint)input.GetProperty("storedSignCount").GetInt32();

        bool shouldSucceed = expected.GetProperty("success").GetBoolean();

        if (shouldSucceed)
        {
            var result = WebAuthn.VerifyAuthentication(new AuthenticationInput
            {
                RpId = input.GetProperty("rpId").GetString()!,
                ExpectedChallenge = input.GetProperty("expectedChallenge").GetString()!,
                ExpectedOrigin = input.GetProperty("expectedOrigin").GetString()!,
                StoredPublicKeyCose = storedPubKey,
                StoredSignCount = storedSignCount,
                ClientDataJSON = response.GetProperty("clientDataJSON").GetString()!,
                AuthenticatorData = response.GetProperty("authenticatorData").GetString()!,
                Signature = response.GetProperty("signature").GetString()!
            });

            if (expected.TryGetProperty("signCount", out var sc))
            {
                Assert.Equal((uint)sc.GetInt32(), result.SignCount);
            }
        }
        else
        {
            var ex = Assert.Throws<WebAuthnException>(() =>
            {
                WebAuthn.VerifyAuthentication(new AuthenticationInput
                {
                    RpId = input.GetProperty("rpId").GetString()!,
                    ExpectedChallenge = input.GetProperty("expectedChallenge").GetString()!,
                    ExpectedOrigin = input.GetProperty("expectedOrigin").GetString()!,
                    StoredPublicKeyCose = storedPubKey,
                    StoredSignCount = storedSignCount,
                    ClientDataJSON = response.GetProperty("clientDataJSON").GetString()!,
                    AuthenticatorData = response.GetProperty("authenticatorData").GetString()!,
                    Signature = response.GetProperty("signature").GetString()!
                });
            });

            string expectedError = expected.GetProperty("error").GetString()!;
            Assert.Equal(expectedError, ex.Code);
        }
    }
}
