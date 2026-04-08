using OpenPasskey.AspNet;
using Xunit;

namespace OpenPasskey.AspNet.Tests;

public class MultiCredentialTests
{
    private static PasskeyConfig Config(bool allowMultiple = false) => new()
    {
        RpId = "example.com",
        RpDisplayName = "Example",
        Origin = "https://example.com",
        AllowMultipleCredentials = allowMultiple,
    };

    private static StoredCredential FakeCred(string userId, byte credId = 1) => new()
    {
        CredentialId = new byte[] { credId },
        PublicKeyCose = new byte[] { 0 },
        SignCount = 0,
        UserId = userId,
    };

    [Fact]
    public void BeginRegistration_Returns409_WhenUserHasCredentials()
    {
        var config = Config();
        config.CredentialStore.Store(FakeCred("user-1"));
        var service = new PasskeyService(config);

        var ex = Assert.Throws<PasskeyException>(() =>
            service.BeginRegistration("user-1", "alice"));
        Assert.Equal(409, ex.StatusCode);
        Assert.Contains("user already registered", ex.Message);
    }

    [Fact]
    public void BeginRegistration_Succeeds_WithAllowMultipleCredentials()
    {
        var config = Config(allowMultiple: true);
        config.CredentialStore.Store(FakeCred("user-1"));
        var service = new PasskeyService(config);

        var resp = service.BeginRegistration("user-1", "alice") as Dictionary<string, object>;
        Assert.NotNull(resp);
        Assert.True(resp!.ContainsKey("challenge"));
    }

    [Fact]
    public void BeginRegistration_IncludesExcludeCredentials_WhenExisting()
    {
        var config = Config(allowMultiple: true);
        config.CredentialStore.Store(FakeCred("user-1", 1));
        config.CredentialStore.Store(FakeCred("user-1", 2));
        var service = new PasskeyService(config);

        var resp = service.BeginRegistration("user-1", "alice") as Dictionary<string, object>;
        Assert.NotNull(resp);
        Assert.True(resp!.ContainsKey("excludeCredentials"));
        var excludeList = resp["excludeCredentials"] as object[];
        Assert.NotNull(excludeList);
        Assert.Equal(2, excludeList!.Length);
    }

    [Fact]
    public void BeginRegistration_NoExcludeCredentials_ForNewUser()
    {
        var config = Config();
        var service = new PasskeyService(config);

        var resp = service.BeginRegistration("new-user", "bob") as Dictionary<string, object>;
        Assert.NotNull(resp);
        Assert.False(resp!.ContainsKey("excludeCredentials"));
    }
}
