using OpenPasskey.AspNet;
using Xunit;

namespace OpenPasskey.AspNet.Tests;

public class SessionTests
{
    private const string Secret = "a]Vv3X!kP9#mW2$nQ7@rT5&jY0^uL8*dF";

    private SessionConfig Config() => new() { Secret = Secret };
    private SessionConfig Config(int durationSeconds, int clockSkewGraceMs) => new()
    {
        Secret = Secret,
        DurationSeconds = durationSeconds,
        ClockSkewGraceMs = clockSkewGraceMs,
    };

    [Fact]
    public void CreateToken_ValidFormat()
    {
        var token = SessionHelper.CreateToken("user123", Config());
        var lastColon = token.LastIndexOf(':');
        var secondLast = token.LastIndexOf(':', lastColon - 1);
        Assert.True(secondLast > 0);
        var expiresAt = long.Parse(token[(secondLast + 1)..lastColon]);
        Assert.True(expiresAt > DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    [Fact]
    public void ValidateToken_FreshToken()
    {
        var token = SessionHelper.CreateToken("user123", Config());
        var data = SessionHelper.ValidateToken(token, Config());
        Assert.Equal("user123", data.UserId);
        Assert.True(data.ExpiresAt > DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    [Fact]
    public void ValidateToken_TamperedUserId()
    {
        var token = SessionHelper.CreateToken("user123", Config());
        var tampered = token.Replace("user123", "evil");
        Assert.Throws<ArgumentException>(() => SessionHelper.ValidateToken(tampered, Config()));
    }

    [Fact]
    public void ValidateToken_TamperedSignature()
    {
        var token = SessionHelper.CreateToken("user123", Config());
        var tampered = token[..^1] + (token[^1] == 'a' ? 'b' : 'a');
        Assert.Throws<ArgumentException>(() => SessionHelper.ValidateToken(tampered, Config()));
    }

    [Fact]
    public async Task ValidateToken_Expired()
    {
        var cfg = Config(0, 0);
        var token = SessionHelper.CreateToken("user123", cfg);
        await Task.Delay(10);
        Assert.Throws<ArgumentException>(() => SessionHelper.ValidateToken(token, cfg));
    }

    [Fact]
    public void ValidateToken_WrongSecret()
    {
        var token = SessionHelper.CreateToken("user123", Config());
        var other = new SessionConfig { Secret = new string('z', 34) };
        Assert.Throws<ArgumentException>(() => SessionHelper.ValidateToken(token, other));
    }

    [Fact]
    public void ValidateToken_Malformed()
    {
        Assert.Throws<ArgumentException>(() => SessionHelper.ValidateToken("", Config()));
        Assert.Throws<ArgumentException>(() => SessionHelper.ValidateToken("nocolons", Config()));
        Assert.Throws<ArgumentException>(() => SessionHelper.ValidateToken("one:colon", Config()));
    }

    [Fact]
    public void ValidateToken_UserIdWithColons()
    {
        var token = SessionHelper.CreateToken("urn:user:123", Config());
        var data = SessionHelper.ValidateToken(token, Config());
        Assert.Equal("urn:user:123", data.UserId);
    }

    [Fact]
    public async Task ValidateToken_ClockSkewGraceAccepts()
    {
        var cfg = Config(0, 10_000);
        var token = SessionHelper.CreateToken("user123", cfg);
        await Task.Delay(10);
        var data = SessionHelper.ValidateToken(token, cfg);
        Assert.Equal("user123", data.UserId);
    }

    [Fact]
    public async Task ValidateToken_ClockSkewGraceRejects()
    {
        var cfg = Config(0, 0);
        var token = SessionHelper.CreateToken("user123", cfg);
        await Task.Delay(10);
        Assert.Throws<ArgumentException>(() => SessionHelper.ValidateToken(token, cfg));
    }

    [Fact]
    public void BuildSetCookieHeader_Defaults()
    {
        var header = SessionHelper.BuildSetCookieHeader("tok", Config());
        Assert.Contains("op_session=tok", header);
        Assert.Contains("HttpOnly", header);
        Assert.Contains("Path=/", header);
        Assert.Contains("SameSite=Lax", header);
        Assert.Contains("Secure", header);
    }

    [Fact]
    public void BuildClearCookieHeader_Test()
    {
        var header = SessionHelper.BuildClearCookieHeader(Config());
        Assert.Contains("Max-Age=0", header);
    }

    [Fact]
    public void RejectShortSecret()
    {
        Assert.Throws<ArgumentException>(() => SessionHelper.Validate(new SessionConfig { Secret = "short" }));
    }
}
