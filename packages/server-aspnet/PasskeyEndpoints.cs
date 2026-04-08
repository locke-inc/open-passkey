using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using OpenPasskey.Core;

namespace OpenPasskey.AspNet;

/// <summary>
/// Extension methods to map passkey endpoints using ASP.NET Core Minimal APIs.
///
/// Usage:
///   app.MapPasskeyEndpoints(new PasskeyConfig { ... });
/// </summary>
public static class PasskeyEndpoints
{
    public static IEndpointRouteBuilder MapPasskeyEndpoints(
        this IEndpointRouteBuilder endpoints,
        PasskeyConfig config,
        string prefix = "/passkey")
    {
        var service = new PasskeyService(config);

        endpoints.MapPost($"{prefix}/register/begin", async (HttpContext ctx) =>
        {
            try
            {
                var body = await JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body);
                var userId = body.GetProperty("userId").GetString()!;
                var username = body.GetProperty("username").GetString()!;
                var result = service.BeginRegistration(userId, username);
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, result);
            }
            catch (PasskeyException ex)
            {
                ctx.Response.StatusCode = ex.StatusCode;
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = ex.Message });
            }
            catch (WebAuthnException ex)
            {
                ctx.Response.StatusCode = 400;
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = ex.Message });
            }
        });

        endpoints.MapPost($"{prefix}/register/finish", async (HttpContext ctx) =>
        {
            try
            {
                var body = await JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body);
                var userId = body.GetProperty("userId").GetString()!;
                var credential = body.GetProperty("credential");
                bool? prfSupported = body.TryGetProperty("prfSupported", out var prf) ? prf.GetBoolean() : null;
                var result = service.FinishRegistration(userId, credential, prfSupported);
                if (config.Session != null && result is Dictionary<string, object> dict && dict.TryGetValue("sessionToken", out var tokenObj))
                {
                    var token = (string)tokenObj;
                    ctx.Response.Headers.Append("Set-Cookie", SessionHelper.BuildSetCookieHeader(token, config.Session));
                }
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, result);
            }
            catch (PasskeyException ex)
            {
                ctx.Response.StatusCode = ex.StatusCode;
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = ex.Message });
            }
            catch (WebAuthnException ex)
            {
                ctx.Response.StatusCode = 400;
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = ex.Message });
            }
        });

        endpoints.MapPost($"{prefix}/login/begin", async (HttpContext ctx) =>
        {
            try
            {
                string? userId = null;
                if (ctx.Request.ContentLength > 0)
                {
                    var body = await JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body);
                    if (body.TryGetProperty("userId", out var uid))
                        userId = uid.GetString();
                }
                var result = service.BeginAuthentication(userId);
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, result);
            }
            catch (PasskeyException ex)
            {
                ctx.Response.StatusCode = ex.StatusCode;
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = ex.Message });
            }
            catch (WebAuthnException ex)
            {
                ctx.Response.StatusCode = 400;
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = ex.Message });
            }
        });

        endpoints.MapPost($"{prefix}/login/finish", async (HttpContext ctx) =>
        {
            try
            {
                var body = await JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body);
                var userId = body.GetProperty("userId").GetString()!;
                var credential = body.GetProperty("credential");
                var result = service.FinishAuthentication(userId, credential);
                if (config.Session != null && result is Dictionary<string, object> dict && dict.TryGetValue("sessionToken", out var tokenObj))
                {
                    var token = (string)tokenObj;
                    ctx.Response.Headers.Append("Set-Cookie", SessionHelper.BuildSetCookieHeader(token, config.Session));
                }
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, result);
            }
            catch (PasskeyException ex)
            {
                ctx.Response.StatusCode = ex.StatusCode;
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = ex.Message });
            }
            catch (WebAuthnException ex)
            {
                ctx.Response.StatusCode = 400;
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = ex.Message });
            }
        });

        if (config.Session != null)
        {
            endpoints.MapGet($"{prefix}/session", async (HttpContext ctx) =>
            {
                try
                {
                    var cookieHeader = ctx.Request.Headers["Cookie"].ToString();
                    var token = SessionHelper.ParseCookieToken(cookieHeader, config.Session);
                    if (token == null)
                    {
                        ctx.Response.StatusCode = 401;
                        ctx.Response.ContentType = "application/json";
                        await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = "no session" });
                        return;
                    }
                    var data = service.GetSessionTokenData(token);
                    ctx.Response.ContentType = "application/json";
                    await JsonSerializer.SerializeAsync(ctx.Response.Body, new { userId = data.UserId, authenticated = true });
                }
                catch (ArgumentException)
                {
                    ctx.Response.StatusCode = 401;
                    ctx.Response.ContentType = "application/json";
                    await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = "invalid or expired session" });
                }
            });

            endpoints.MapPost($"{prefix}/logout", async (HttpContext ctx) =>
            {
                ctx.Response.Headers.Append("Set-Cookie", SessionHelper.BuildClearCookieHeader(config.Session));
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, new { success = true });
            });
        }

        return endpoints;
    }
}
