using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

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
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, result);
            }
            catch (PasskeyException ex)
            {
                ctx.Response.StatusCode = ex.StatusCode;
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
        });

        endpoints.MapPost($"{prefix}/login/finish", async (HttpContext ctx) =>
        {
            try
            {
                var body = await JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body);
                var userId = body.GetProperty("userId").GetString()!;
                var credential = body.GetProperty("credential");
                var result = service.FinishAuthentication(userId, credential);
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, result);
            }
            catch (PasskeyException ex)
            {
                ctx.Response.StatusCode = ex.StatusCode;
                ctx.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(ctx.Response.Body, new { error = ex.Message });
            }
        });

        return endpoints;
    }
}
