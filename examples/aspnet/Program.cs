using OpenPasskey.AspNet;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseStaticFiles();

var config = new PasskeyConfig
{
    RpId = "localhost",
    RpDisplayName = "Open Passkey ASP.NET Example",
    Origin = "http://localhost:5000"
};

app.MapPasskeyEndpoints(config);
app.MapFallbackToFile("index.html");

app.Run("http://localhost:5000");
