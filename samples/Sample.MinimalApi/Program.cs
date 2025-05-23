using System.Security.Claims;

using AspNetCore.SecurityKey;

using Sample.Shared;

using Scalar.AspNetCore;

namespace Sample.MinimalApi;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services
            .AddAuthentication()
            .AddSecurityKey();

        builder.Services.AddAuthorization();

        builder.Services.AddSecurityKey();

        builder.Services.AddOpenApi(options => options.AddDocumentTransformer<SecurityKeyDocumentTransformer>());
        builder.Services.AddEndpointsApiExplorer();

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/weather", () => WeatherFaker.Instance.Generate(5))
            .WithName("GetWeatherForecast")
            .WithOpenApi();

        app.MapGet("/users", () => UserFaker.Instance.Generate(10))
            .WithName("GetUsers")
            .WithOpenApi()
            .RequireSecurityKey();

        app.MapGet("/addresses", () => AddressFaker.Instance.Generate(10))
            .WithName("GetAddresses")
            .WithOpenApi()
            .RequireAuthorization();

        app.MapGet("/current", (ClaimsPrincipal? principal) =>
            {
                return new
                {
                    Name = principal?.Identity?.Name,
                    Data = WeatherFaker.Instance.Generate(5)
                };
            })
            .WithName("GetCurrentUser")
            .WithOpenApi();

        app.MapOpenApi();
        app.MapScalarApiReference();

        app.Run();
    }
}
