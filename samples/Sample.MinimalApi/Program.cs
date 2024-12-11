using System.Security.Claims;

using AspNetCore.SecurityKey;

using Sample.Shared;

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

        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        var app = builder.Build();

        app.UseSwagger();
        app.UseSwaggerUI();

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
                var p = principal;
                return WeatherFaker.Instance.Generate(5);
            })
            .WithName("GetCurrentUser")
            .WithOpenApi();

        app.Run();
    }
}
