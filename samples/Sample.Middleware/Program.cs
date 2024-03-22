using AspNetCore.SecurityKey;

using Sample.Shared;

namespace Sample.Middleware;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddAuthorization();

        builder.Services.AddSecurityKey();

        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        var app = builder.Build();

        app.UseSwagger();
        app.UseSwaggerUI();

        // required api key for all end points
        app.UseSecurityKey();

        app.UseHttpsRedirection();

        app.UseAuthorization();

        app.MapGet("/weather", () => WeatherFaker.Instance.Generate(5))
            .WithName("GetWeatherForecast")
            .WithOpenApi();

        app.MapGet("/users", () => UserFaker.Instance.Generate(10))
            .WithName("GetUsers")
            .WithOpenApi();

        app.MapGet("/addresses", () => AddressFaker.Instance.Generate(10))
            .WithName("GetAddresses")
            .WithOpenApi();

        app.Run();
    }
}
