using AspNetCore.SecurityKey;

namespace Sample.Controllers;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddControllers();

        builder.Services.AddSecurityKey(options => options.ConfigurationName = "Authentication:ApiKey");

        builder.Services.AddOpenApi();

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseAuthorization();

        app.MapControllers();

        app.MapOpenApi();

        app.Run();
    }
}
