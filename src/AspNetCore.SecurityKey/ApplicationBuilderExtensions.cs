using Microsoft.AspNetCore.Builder;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides extension methods for integrating <see cref="SecurityKeyMiddleware"/> into the ASP.NET Core request pipeline.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Registers the <see cref="SecurityKeyMiddleware"/> in the application's request pipeline.
    /// This middleware enforces the presence of a valid security API key for all incoming HTTP requests.
    /// </summary>
    /// <param name="builder">The <see cref="IApplicationBuilder"/> to configure.</param>
    /// <returns>
    /// The <see cref="IApplicationBuilder"/> instance for chaining further middleware registrations.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <c>null</c>.
    /// </exception>
    public static IApplicationBuilder UseSecurityKey(this IApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.UseMiddleware<SecurityKeyMiddleware>();
    }
}
