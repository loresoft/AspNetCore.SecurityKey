using Microsoft.AspNetCore.Builder;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Extension methods for the <see cref="SecurityKeyMiddleware"/>.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds middleware for requiring security API key for all requests.
    /// </summary>
    /// <param name="builder">The <see cref="IApplicationBuilder" /> instance this method extends</param>
    /// <returns>
    /// The <see cref="IApplicationBuilder" /> for requiring security API keys
    /// </returns>
    /// <exception cref="System.ArgumentNullException">builder is null</exception>
    public static IApplicationBuilder UseSecurityKey(this IApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.UseMiddleware<SecurityKeyMiddleware>();
    }
}
