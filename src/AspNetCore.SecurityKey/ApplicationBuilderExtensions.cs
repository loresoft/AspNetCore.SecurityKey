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
    /// The <see cref="IApplicationBuilder" /> for requirirng security API keys
    /// </returns>
    /// <exception cref="System.ArgumentNullException">builder is null</exception>
    public static IApplicationBuilder UseSecurityKey(this IApplicationBuilder builder)
    {
        if (builder is null)
            throw new ArgumentNullException(nameof(builder));

        return builder.UseMiddleware<SecurityKeyMiddleware>();
    }
}
