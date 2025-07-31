#if NET7_0_OR_GREATER
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides extension methods for attaching <see cref="IEndpointFilter"/> implementations to route handlers.
/// </summary>
public static class EndpointFilterExtensions
{
    /// <summary>
    /// Adds an endpoint filter to the specified <see cref="RouteHandlerBuilder"/> that enforces a security API key requirement.
    /// The filter uses <see cref="SecurityKeyEndpointFilter"/> to validate requests for the presence of a valid API key.
    /// </summary>
    /// <param name="builder">The <see cref="RouteHandlerBuilder"/> to configure.</param>
    /// <returns>
    /// The same <see cref="RouteHandlerBuilder"/> instance for further route customization.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <c>null</c>.
    /// </exception>
    public static RouteHandlerBuilder RequireSecurityKey(this RouteHandlerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.AddEndpointFilter<SecurityKeyEndpointFilter>();
        return builder;
    }
}
#endif
