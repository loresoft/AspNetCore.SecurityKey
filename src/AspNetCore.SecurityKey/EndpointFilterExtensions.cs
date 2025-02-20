#if NET7_0_OR_GREATER
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Extension methods for adding <see cref="IEndpointFilter" /> to a route handler.
/// </summary>
public static class EndpointFilterExtensions
{
    /// <summary>
    /// Registers an endpoint filter requiring security API key for the specified route handler.
    /// </summary>
    /// <param name="builder">The <see cref="RouteHandlerBuilder"/>.</param>
    /// <returns>
    /// A <see cref="RouteHandlerBuilder"/> that can be used to further customize the route handler.
    /// </returns>
    public static RouteHandlerBuilder RequireSecurityKey(this RouteHandlerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.AddEndpointFilter<SecurityKeyEndpointFilter>();
        return builder;
    }
}
#endif
