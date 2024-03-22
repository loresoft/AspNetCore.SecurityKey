using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Extension methods for setting up security API key services
/// </summary>
public static class DependencyInjectionExtensions
{
    /// <summary>
    /// Adds the security API key services to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services.</param>
    /// <param name="configure">An action delegate to configure the provided <see cref="SecurityKeyOptions"/>.</param>
    /// <returns>
    /// The <see cref="IServiceCollection"/> so that additional calls can be chained.
    /// </returns>
    public static IServiceCollection AddSecurityKey(this IServiceCollection services, Action<SecurityKeyOptions>? configure = null)
    {
        services.AddHttpContextAccessor();

        services.AddOptions<SecurityKeyOptions>();
        if (configure != null)
            services.Configure(configure);

        services.TryAddSingleton<ISecurityKeyExtractor, SecurityKeyExtractor>();
        services.TryAddSingleton<ISecurityKeyValidator, SecurityKeyValidator>();

        // used by SecurityKeyAttribute
        services.TryAddSingleton<SecurityKeyAuthorizationFilter>();

        return services;
    }
}
