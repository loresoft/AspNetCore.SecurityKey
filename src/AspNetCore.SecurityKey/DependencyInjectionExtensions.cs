using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides extension methods for registering security API key services in an ASP.NET Core application.
/// </summary>
public static class DependencyInjectionExtensions
{
    /// <summary>
    /// Registers the default security API key services and configuration in the specified <see cref="IServiceCollection"/>.
    /// Uses <see cref="SecurityKeyValidator"/> for validation and <see cref="SecurityKeyExtractor"/> for extraction.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to which the services are added.</param>
    /// <param name="configure">An optional delegate to configure <see cref="SecurityKeyOptions"/>.</param>
    /// <returns>
    /// The same <see cref="IServiceCollection"/> instance for chaining further service registrations.
    /// </returns>
    public static IServiceCollection AddSecurityKey(this IServiceCollection services, Action<SecurityKeyOptions>? configure = null)
        => AddSecurityKey<SecurityKeyValidator, SecurityKeyExtractor>(services, configure);

    /// <summary>
    /// Registers security API key services with a custom validator in the specified <see cref="IServiceCollection"/>.
    /// Uses <see cref="SecurityKeyExtractor"/> for extraction.
    /// </summary>
    /// <typeparam name="TValidator">The type implementing <see cref="ISecurityKeyValidator"/> for validating the security API key.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to which the services are added.</param>
    /// <param name="configure">An optional delegate to configure <see cref="SecurityKeyOptions"/>.</param>
    /// <returns>
    /// The same <see cref="IServiceCollection"/> instance for chaining further service registrations.
    /// </returns>
    public static IServiceCollection AddSecurityKey<TValidator>(this IServiceCollection services, Action<SecurityKeyOptions>? configure = null)
        where TValidator : class, ISecurityKeyValidator
        => AddSecurityKey<TValidator, SecurityKeyExtractor>(services, configure);

    /// <summary>
    /// Registers security API key services with custom validator and extractor types in the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <typeparam name="TValidator">The type implementing <see cref="ISecurityKeyValidator"/> for validating the security API key.</typeparam>
    /// <typeparam name="TExtractor">The type implementing <see cref="ISecurityKeyExtractor"/> for extracting the security API key.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to which the services are added.</param>
    /// <param name="configure">An optional delegate to configure <see cref="SecurityKeyOptions"/>.</param>
    /// <returns>
    /// The same <see cref="IServiceCollection"/> instance for chaining further service registrations.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="services"/> is <c>null</c>.
    /// </exception>
    public static IServiceCollection AddSecurityKey<TValidator, TExtractor>(this IServiceCollection services, Action<SecurityKeyOptions>? configure = null)
        where TValidator : class, ISecurityKeyValidator
        where TExtractor : class, ISecurityKeyExtractor
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddHttpContextAccessor();

        services.AddOptions<SecurityKeyOptions>();
        if (configure != null)
            services.Configure(configure);

        services.TryAddSingleton<ISecurityKeyExtractor, TExtractor>();
        services.TryAddSingleton<ISecurityKeyValidator, TValidator>();

        // used by SecurityKeyAttribute
        services.TryAddSingleton<SecurityKeyAuthorizationFilter>();

        return services;
    }
}
