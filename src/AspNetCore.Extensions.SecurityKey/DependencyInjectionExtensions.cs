using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace AspNetCore.Extensions.SecurityKey;

public static class DependencyInjectionExtensions
{
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
