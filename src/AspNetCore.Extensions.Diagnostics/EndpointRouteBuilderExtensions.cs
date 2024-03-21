using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;

namespace AspNetCore.Extensions.Diagnostics;

public static class EndpointRouteBuilderExtensions
{
    public static RouteHandlerBuilder MapConfigurationDebugger(this IEndpointRouteBuilder endpoints, string? pattern = "/config-debugger")
    {
        return endpoints
            .MapGet(
                pattern ?? "/config-debugger",
                ([FromServices] IConfiguration configuration) => (configuration is IConfigurationRoot configurationRoot) ? configurationRoot.GetDebugView() : string.Empty
            )
            .WithDisplayName("Configuration Debugger")
            .WithName("ConfigDebugger")
            .ExcludeFromDescription();
    }
}
