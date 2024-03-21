using Microsoft.AspNetCore.Builder;

namespace AspNetCore.Extensions.SecurityKey;

public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseSecurityKey(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SecurityKeyMiddleware>();
    }
}
