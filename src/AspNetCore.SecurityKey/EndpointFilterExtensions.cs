using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.SecurityKey;

public static class EndpointFilterExtensions
{
    #if NET7_0_OR_GREATER
    public static RouteHandlerBuilder RequireSecurityKey(this RouteHandlerBuilder builder)
    {
        builder.AddEndpointFilter<SecurityKeyEndpointFilter>();
        return builder;
    }
    #endif
}
