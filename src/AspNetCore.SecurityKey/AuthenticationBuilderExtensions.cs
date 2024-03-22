using Microsoft.AspNetCore.Authentication;

namespace AspNetCore.SecurityKey;

public static class AuthenticationBuilderExtensions
{
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder)
    {
        return builder.AddScheme<SecurityKeyAuthenticationSchemeOptions, SecurityKeyAuthenticationHandler>(
            SecurityKeyAuthenticationDefaults.AuthenticationScheme,
            options => { }
        );
    }
}
