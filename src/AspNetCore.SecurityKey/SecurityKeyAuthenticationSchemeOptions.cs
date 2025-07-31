using Microsoft.AspNetCore.Authentication;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides configuration options for the security API key authentication scheme.
/// Inherits from <see cref="AuthenticationSchemeOptions"/> and can be extended to support custom settings
/// for security API key authentication in ASP.NET Core applications.
/// </summary>
/// <seealso cref="Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions" />
public class SecurityKeyAuthenticationSchemeOptions : AuthenticationSchemeOptions
{

}
