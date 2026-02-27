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
    /// <summary>
    /// The service key used to resolve a custom <see cref="ISecurityKeyExtractor"/> and <see cref="ISecurityKeyValidator"/> from the
    /// dependency injection container. When set, the keyed service registered under this key is used instead of the default provider.
    /// </summary>
    public string? ProviderServiceKey { get; set; }
}
