using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Default implementation for extracting the security API key
/// </summary>
/// <seealso cref="AspNetCore.SecurityKey.ISecurityKeyExtractor" />
public class SecurityKeyExtractor : ISecurityKeyExtractor
{
    private readonly SecurityKeyOptions _securityKeyOptions;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyExtractor"/> class.
    /// </summary>
    /// <param name="securityKeyOptions">The security key options.</param>
    /// <exception cref="System.ArgumentNullException">securityKeyOptions</exception>
    public SecurityKeyExtractor(IOptions<SecurityKeyOptions> securityKeyOptions)
    {
        if (securityKeyOptions == null)
            throw new ArgumentNullException(nameof(securityKeyOptions));

        _securityKeyOptions = securityKeyOptions.Value;
    }

    /// <inheritdoc />
    public string? GetKey(HttpContext? context)
    {
        if (context is null)
            return null;

        if (context.Request.Headers.TryGetValue(_securityKeyOptions.HeaderName, out var headerKey))
            return headerKey;

        if (context.Request.Query.TryGetValue(_securityKeyOptions.QueryName, out var queryKey))
            return queryKey;

        if (context.Request.Cookies.TryGetValue(_securityKeyOptions.CookieName, out var cookieKey))
            return cookieKey;

        return null;
    }
}
