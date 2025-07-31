using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides the default implementation for extracting a security API key from an HTTP request.
/// This extractor attempts to retrieve the key from the request headers, query string, or cookies
/// using the names specified in <see cref="SecurityKeyOptions"/>.
/// </summary>
/// <seealso cref="AspNetCore.SecurityKey.ISecurityKeyExtractor" />
public class SecurityKeyExtractor : ISecurityKeyExtractor
{
    private readonly SecurityKeyOptions _securityKeyOptions;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyExtractor"/> class.
    /// </summary>
    /// <param name="securityKeyOptions">The options specifying header, query, and cookie names for key extraction.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="securityKeyOptions"/> is <c>null</c>.
    /// </exception>
    public SecurityKeyExtractor(IOptions<SecurityKeyOptions> securityKeyOptions)
    {
        ArgumentNullException.ThrowIfNull(securityKeyOptions);

        _securityKeyOptions = securityKeyOptions.Value;
    }

    /// <summary>
    /// Attempts to extract the security API key from the specified <see cref="HttpContext"/>.
    /// The key is searched in the request headers, query string, and cookies, in that order,
    /// using the names configured in <see cref="SecurityKeyOptions"/>.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> representing the current HTTP request.</param>
    /// <returns>
    /// The extracted security API key if found; otherwise, <c>null</c>.
    /// </returns>
    public string? GetKey(HttpContext? context)
    {
        if (context is null)
            return null;

        var request = context.Request;
        if (request.Headers.TryGetValue(_securityKeyOptions.HeaderName, out var headerKey))
            return headerKey;

        if (request.Query.TryGetValue(_securityKeyOptions.QueryName, out var queryKey))
            return queryKey;

        if (request.Cookies.TryGetValue(_securityKeyOptions.CookieName, out var cookieKey))
            return cookieKey;

        return null;
    }
}
