using System.Net;

using Microsoft.AspNetCore.Http;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Defines a contract for extracting a security API key from an HTTP request context.
/// Implementations should provide logic to retrieve the API key from headers, query parameters, or other request data.
/// </summary>
public interface ISecurityKeyExtractor
{
    /// <summary>
    /// Attempts to extract the security API key from the specified <see cref="HttpContext"/>.
    /// Implementations may inspect headers, query parameters, or other request properties to locate the key.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> representing the current HTTP request.</param>
    /// <returns>
    /// The extracted security API key if found; otherwise, <c>null</c>.
    /// </returns>
    string? GetKey(HttpContext? context);

    /// <summary>
    /// Retrieves the remote IP address of the client from the specified HTTP context.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> instance containing the client's request information. Can be <see
    /// langword="null"/>.</param>
    /// <returns>The remote IP address of the client, or <see langword="null"/> if the context is <see
    /// langword="null"/>  or the remote address is unavailable.</returns>
    IPAddress? GetRemoteAddress(HttpContext? context);
}
