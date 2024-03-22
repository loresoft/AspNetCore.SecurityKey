using Microsoft.AspNetCore.Http;

namespace AspNetCore.SecurityKey;

/// <summary>
/// An interface for extracting the security API key
/// </summary>
public interface ISecurityKeyExtractor
{
    /// <summary>
    /// Gets the security API key from the specified <see cref="HttpContent"/>.
    /// </summary>
    /// <param name="context">The <see cref="HttpContent"/> to get security key from.</param>
    /// <returns>The security API key if found; otherwise null</returns>
    string? GetKey(HttpContext? context);
}
