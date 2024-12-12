using System.Security.Claims;

namespace AspNetCore.SecurityKey;

/// <summary>
/// An interface for validating the security API key
/// </summary>
public interface ISecurityKeyValidator
{
    /// <summary>
    /// Validates the specified security API key.
    /// </summary>
    /// <param name="value">The security API key to validate.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// true if security API key is valid; otherwise false
    /// </returns>
    ValueTask<bool> Validate(string? value, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticate the specified security API key.
    /// </summary>
    /// <param name="value">The security API key to validate.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    ///   <see cref="ClaimsIdentity" /> result of the authentication
    /// </returns>
    ValueTask<ClaimsIdentity> Authenticate(string? value, CancellationToken cancellationToken = default);
}
