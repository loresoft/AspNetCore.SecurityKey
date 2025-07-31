using System.Security.Claims;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Defines a contract for validating and authenticating security API keys in an HTTP request context.
/// Implementations should provide logic to verify the key's validity and produce authentication identities.
/// </summary>
public interface ISecurityKeyValidator
{
    /// <summary>
    /// Asynchronously validates the specified security API key.
    /// </summary>
    /// <param name="value">The security API key to validate. May be <c>null</c> if not provided in the request.</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
    /// <returns>
    /// A <see cref="ValueTask{Boolean}"/> that resolves to <c>true</c> if the security API key is valid; otherwise, <c>false</c>.
    /// </returns>
    ValueTask<bool> Validate(string? value, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously authenticates the specified security API key and produces a <see cref="ClaimsIdentity"/> if valid.
    /// </summary>
    /// <param name="value">The security API key to authenticate. May be <c>null</c> if not provided in the request.</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
    /// <returns>
    /// A <see cref="ValueTask{ClaimsIdentity}"/> representing the result of the authentication.
    /// The returned <see cref="ClaimsIdentity"/> should reflect the authenticated principal if the key is valid.
    /// </returns>
    ValueTask<ClaimsIdentity> Authenticate(string? value, CancellationToken cancellationToken = default);
}
