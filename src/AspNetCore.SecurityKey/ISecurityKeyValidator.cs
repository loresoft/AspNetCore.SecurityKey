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
    /// <returns>true if security API key is valid; otherwise false</returns>
    bool Validate(string? value);

    /// <summary>
    /// Validates the specified security API key.
    /// </summary>
    /// <param name="value">The security API key to validate.</param>
    /// <param name="claims">The claims associated with the security API key.</param>
    /// <returns>
    /// true if security API key is valid; otherwise false
    /// </returns>
    bool Validate(string? value, out Claim[] claims);
}
