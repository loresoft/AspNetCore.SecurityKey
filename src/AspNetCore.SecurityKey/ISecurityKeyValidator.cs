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
}
