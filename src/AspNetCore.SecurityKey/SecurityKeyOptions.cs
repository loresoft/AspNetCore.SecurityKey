using System.Security.Claims;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides configuration options for security API key extraction, validation, and authentication.
/// These options control how the API key is retrieved from requests, how it is compared, and how claims are handled.
/// </summary>
public class SecurityKeyOptions
{
    /// <summary>
    /// Gets or sets the name of the HTTP header used to extract the security API key from incoming requests.
    /// </summary>
    /// <value>
    /// The header name used for API key extraction. Default is <c>x-api-key</c>.
    /// </value>
    public string HeaderName { get; set; } = "x-api-key";

    /// <summary>
    /// Gets or sets the name of the query string parameter used to extract the security API key from incoming requests.
    /// </summary>
    /// <value>
    /// The query string parameter name used for API key extraction. Default is <c>x-api-key</c>.
    /// </value>
    public string QueryName { get; set; } = "x-api-key";

    /// <summary>
    /// Gets or sets the name of the cookie used to extract the security API key from incoming requests.
    /// </summary>
    /// <value>
    /// The cookie name used for API key extraction. Default is <c>x-api-key</c>.
    /// </value>
    public string CookieName { get; set; } = "x-api-key";

    /// <summary>
    /// Gets or sets the configuration key name used to retrieve the valid security API key from application settings.
    /// </summary>
    /// <value>
    /// The configuration key name. Default is <c>SecurityKey</c>.
    /// </value>
    public string ConfigurationName { get; set; } = "SecurityKey";

    /// <summary>
    /// Gets or sets the <see cref="IEqualityComparer{String}"/> used to compare security API keys for validation.
    /// </summary>
    /// <value>
    /// The key comparer used for API key validation. Default is <see cref="StringComparer.OrdinalIgnoreCase"/>.
    /// </value>
    public IEqualityComparer<string> KeyComparer { get; set; } = StringComparer.OrdinalIgnoreCase;

    /// <summary>
    /// Gets or sets the authentication scheme name used for security API key authentication.
    /// </summary>
    /// <value>
    /// The authentication scheme name. Default is <see cref="SecurityKeyAuthenticationDefaults.AuthenticationScheme"/>.
    /// </value>
    public string AuthenticationScheme { get; set; } = SecurityKeyAuthenticationDefaults.AuthenticationScheme;

    /// <summary>
    /// Gets or sets the claim type used for the <see cref="ClaimsIdentity.Name"/> property.
    /// </summary>
    /// <value>
    /// The claim type for the user's name. Default is <see cref="ClaimTypes.Name"/>.
    /// </value>
    public string ClaimNameType { get; set; } = ClaimTypes.Name;

    /// <summary>
    /// Gets or sets the claim type used for role-based authorization via <see cref="ClaimsPrincipal.IsInRole"/>.
    /// </summary>
    /// <value>
    /// The claim type for user roles. Default is <see cref="ClaimTypes.Role"/>.
    /// </value>
    public string ClaimRoleType { get; set; } = ClaimTypes.Role;

    /// <summary>
    /// Gets or sets the duration for which claims are cached.
    /// </summary>
    /// <value>
    /// The time span for caching claims. If <c>null</c>, claims are not cached.
    /// </value>
    public TimeSpan? CacheTime { get; set; }
}
