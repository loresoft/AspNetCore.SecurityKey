using System.Security.Claims;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Security API Key configuration options
/// </summary>
public class SecurityKeyOptions
{
    /// <summary>
    /// Gets or sets the name of the header name to get the security key from
    /// </summary>
    /// <value>
    /// The name of the header name to get the security key from
    /// </value>
    public string HeaderName { get; set; } = "x-api-key";

    /// <summary>
    /// Gets or sets the name of the query string name to get the security key from
    /// </summary>
    /// <value>
    /// The name of the query string name to get the security key from
    /// </value>
    public string QueryName { get; set; } = "x-api-key";

    /// <summary>
    /// Gets or sets the name of the cookie to get the security key from
    /// </summary>
    /// <value>
    /// The name of the cookie to get the security key from
    /// </value>
    public string CookieName { get; set; } = "x-api-key";

    /// <summary>
    /// Gets or sets the name of the configuration name to get the valid secuirty key from
    /// </summary>
    /// <value>
    /// The name of the configuration name to get the valid secuirty key from
    /// </value>
    public string ConfigurationName { get; set; } = "SecurityKey";

    /// <summary>
    /// Gets or sets the key comparer for validating the security key
    /// </summary>
    /// <value>
    /// The key comparer for validating the security key
    /// </value>
    public IEqualityComparer<string> KeyComparer { get; set; } = StringComparer.OrdinalIgnoreCase;

    /// <summary>
    /// Gets or sets the authentication scheme used.
    /// </summary>
    /// <value>
    /// The authentication scheme.
    /// </value>
    public string AuthenticationScheme { get; set; } = SecurityKeyAuthenticationDefaults.AuthenticationScheme;

    /// <summary>
    /// Gets or sets the <see cref="Claim.Type"/> used when obtaining the value of <see cref="ClaimsIdentity.Name"/>
    /// </summary>
    /// <value>
    /// The <see cref="Claim.Type"/> used when obtaining the value of <see cref="ClaimsIdentity.Name"/>
    /// </value>
    public string ClaimNameType { get; set; } = ClaimTypes.Name;

    /// <summary>
    /// Gets or sets the <see cref="Claim.Type"/> used when performing logic for <see cref="ClaimsPrincipal.IsInRole"/>
    /// </summary>
    /// <value>
    /// The <see cref="Claim.Type"/> used when performing logic for <see cref="ClaimsPrincipal.IsInRole"/>
    /// </value>
    public string ClaimRoleType { get; set; } = ClaimTypes.Role;

    /// <summary>
    /// Gets or sets the amount of time to cache the claims
    /// </summary>
    /// <value>
    /// The amount of time to cache the claims
    /// </value>
    public TimeSpan? CacheTime { get; set; }
}
