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
}
