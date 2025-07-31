namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides default values used for security API key authentication in ASP.NET Core applications.
/// </summary>
public static class SecurityKeyAuthenticationDefaults
{
    /// <summary>
    /// The default authentication scheme name used for security API key authentication.
    /// This value is referenced when configuring authentication handlers and middleware.
    /// </summary>
    public const string AuthenticationScheme = "SecurityKey";
}
