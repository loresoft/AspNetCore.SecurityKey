using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCore.SecurityKey;

/// <summary>
///  Extension methods to configure security API key authentication.
/// </summary>
public static class AuthenticationBuilderExtensions
{
    /// <summary>
    /// Adds security API key authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="SecurityKeyAuthenticationDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder)
        => builder.AddSecurityKey(SecurityKeyAuthenticationDefaults.AuthenticationScheme);

    /// <summary>
    /// Adds security API key authentication to <see cref="AuthenticationBuilder"/> using the specified scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder, string authenticationScheme)
        => builder.AddSecurityKey(authenticationScheme, configureOptions: null!);

    /// <summary>
    /// Adds security API key authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="SecurityKeyAuthenticationDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder, Action<SecurityKeyAuthenticationSchemeOptions> configureOptions)
        => builder.AddSecurityKey(SecurityKeyAuthenticationDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds security api key authentication to <see cref="AuthenticationBuilder"/> using the specified scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder, string authenticationScheme, Action<SecurityKeyAuthenticationSchemeOptions> configureOptions)
        => builder.AddSecurityKey(authenticationScheme, displayName: null, configureOptions: configureOptions);

    /// <summary>
    /// Adds security api key authentication to <see cref="AuthenticationBuilder"/> using the specified scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="displayName">A display name for the authentication handler.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<SecurityKeyAuthenticationSchemeOptions> configureOptions)
    {
        builder.Services.AddOptions<SecurityKeyAuthenticationSchemeOptions>(authenticationScheme);
        return builder.AddScheme<SecurityKeyAuthenticationSchemeOptions, SecurityKeyAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
    }
}
