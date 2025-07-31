using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides extension methods for configuring security API key authentication in ASP.NET Core applications.
/// </summary>
public static class AuthenticationBuilderExtensions
{
    /// <summary>
    /// Registers security API key authentication using the default scheme.
    /// The default scheme is defined by <see cref="SecurityKeyAuthenticationDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder)
        => builder.AddSecurityKey(SecurityKeyAuthenticationDefaults.AuthenticationScheme);

    /// <summary>
    /// Registers security API key authentication using a specified scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <param name="authenticationScheme">The name of the authentication scheme to use.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder, string authenticationScheme)
        => builder.AddSecurityKey(authenticationScheme, configureOptions: null);

    /// <summary>
    /// Registers security API key authentication using the default scheme and allows configuration of options.
    /// The default scheme is defined by <see cref="SecurityKeyAuthenticationDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder, Action<SecurityKeyAuthenticationSchemeOptions>? configureOptions)
        => builder.AddSecurityKey(SecurityKeyAuthenticationDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Registers security API key authentication using a specified scheme and allows configuration of options.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <param name="authenticationScheme">The name of the authentication scheme to use.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder, string authenticationScheme, Action<SecurityKeyAuthenticationSchemeOptions>? configureOptions)
        => builder.AddSecurityKey(authenticationScheme, displayName: null, configureOptions: configureOptions);

    /// <summary>
    /// Registers security API key authentication using a specified scheme, display name, and configuration options.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <param name="authenticationScheme">The name of the authentication scheme to use.</param>
    /// <param name="displayName">A display name for the authentication handler, used for UI or logging purposes.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <c>null</c>.
    /// </exception>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<SecurityKeyAuthenticationSchemeOptions>? configureOptions)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddOptions<SecurityKeyAuthenticationSchemeOptions>(authenticationScheme);
        return builder.AddScheme<SecurityKeyAuthenticationSchemeOptions, SecurityKeyAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
    }
}
