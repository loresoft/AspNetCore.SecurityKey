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
        => builder.AddSecurityKey(authenticationScheme: SecurityKeyAuthenticationDefaults.AuthenticationScheme, displayName: null, configureOptions: null);

    /// <summary>
    /// Registers security API key authentication using a specified scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <param name="authenticationScheme">The name of the authentication scheme to use.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey(this AuthenticationBuilder builder, string authenticationScheme)
        => builder.AddSecurityKey(authenticationScheme: authenticationScheme, displayName: null, configureOptions: null);

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
        => builder.AddSecurityKey(authenticationScheme: SecurityKeyAuthenticationDefaults.AuthenticationScheme, displayName: null, configureOptions: configureOptions);

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
        => builder.AddSecurityKey(authenticationScheme: authenticationScheme, displayName: null, configureOptions: configureOptions);

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
        => builder.AddSecurityKey<SecurityKeyValidator, SecurityKeyExtractor>(authenticationScheme, displayName, configureOptions);

    /// <summary>
    /// Registers security API key authentication using a specified validator type.
    /// </summary>
    /// <typeparam name="TValidator">The type of the validator implementing <see cref="ISecurityKeyValidator"/>.</typeparam>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey<TValidator>(this AuthenticationBuilder builder)
        where TValidator : class, ISecurityKeyValidator
        => builder.AddSecurityKey<TValidator, SecurityKeyExtractor>(authenticationScheme: SecurityKeyAuthenticationDefaults.AuthenticationScheme, displayName: null, configureOptions: null);

    /// <summary>
    /// Registers security API key authentication using a specified validator type and scheme.
    /// </summary>
    /// <typeparam name="TValidator">The type of the validator implementing <see cref="ISecurityKeyValidator"/>.</typeparam>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <param name="authenticationScheme">The name of the authentication scheme to use.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey<TValidator>(this AuthenticationBuilder builder, string authenticationScheme)
        where TValidator : class, ISecurityKeyValidator
        => builder.AddSecurityKey<TValidator, SecurityKeyExtractor>(authenticationScheme: authenticationScheme, displayName: null, configureOptions: null);

    /// <summary>
    /// Registers security API key authentication using a specified validator type and configuration options.
    /// </summary>
    /// <typeparam name="TValidator">The type of the validator implementing <see cref="ISecurityKeyValidator"/>.</typeparam>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey<TValidator>(this AuthenticationBuilder builder, Action<SecurityKeyAuthenticationSchemeOptions>? configureOptions)
        where TValidator : class, ISecurityKeyValidator
        => builder.AddSecurityKey<TValidator, SecurityKeyExtractor>(authenticationScheme: SecurityKeyAuthenticationDefaults.AuthenticationScheme, displayName: null, configureOptions: configureOptions);

    /// <summary>
    /// Registers security API key authentication using specified validator and extractor types.
    /// </summary>
    /// <typeparam name="TValidator">The type of the validator implementing <see cref="ISecurityKeyValidator"/>.</typeparam>
    /// <typeparam name="TExtractor">The type of the extractor implementing <see cref="ISecurityKeyExtractor"/>.</typeparam>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey<TValidator, TExtractor>(this AuthenticationBuilder builder)
        where TValidator : class, ISecurityKeyValidator
        where TExtractor : class, ISecurityKeyExtractor
        => builder.AddSecurityKey<TValidator, TExtractor>(authenticationScheme: SecurityKeyAuthenticationDefaults.AuthenticationScheme, displayName: null, configureOptions: null);

    /// <summary>
    /// Registers security API key authentication using specified validator and extractor types and a scheme.
    /// </summary>
    /// <typeparam name="TValidator">The type of the validator implementing <see cref="ISecurityKeyValidator"/>.</typeparam>
    /// <typeparam name="TExtractor">The type of the extractor implementing <see cref="ISecurityKeyExtractor"/>.</typeparam>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <param name="authenticationScheme">The name of the authentication scheme to use.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey<TValidator, TExtractor>(this AuthenticationBuilder builder, string authenticationScheme)
        where TValidator : class, ISecurityKeyValidator
        where TExtractor : class, ISecurityKeyExtractor
        => builder.AddSecurityKey<TValidator, TExtractor>(authenticationScheme: authenticationScheme, displayName: null, configureOptions: null);

    /// <summary>
    /// Registers security API key authentication using specified validator and extractor types and configuration options.
    /// </summary>
    /// <typeparam name="TValidator">The type of the validator implementing <see cref="ISecurityKeyValidator"/>.</typeparam>
    /// <typeparam name="TExtractor">The type of the extractor implementing <see cref="ISecurityKeyExtractor"/>.</typeparam>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/> to configure.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <returns>
    /// The <see cref="AuthenticationBuilder"/> instance for chaining further authentication configuration.
    /// </returns>
    public static AuthenticationBuilder AddSecurityKey<TValidator, TExtractor>(this AuthenticationBuilder builder, Action<SecurityKeyAuthenticationSchemeOptions>? configureOptions)
        where TValidator : class, ISecurityKeyValidator
        where TExtractor : class, ISecurityKeyExtractor
        => builder.AddSecurityKey<TValidator, TExtractor>(authenticationScheme: SecurityKeyAuthenticationDefaults.AuthenticationScheme, displayName: null, configureOptions: configureOptions);

    /// <summary>
    /// Registers security API key authentication using specified validator and extractor types, a scheme, a display name, and configuration options.
    /// </summary>
    /// <typeparam name="TValidator">The type of the validator implementing <see cref="ISecurityKeyValidator"/>.</typeparam>
    /// <typeparam name="TExtractor">The type of the extractor implementing <see cref="ISecurityKeyExtractor"/>.</typeparam>
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
    public static AuthenticationBuilder AddSecurityKey<TValidator, TExtractor>(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<SecurityKeyAuthenticationSchemeOptions>? configureOptions)
        where TValidator : class, ISecurityKeyValidator
        where TExtractor : class, ISecurityKeyExtractor
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddOptions<SecurityKeyAuthenticationSchemeOptions>(authenticationScheme);
        builder.Services.AddSecurityKey<TValidator, TExtractor>();

        return builder.AddScheme<SecurityKeyAuthenticationSchemeOptions, SecurityKeyAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
    }
}
