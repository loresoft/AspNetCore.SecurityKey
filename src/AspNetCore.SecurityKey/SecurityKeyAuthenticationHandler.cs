using System.Security.Claims;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides an authentication handler for validating requests using a security API key.
/// This handler extracts the API key from the HTTP context and authenticates it using the configured validator.
/// </summary>
public class SecurityKeyAuthenticationHandler : AuthenticationHandler<SecurityKeyAuthenticationSchemeOptions>
{
    private static readonly AuthenticateResult InvalidSecurityKey = AuthenticateResult.Fail("Invalid Security Key");

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">The options monitor for <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <param name="logger">The factory for creating <see cref="ILogger"/> instances.</param>
    /// <param name="encoder">The <see cref="UrlEncoder"/> for encoding URLs.</param>
    public SecurityKeyAuthenticationHandler(
        IOptionsMonitor<SecurityKeyAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    { }

    /// <summary>
    /// Handles authentication for the current request by extracting and validating the security API key.
    /// If the key is valid, creates an <see cref="AuthenticationTicket"/> with the authenticated principal.
    /// </summary>
    /// <returns>
    /// An <see cref="AuthenticateResult"/> indicating success or failure of the authentication process.
    /// </returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Resolve provider when configured; otherwise use the default registration.
        var keyExtractor = string.IsNullOrEmpty(Options.ProviderServiceKey)
            ? Context.RequestServices.GetRequiredService<ISecurityKeyExtractor>()
            : Context.RequestServices.GetRequiredKeyedService<ISecurityKeyExtractor>(Options.ProviderServiceKey);

        // Extract the security key from the request using the configured extractor
        var securityKey = keyExtractor.GetKey(Context);

        // If no security key is provided, return no result
        if (string.IsNullOrEmpty(securityKey))
            return AuthenticateResult.NoResult();

        var ipAddress = keyExtractor.GetRemoteAddress(Context);

        // Resolve provider when configured; otherwise use the default registration.
        var keyValidator = string.IsNullOrEmpty(Options.ProviderServiceKey)
            ? Context.RequestServices.GetRequiredService<ISecurityKeyValidator>()
            : Context.RequestServices.GetRequiredKeyedService<ISecurityKeyValidator>(Options.ProviderServiceKey);

        // Authenticate the security key and get the claims identity
        var identity = await keyValidator.Authenticate(securityKey, ipAddress, Scheme.Name, Context.RequestAborted);
        if (!identity.IsAuthenticated)
        {
            Logger.LogWarning("Invalid security key {SecurityKey} from IP {IPAddress}", securityKey, ipAddress);
            return InvalidSecurityKey;
        }

        // create a user claim for the security key
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }
}
